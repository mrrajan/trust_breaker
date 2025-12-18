use crate::sbom_cdx;
use chrono;
use csv::Writer;
use cvss::v3::Base;
use cvss::v4::{score, Vector};
use log::{error, info, warn};
use reqwest::{Response, StatusCode};
use serde::de::value;
use serde_derive::{Deserialize, Serialize};
use serde_json::{to_string_pretty, Value};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::str::FromStr;

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, Hash)]
pub struct Vulnerability {
    pub id: String,
    pub cvssScore: String,
}

impl Vulnerability {
    fn new(cve: &str, cvss: String) -> Self {
        Vulnerability {
            id: cve.to_string(),
            cvssScore: cvss,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Vulns {
    vulnerabilities: Option<Vec<Vulnerability>>,
}

impl Vulns {
    fn new(vul: Option<Vec<Vulnerability>>) -> Self {
        Vulns { vulnerabilities: vul }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OsvQuerybatchResponse {
    #[serde(default)]
    results: Vec<OsvVulns>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OsvVulns {
    #[serde(default)]
    vulns: Vec<OsvVulnId>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OsvVulnId {
    id: String,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct OSVAlias {
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    severity: Vec<OSVSeverity>,
}

impl OSVAlias {
    pub fn get_alias(&self) -> &Vec<String> {
        &self.aliases
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OSVSeverity {
    #[serde(rename = "type")]
    cvsstype: String,
    score: String,
}

impl OsvQuerybatchResponse {
    pub fn iter_results(&self) -> impl Iterator<Item = &OsvVulns> {
        self.results.iter()
    }
}

impl OsvVulns {
    pub fn iter_vulns(&self) -> impl Iterator<Item = &OsvVulnId> {
        self.vulns.iter()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OSVResults {
    #[serde(rename = "ref")]
    pub reference: String,
    pub issues: Option<Vec<Vulnerability>>,
    pub transitive: Option<Vec<Depends>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Depends {
    #[serde(rename = "ref")]
    pub reference: String,
    pub vulnerabilities: Option<Vec<Vulnerability>>,
}

impl Depends {
    pub fn new(package: String, vuln: Option<Vec<Vulnerability>>) -> Self {
        Depends {
            reference: package,
            vulnerabilities: vuln,
        }
    }
}

impl OSVResults {
    pub fn new(reference: String, issues: Option<Vec<Vulnerability>>, transitive: Option<Vec<Depends>>) -> Self {
        OSVResults {
            reference: reference,
            issues: issues,
            transitive: transitive,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OSVHeader {
    pub PURL: String,
    pub CVE_ID: String,
    pub CVSS: String,
}

pub async fn retrieve_sbom_osv_vulns(purls: Vec<String>, sbom_type: &str) -> Result<Vec<OSVHeader>, Box<dyn Error>> {
    info!("OSV: Initiate process...");
    let now = chrono::offset::Local::now();
    let custom_datetime_format = now.format("%Y%m%y_%H%M%S");
    let mut vulmap: HashMap<String, Option<Vec<Vulnerability>>> = HashMap::new();
    for purl in purls {
        info!("Getting vuln info for {:?}...", &purl);
        let purl_vuln: Option<Vec<Vulnerability>> = get_osv_vulnerability(&purl).await;
        vulmap.insert(purl.clone(), purl_vuln);
    }
    info!("Vuln info gathing finished!");

    let vulnerable_dependencies: HashMap<String, Option<Vec<Vulnerability>>> = remove_dep_without_vulns(vulmap);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(format!("test_results/source/{}_osv_{}.json",sbom_type.to_string(), custom_datetime_format.to_string()))
        .expect("File creation failed");
    let json_str = to_string_pretty(&vulnerable_dependencies).expect("Failed to serialize JSON");
    file.write_all(json_str.as_bytes()).expect("Writing failed");
    info!("OSV-NVD Dependency Analysis Completed!");

    let mut wtr = Writer::from_path(format!("test_results/source/{}_osv_{}.csv",sbom_type.to_string(), custom_datetime_format.to_string()))?;
    let mut osv_rows: Vec<OSVHeader> = Vec::new();
    for (purl, vulnlist) in &vulnerable_dependencies {
        for vuln in vulnlist {
            for vul in vuln {
                osv_rows.push(OSVHeader {
                    PURL: purl.to_string(),
                    CVE_ID: vul.id.clone(),
                    CVSS: vul.cvssScore.clone(),
                });
            }
        }
    }
    for row in &osv_rows {
        wtr.serialize(row)?;
    }
    let _ = wtr.flush();
    info!("OSV: Response Retrieved...");
    Ok(osv_rows)
}

pub async fn get_package_vulnmap(key: String, vulmap: HashMap<String, Option<Vec<Vulnerability>>>) -> Depends {
    match vulmap.get(&key) {
        Some(vuln) => Depends::new(key, vuln.clone()),
        None => panic!("Impossible! Key not found in vulmap: {}", key),
    }
}
pub async fn get_osv_vulnerability(purl: &str) -> Option<Vec<Vulnerability>> {
    get_osv_response((&purl).to_string()).await
}

pub async fn get_osv_payload(purl: String) -> String {
    let json_str = r#"{"queries": [{"package": {"purl": "<purl>"}}]}"#;
    format!("{}", json_str.replace("<purl>", &purl))
}

pub async fn get_osv_response(purl: String) -> Option<Vec<Vulnerability>> {
    let osv_response = retrieve_osv_ghsa(purl).await;

    if osv_response.results.is_empty() {
        return Some(Vec::new());
    }

    let mut unique_vulns: HashSet<Vulnerability> = HashSet::new();

    for osv_vuln in &osv_response.results {
        if osv_vuln.vulns.is_empty() {
            continue;
        }

        for ghsa in &osv_vuln.vulns {
            let cves = get_osv_cve(ghsa.id.clone()).await;

            if cves.aliases.is_empty() {
                continue;
            }

            let cvss_vector = cves
                .severity
                .iter()
                .find(|cvss| (cvss.score.contains("CVSS:3") || cvss.score.contains("CVSS:4")))
                .map(|cvss| cvss.score.clone());

            for alias in &cves.aliases {
                if !alias.contains("CVE") {
                    continue;
                }

                let osv_score = match &cvss_vector {
                    Some(vector) => get_cvss(vector.clone(), alias).await,
                    None => String::new(),
                };

                unique_vulns.insert(Vulnerability::new(alias, osv_score));
            }
        }
    }

    Some(unique_vulns.into_iter().collect())
}

pub async fn retrieve_osv_ghsa(purl: String) -> OsvQuerybatchResponse {
    let url = format!("https://api.osv.dev/v1/querybatch");
    let body = get_osv_payload(purl.clone());
    let response = reqwest::Client::new()
        .post(url)
        .header("Accept", "application/json")
        .body(body.await)
        .send()
        .await
        .expect("Error from response")
        .json::<OsvQuerybatchResponse>()
        .await
        .expect("Error");
    response
}

pub async fn get_json_response(url: String) -> serde_json::Value {
    let response = reqwest::Client::new()
        .get(url)
        .header("Accept", "application/json")
        .send()
        .await
        .unwrap();
    let status = response.status();
    let text_res = response.text().await.unwrap();
    if !(status == StatusCode::OK) {
        error!("NVD API failed with Error body: {}", text_res);
    }
    let json_response: serde_json::Value = serde_json::from_str(&text_res).expect("Failure");
    json_response
}

pub async fn get_osv_cve(ghsa_id: String) -> OSVAlias {
    let url = format!("https://api.osv.dev/v1/vulns/{}", ghsa_id);
    let json_response = reqwest::Client::new()
        .get(url)
        .header("Accept", "application/json")
        .send()
        .await
        .unwrap();
    let status = json_response.status();
    if !(status == StatusCode::OK) {
        error!("NVD API failed with Error code: {}", status);
    }
    let osv_response = match json_response.json::<OSVAlias>().await {
        Ok(json) => json,
        Err(err) => {
            panic!("Error parsing JSON response: {}", err);
        }
    };
    osv_response
}

pub async fn get_cvss(vector: String, id: &str) -> String {
    let mut cvss = String::new();
    if vector.starts_with("CVSS:4") {
        cvss = match Vector::from_str(&vector) {
            Ok(base) => base.score().value().to_string(),
            Err(e) => {
                warn!("Error from vector {} {}", vector, e);
                String::from("0.0")
            }
        }
    } else if vector.starts_with("CVSS:3") {
        cvss = match Base::from_str(&vector) {
            Ok(base) => base.score().value().to_string(),
            Err(e) => {
                warn!("Error from vector {} {}", vector, e);
                String::from("0.0")
            }
        }
        //cvss = Base::from_str(&vector).expect("Error for Vector").score().value().to_string();
    } else {
        warn!("Unsupported CVSS for CVE {} with vector {}", id, vector);
    }
    // match Base::from_str(&vector) {
    //     Ok(base) => {
    //         cvss = base.score().value().to_string();
    //     }
    //     Err(e) => {

    //     }
    // }
    cvss
}

/* Obselete - using CVSS crate to retrieve CVSS from vector
pub async fn get_nvd(cve: &str) -> Value {
    let url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=".to_owned() + cve;
    let json_response: serde_json::Value = get_json_response(url).await;
    let v31base =
        json_response["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"].clone();
    let v30base =
        json_response["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV30"][0]["cvssData"]["baseScore"].clone();
    let v2base =
        json_response["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"].clone();
    let mut base = v31base.clone();
    if !(v31base.is_null()) {
        base = v31base.clone();
    } else {
        if !(v30base.is_null()) {
            base = v30base.clone();
        } else if !(v2base.is_null()) {
            base = v2base.clone();
        }
    }
    base
}
*/
pub async fn get_dep_tree(data: &sbom_cdx::CycloneDXBOM) -> HashMap<&str, Option<Vec<String>>> {
    let mut deptree: HashMap<&str, Option<Vec<String>>> = HashMap::new();
    for comp in data.iter_component() {
        match &comp.purl {
            Some(purl) => {
                let mut dependencies: Option<Vec<String>> = None;
                if !(data.dependencies == None) {
                    for dep in data.iter_dependents() {
                        if *purl == dep.dependency_ref {
                            if let Some(dependency) = &dep.dependsOn {
                                dependencies = dep.dependsOn.clone();
                            }
                        }
                    }
                }
                deptree.insert(purl, dependencies);
            }
            None => {
                info!("No Package URL found");
            }
        }
    }
    deptree
}

pub fn flatten_dependencies(
    purl: &str,
    deptree: HashMap<&str, Option<Vec<String>>>,
    exist_dep: Option<HashSet<String>>,
) -> Vec<String> {
    let mut flat_hs: HashSet<String> = exist_dep.unwrap_or_else(HashSet::new);
    if let Some(dependency) = deptree.get(purl).cloned().flatten() {
        for dep in dependency {
            if flat_hs.contains(&dep) {
                continue;
            }
            flat_hs.insert(dep.clone());
            let x = flatten_dependencies(&dep, deptree.clone(), Some(flat_hs.clone()));
            for y in x {
                flat_hs.insert(y);
            }
        }
    }
    let unique_flatdep = flat_hs.into_iter().collect();
    unique_flatdep
}

pub fn remove_dep_without_vulns(
    vulnmap: HashMap<String, Option<Vec<Vulnerability>>>,
) -> HashMap<String, Option<Vec<Vulnerability>>> {
    let mut depwithvuln: HashMap<String, Option<Vec<Vulnerability>>> = HashMap::new();
    for (reference, vuln) in vulnmap {
        if !(vuln.clone().expect("").is_empty()) {
            depwithvuln.insert(reference, vuln);
        }
    }
    depwithvuln
}
