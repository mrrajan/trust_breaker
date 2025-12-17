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
    results: Option<Vec<OsvVulns>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OsvVulns {
    vulns: Option<Vec<OsvVulnId>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OsvVulnId {
    id: String,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct OSVAlias {
    aliases: Option<Vec<String>>,
    severity: Option<Vec<OSVSeverity>>,
}

impl OSVAlias {
    pub fn get_alias(&self) -> Option<&Vec<String>> {
        self.aliases.as_ref()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OSVSeverity {
    #[serde(rename = "type")]
    cvsstype: String,
    score: String,
}

impl OsvQuerybatchResponse {
    pub fn iter_results(&self) -> impl Iterator<Item = &Vec<OsvVulns>> {
        self.results.iter()
    }
}

impl OsvVulns {
    pub fn iter_vulns(&self) -> impl Iterator<Item = &Vec<OsvVulnId>> {
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
pub struct ExportHeader {
    PURL: String,
    CVE_ID: String,
    CVSS: String,
}

pub async fn retrieve_sbom_osv_vulns(purls: Vec<String>, sbom_type: &str) -> Result<(), Box<dyn Error>> {
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
        .open(sbom_type.to_string() + "_osv_" + &custom_datetime_format.to_string() + ".json")
        .expect("File creation failed");
    let json_str = to_string_pretty(&vulnerable_dependencies).expect("Failed to serialize JSON");
    file.write_all(json_str.as_bytes()).expect("Writing failed");
    info!("OSV-NVD Dependency Analysis Completed!");

    let mut wtr = Writer::from_path(sbom_type.to_string() + "_osv_" + &custom_datetime_format.to_string() + ".csv")?;

    for (purl, vulnlist) in &vulnerable_dependencies {
        for vuln in vulnlist {
            for vul in vuln {
                let _ = wtr.serialize(ExportHeader {
                    PURL: purl.to_string(),
                    CVE_ID: vul.id.clone(),
                    CVSS: vul.cvssScore.clone(),
                });
            }
        }
    }
    let _ = wtr.flush();
    info!("OSV: Response Retrieved...");
    Ok(())
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
    let osv_response = retrieve_osv_ghsa(purl.clone()).await;
    let mut vulns: Vec<Vulnerability> = Vec::new();
    if Some(&osv_response).is_some() {
        for osv_vuln in osv_response.iter_results() {
            for vuln in osv_vuln {
                if vuln.vulns.is_some() {
                    for id in vuln.iter_vulns() {
                        for ghsa in id {
                            let cves: OSVAlias = get_osv_cve(ghsa.id.clone()).await;
                            for cve in cves.aliases {
                                for id in cve {
                                    let mut vector = String::new();
                                    if id.contains("CVE") {
                                        for severity in &cves.severity {
                                            for cvss in severity {
                                                if cvss.score.contains("CVSS:3") {
                                                    vector = cvss.score.clone();
                                                }
                                            }
                                        }
                                        let mut osv_score = String::new();
                                        if !vector.is_empty() {
                                            osv_score = get_cvss(vector, &id.clone()).await;
                                        }
                                        let vuln: Vulnerability = Vulnerability::new(&id, osv_score);
                                        vulns.push(vuln);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let unique: Vec<_> = vulns.clone().into_iter().collect::<HashSet<_>>().into_iter().collect();
    Some(unique)
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
                warn!("Error from vector {}", e);
                String::from("0.0")
            }
        }
    } else if vector.starts_with("CVSS:3") {
        cvss = match Base::from_str(&vector) {
            Ok(base) => base.score().value().to_string(),
            Err(e) => {
                warn!("Error from vector {}", e);
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
