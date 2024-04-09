use crate::sbom_cdx;
use log::{error, info};
use reqwest::{Response, StatusCode};
use serde_derive::{Deserialize, Serialize};
use serde_json::{to_string_pretty, Value};
use simplelog::*;
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, Hash)]
pub struct Vulnerability {
    pub id: String,
    pub cvssScore: String,
}

impl Vulnerability {
    fn new(cve: &str, cvss: &str) -> Self {
        Vulnerability {
            id: cve.to_string(),
            cvssScore: cvss.to_string(),
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
}

impl OSVAlias {
    pub fn get_alias(&self) -> Option<&Vec<String>> {
        self.aliases.as_ref()
    }
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
    #[serde(rename="ref")]
    pub reference: String,
    pub issues: Option<Vec<Vulnerability>>,
    pub transitive: Option<Vec<Depends>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Depends {
    #[serde(rename="ref")]
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
            transitive:transitive
        }
    }
}

pub async fn retrieve_sbom_osv_vulns(filepath: &str) ->(Vec<OSVResults>, HashMap<String, Option<Vec<Vulnerability>>>) {
    let data: sbom_cdx::CycloneDXBOM = sbom_cdx::get_cdx_purl(filepath).await;
    let mut vulmap: HashMap<String, Option<Vec<Vulnerability>>> = HashMap::new();
    let dep_tree = get_dep_tree(&data).await;
    let mut osv_results: Vec<OSVResults> = Vec::new();
    for comp in data.iter_component() {
        info!("Getting vuln info for {:?}...", &comp);
        let purl_vuln:Option<Vec<Vulnerability>> = get_osv_vulnerability(&comp.purl).await;
        vulmap.insert(comp.purl.clone(), purl_vuln);
    }
    info!("Vuln info gathing finished!");
    info!("OSV-NVD Dependency Analysis in progress...");
    for key in vulmap.keys() {
        let direct_vulns = vulmap.get(key).expect("");
        let deps = flatten_dependencies(key, dep_tree.clone());
        let mut osv_dep: Vec<Depends> = Vec::new();
        for dep in deps {
            osv_dep.push(get_package_vulnmap(dep, vulmap.clone()).await);
        }
        let temp_result = OSVResults::new(key.to_string(), direct_vulns.clone(), Some(osv_dep));
        osv_results.push(temp_result);
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open("osv_dep_analysis.json")
        .expect("File creation failed");
    let json_str = to_string_pretty(&osv_results).expect("Failed to serialize JSON");
    file.write_all(json_str.as_bytes()).expect("Writing failed");
    info!("OSV-NVD Dependency Analysis Completed!");
    let vulnerable_dependencies: HashMap<String, Option<Vec<Vulnerability>>>= remove_dep_without_vulns(vulmap);
    (osv_results, vulnerable_dependencies)
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
                                    if id.contains("CVE") {
                                        let nvd_score = get_nvd(&id).await;
                                        let vuln: Vulnerability = Vulnerability::new(&id, &nvd_score.to_string());
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
    let unique:Vec<_> = vulns.clone().into_iter().collect::<HashSet<_>>().into_iter().collect();
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
    if !(status == StatusCode::OK){
        error!("NVD API failed with Error body: {}",text_res);
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
    if !(status == StatusCode::OK){
        error!("NVD API failed with Error code: {}",status);
    }
    let osv_response = match json_response.json::<OSVAlias>().await {
        Ok(json) => json,
        Err(err) => {
            panic!("Error parsing JSON response: {}", err);
        }
    };
    osv_response
}

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

pub async fn get_dep_tree(data: &sbom_cdx::CycloneDXBOM) -> HashMap<&str, Option<Vec<String>>> {
    let mut deptree: HashMap<&str, Option<Vec<String>>> = HashMap::new();
    for comp in data.iter_component() {
        let mut dependencies: Option<Vec<String>> = None;
        if !(data.dependencies == None) {
            for dep in data.iter_dependents() {
                if comp.purl == dep.dependency_ref {
                    if let Some(dependency) = &dep.dependsOn {
                        dependencies = dep.dependsOn.clone();
                    }
                }
            }
        }
        deptree.insert(&comp.purl, dependencies);
    }
    deptree
}

pub fn flatten_dependencies(purl: &str, deptree: HashMap<&str, Option<Vec<String>>>) -> Vec<String> {
    let mut flatdep: Vec<String> = Vec::new();
    if let Some(dependency) = deptree.get(purl).cloned().flatten() {
        flatdep = dependency.clone();
        for dep in dependency {
            let x = flatten_dependencies(&dep, deptree.clone());
            flatdep.extend(x);
        }
    }
    let unique_flatdep = flatdep.into_iter().collect::<HashSet<_>>().into_iter().collect();
    unique_flatdep
}

pub fn remove_dep_without_vulns(vulnmap: HashMap<String, Option<Vec<Vulnerability>>>) -> HashMap<String, Option<Vec<Vulnerability>>>{
    let mut depwithvuln: HashMap<String, Option<Vec<Vulnerability>>> = HashMap::new();
    for (reference, vuln) in vulnmap{
        if !(vuln.clone().expect("").is_empty()){
            depwithvuln.insert(reference, vuln);
        }
    }
    depwithvuln
}