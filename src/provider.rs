use serde::de::value::StringDeserializer;
use serde_derive::{Serialize, Deserialize};
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use std::collections::{HashMap, HashSet};
use serde_json::Value;
use log::{info, error};
use simplelog::*;

#[derive(Serialize,Deserialize,Debug)]
pub struct Component{
    name: String
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Metadata{
    component: Option<Component>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Components{
    purl: String
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Dependencies{
    #[serde(rename = "ref")]
    dependency_ref: String,
    dependsOn: Option<Vec<String>>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CycloneDXBOM{
    bomFormat: String,
    specVersion: String,
    serialNumber: Option<String>,
    metadata: Option<Metadata>,
    components: Vec<Components>,
    dependencies: Option<Vec<Dependencies>>
}

impl CycloneDXBOM{
    pub fn iter_component(&self) -> impl Iterator<Item = &Components>{
        self.components.iter()
    }
    pub fn iter_dependents(&self) -> impl Iterator<Item = &Dependencies>{
        self.dependencies.iter().flatten()
    }

}

#[derive(Serialize, Deserialize, Debug)]
pub struct Vulnerability{
    CVE_ID: String,
    CVSSScore: String
}

impl Vulnerability{
    fn new(cve: &str, cvss: &str)-> Self{
        Vulnerability{
            CVE_ID:cve.to_string(),
            CVSSScore:cvss.to_string()
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Vulns{
    vulnerabilities: Option<Vec<Vulnerability>>,
}

impl Vulns{
    fn new(vul: Option<Vec<Vulnerability>>) -> Self{
        Vulns{
            vulnerabilities: vul
        }
    }

}

#[derive(Serialize, Deserialize, Debug)]
pub struct OsvQuerybatchResponse{
    results: Option<Vec<OsvVulns>>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OsvVulns{
    vulns: Option<Vec<OsvVulnId>>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OsvVulnId{
    id: String
}
#[derive(Serialize, Deserialize, Debug)]
pub struct OSVAlias{
    aliases: Option<Vec<String>>,
}

impl OSVAlias{
    pub fn get_alias(&self) -> Option<&Vec<String>>{
        self.aliases.as_ref()
    }
}

impl OsvQuerybatchResponse{
    pub fn iter_results(&self) -> impl Iterator<Item = &Vec<OsvVulns>>{
        self.results.iter()
    }
}

impl OsvVulns{
    pub fn iter_vulns(&self) -> impl Iterator<Item = &Vec<OsvVulnId>>{
        self.vulns.iter()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Results{
    package: String,
    CVE: String,
    CVSSScore: String

}

impl Results {
    pub fn new(package: String, CVE: String, CVSSScore: String) -> Self{
        Results{
            package: package,
            CVE: CVE,
            CVSSScore: CVSSScore
        }
    }
}

pub async fn retrieve_sbom_purl_vulns(filepath: &str){
    let mut file = File::open(filepath).await.expect("Error opening the file");
    let mut content_str = String::new();
    file.read_to_string(&mut content_str).await.expect("");
    let data: CycloneDXBOM = serde_json::from_str(&content_str).expect("Error converting json");
    let mut vulnmap: HashMap<&str, Vulns> = HashMap::new();
    let mut dependencies: Option<Vec<String>> = None;
    let dep_tree = get_dep_tree(&data).await;
    for comp in data.iter_component(){
        info!("Getting vuln info for {:?}...", &comp.purl);
        let vuln: Vulns = Vulns::new(get_osv_vulnerability(&comp.purl).await);
        vulnmap.insert(&comp.purl, vuln);
    }
    info!("Vuln info gathing finished!");
    info!("Vulnerability Dump: {:?}", &vulnmap);
    for key in vulnmap.keys(){
        info!("Purl: {:?}", &key);
        let deps = flatten_dependencies(key,dep_tree.clone());
        info!("Deps: {:?}",deps);
    }
}

pub async fn get_osv_vulnerability(purl: &str) -> Option<Vec<Vulnerability>>{
    get_osv_response((&purl).to_string()).await
}

pub async fn get_osv_payload(purl: String) -> String{
    let json_str = r#"{"queries": [{"package": {"purl": "<purl>"}}]}"#;
    format!("{}",json_str.replace("<purl>", &purl))
}

pub async fn get_osv_response(purl: String)-> Option<Vec<Vulnerability>>{
    let osv_response = retrieve_osv_ghsa(purl.clone()).await;
    let mut vulns: Vec<Vulnerability> = Vec::new();
    if Some(&osv_response).is_some(){
        for osv_vuln in osv_response.iter_results(){
            for vuln in osv_vuln{
                if vuln.vulns.is_some(){
                    for id in vuln.iter_vulns() {
                        for ghsa in id{
                            let cves: OSVAlias = get_osv_cve(ghsa.id.clone()).await;
                            for cve in cves.aliases{
                                for id in cve{
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
    Some(vulns)
}

pub async fn retrieve_osv_ghsa(purl: String) -> OsvQuerybatchResponse{
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

pub async fn get_json_response(url: String) -> serde_json::Value{
    let response = reqwest::Client::new()
        .get(url)
        .header("Accept", "application/json")
        .send()
        .await
        .expect("Error from Response")
        .text()
        .await
        .expect("Error");
    let json_response: serde_json::Value = serde_json::from_str(&response).expect("Failure");
    json_response
}

pub async fn get_osv_cve(ghsa_id: String) -> OSVAlias{
    let url = format!("https://api.osv.dev/v1/vulns/{}",ghsa_id);
    let json_response: OSVAlias = reqwest::Client::new()
        .get(url)
        .header("Accept", "application/json")
        .send()
        .await
        .expect("Error from Response")
        .json::<OSVAlias>()
        .await
        .expect("Error");
    json_response
}

pub async fn get_nvd(cve: &str)-> Value{
    let url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=".to_owned()+cve;
    let json_response: serde_json::Value = get_json_response(url).await;
    let v31base= json_response["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"].clone();
    let v30base= json_response["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV30"][0]["cvssData"]["baseScore"].clone();
    let v2base= json_response["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"].clone();
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

pub async fn get_dep_tree(data: &CycloneDXBOM)->HashMap<&str, Option<Vec<String>>>{
    let mut deptree: HashMap<&str, Option<Vec<String>>> = HashMap::new();
    for comp in data.iter_component(){
        let mut dependencies: Option<Vec<String>> = None;
        if !(data.dependencies == None) {
            for dep in data.iter_dependents() {
                if comp.purl == dep.dependency_ref{
                   if let Some(dependency) = &dep.dependsOn{
                       dependencies = dep.dependsOn.clone();
                   }
                }
            }
        }
        deptree.insert(&comp.purl, dependencies);
    }
    deptree
}

pub fn flatten_dependencies(purl: &str, deptree: HashMap<&str, Option<Vec<String>>> )-> Vec<String> {
    let mut flatdep: Vec<String>= Vec::new();
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
