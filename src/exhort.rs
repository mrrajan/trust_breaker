use serde_json::{json, to_string_pretty};
use log::info;
use log::error;
use std::fs::OpenOptions;
use std::io::Write;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use reqwest;
use reqwest::StatusCode;
use serde_derive::{Deserialize, Serialize};
use serde_json::from_str;
use serde_json::Value;
use std::{process, panic};

#[derive(Serialize, Deserialize, Debug)]
pub struct ExhortResponse{
    pub providers: ResponseContent,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ResponseContent{
    #[serde(rename = "trusted-content")]
    pub trustedcontent: Status,
    pub osv: OSV
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Status {
    pub status: Code
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Code {
    pub code: u32
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OSV {
    pub status: Code,
    pub sources: OSVSources
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OSVSources {
    pub osv: OSVDependencies,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OSVDependencies {
    pub dependencies: Vec<ApiResponse>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse {
    #[serde(rename = "ref")]
    pub reference: String,
    pub issues: Vec<Issues>,
    pub transitive: Vec<Transitive>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Issues {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvssScore: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cves: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss: Option<CVSS>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CVSS {
    exploitCodeMaturity: Option<String>,
}

#[derive(Debug, Serialize, Deserialize,Clone)]
pub struct Transitive {
    #[serde(rename = "ref")]
    pub reference: String,
    pub issues:Vec<Issues>,
}

pub async fn get_exhort_response(file_path: &str, exhort_api: &str) -> ExhortResponse {
    let mut file = File::open(file_path).await.expect("Error opening the file");
    let mut content_str = String::new();
    let mut exhort_response: ExhortResponse;
    file.read_to_string(&mut content_str).await.expect("");
    let url = exhort_api;
    let response = reqwest::Client::new()
        .post(url.to_owned())
        .header("Content-Type", "application/vnd.cyclonedx+json")
        .header("Accept", "application/json")
        .body(content_str)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let text_res = response.text().await.unwrap();
    if !(status == StatusCode::OK){
        error!("NVD API failed with Error body: {}",text_res);
    }
    if let Ok(parsed_data) = from_str::<ExhortResponse>(&text_res){
        exhort_response = parsed_data;
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open("exhort.json")
            .expect("File creation failed");
        let json_str = to_string_pretty(&exhort_response).expect("Failed to serialize JSON");
        file.write_all(json_str.as_bytes()).expect("Writing failed");
    }else{
        info!("Error while Parsing the response, The response might not have any vulnerabilities");
        process::exit(1);
    }
    exhort_response
}
