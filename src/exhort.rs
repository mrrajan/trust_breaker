use log::error;
use std::fs::OpenOptions;
use std::io::Write;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use reqwest;
use reqwest::StatusCode;
use serde_derive::{Deserialize, Serialize};
use serde_json::to_string_pretty;

#[derive(Serialize, Deserialize, Debug)]
pub struct ExhortResponse{
    providers: ResponseContent,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ResponseContent{
    #[serde(rename = "trusted-content")]
    trustedcontent: Status,
    #[serde(rename="osv-nvd")]
    osvnvd: OSVNVD

}

#[derive(Serialize, Deserialize, Debug)]
pub struct Status {
    status: Code
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Code {
    code: u32
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OSVNVD {
    status: Code,
    sources: OSVSources
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OSVSources {
    #[serde(rename="osv-nvd")]
    osvnvd: OSVDependencies,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OSVDependencies {
    dependencies: Vec<ApiResponse>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse {
    #[serde(rename = "ref")]
    reference: String,
    issues: Vec<Issues>,
    transitive: Vec<Transitive>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Issues {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cvssScore: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cves: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cvss: Option<CVSS>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CVSS {
    exploitCodeMaturity: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Transitive {
    #[serde(rename = "ref")]
    reference: String,
    issues: Option<Vec<Issues>>,
}

pub async fn get_exhort_response(file_path: &str) -> ExhortResponse {
    let mut file = File::open(file_path).await.expect("Error opening the file");
    let mut content_str = String::new();
    file.read_to_string(&mut content_str).await.expect("");
    let url = "https://rhda.rhcloud.com/api/v4/analysis";
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

    let parsed_data: ExhortResponse =  serde_json::from_str(&text_res).expect("Failure");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open("exhort.json")
        .expect("File creation failed");
    let json_str = to_string_pretty(&parsed_data).expect("Failed to serialize JSON");
    file.write_all(json_str.as_bytes()).expect("Writing failed");
    parsed_data
}
