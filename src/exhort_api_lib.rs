use exhort_validator::run_command;
use reqwest;
use serde_derive::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ExhortResponse{
    dependencies: Vec<ApiResponse>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse{
    #[serde(rename = "ref")]
    reference: String,
    issues: Vec<Issues>,
    transitive: Vec<Transitive>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Issues{
    #[serde(skip_serializing_if="Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    title: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    severity: Option<String>,
    #[serde(skip_serializing_if="Option::is_none")]
    cvssScore: Option<f64>,
    #[serde(skip_serializing_if="Option::is_none")]
    cves: Option<Vec<String>>,
    #[serde(skip_serializing_if="Option::is_none")]
    cvss: Option<CVSS>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CVSS{
    exploitCodeMaturity: Option<String>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Transitive{
    #[serde(rename = "ref")]
    reference: String,
    issues: Option<Vec<Issues>>,
}

pub async fn get_exhort_response(sbom_input: String)-> ExhortResponse{
    let url = "https://exhort-alpha.stage.devshift.net/api/v3/analysis";
    let response =reqwest::Client::new()
        .post(url.to_owned())
        .header("Content-Type", "application/vnd.cyclonedx+json")
        .header("Accept", "application/json")
        .body(sbom_input)
        .send()
        .await
        .unwrap().text().await.expect("msg");
    let parsed_data: ExhortResponse = serde_json::from_str(&response).expect("Failed to parse data to Json");
    parsed_data
}