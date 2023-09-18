use exhort_validator::run_command;
use reqwest;
use serde_derive::{Serialize, Deserialize};
use serde_json::{Value, to_string_pretty};
use std::fs::{OpenOptions, File};
use std::io::{Write, Read};

#[derive(Debug, Serialize, Deserialize)]
pub struct Dependencies{
    dependencies: Vec<ApiResponse>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse{
    #[serde(rename = "ref")]
    reference: String,
    issues: Vec<Issues>,
    transitive: Vec<transitive>,
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
pub struct transitive{
    #[serde(rename = "ref")]
    reference: String,
    issues: Option<Vec<Issues>>,
}



pub async fn exhort_response(snyk_token: &str)-> String{
    let command = "mvn";
    let args = &["org.cyclonedx:cyclonedx-maven-plugin:2.7.6:makeBom","-DincludeTestScope=false", "-DoutputFormat=json","-DoutputName=bom","-f", "pom.xml"];
    run_command(command, args);
    let url = "https://exhort-alpha.stage.devshift.net/api/v3/analysis";
    let mut ofile = File::open("./target/bom.json").unwrap();
    let mut request_body = String::new();
    ofile.read_to_string(&mut request_body).expect("msg");
    let response =reqwest::Client::new()
        .post(url.to_owned())
        .header("Content-Type", "application/vnd.cyclonedx+json")
        .header("Accept", "application/json")
        .header("ex-snyk-token",snyk_token)
        .body(request_body)
        .send()
        .await
        .unwrap().text().await.expect("msg");
    let parsed_data: Dependencies = serde_json::from_str(&response).expect("Failed to parse data to Json");
    let mut file = OpenOptions::new().write(true).create(true)
    .append(true)
    .open("x_temp.json").expect("File creation failed");
    let json_str = to_string_pretty(&parsed_data).expect("Failed to serialize JSON");
    file.write_all(json_str.as_bytes()).expect("Writing failed");
    response
}