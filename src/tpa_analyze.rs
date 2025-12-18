use std::{collections::HashMap, error::Error};

use csv::Writer;
use log::{error, info};
use reqwest;
use reqwest::StatusCode;
use serde_derive::{Deserialize, Serialize};
use serde_json::{from_str, json, to_string_pretty};
use tokio::{fs::OpenOptions, io::AsyncWriteExt};

use crate::sbom_spdx::Package;

#[derive(Serialize, Deserialize, Debug)]
pub struct Score {
    #[serde(rename = "type")]
    pub cvssType: String,
    pub value: f32,
    pub severity: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Labels {
    //pub importer: String,
    #[serde(rename = "type")]
    pub importerType: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AffContent {
    pub identifier: String,
    pub title: String,
    pub labels: Labels,
    pub scores: Vec<Score>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Affected {
    pub affected: Vec<AffContent>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Vulnerability {
    pub identifier: String,
    pub status: Affected,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TPAResponse {
    #[serde(flatten)]
    pub tpa_response: HashMap<String, PackageResponse>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PackageResponse {
    pub details: Vec<Vulnerability>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TPAHeaders {
    pub PURL: String,
    pub CVE_ID: String,
    pub OSV_ID: String,
    pub CVSS: String,
    pub CVSSType: String,
    pub Source: String,
}

pub async fn tpa_purl_vuln_analyze(tpa_base_url: &str, tpa_access_token: &str, purls: Vec<String>) -> Vec<TPAHeaders> {
    info!("RHTPA: Initiate process...");
    let tpa_analyze_endpoint = format!("{}/api/v2/vulnerability/analyze", tpa_base_url);
    info!("TPA Endpoint: {}", tpa_analyze_endpoint);
    let content_body =
        format! {"{{\"purls\":[{}]}}",purls.iter().map(|purl| format!("\"{}\"",purl)).collect::<Vec<_>>().join(",")};
    let response = reqwest::Client::new()
        .post(tpa_analyze_endpoint.to_owned())
        .header("Content-Type", "application/json")
        //.header("Accept", "application/json")
        .header("Authorization", format!("Bearer {}", tpa_access_token))
        .body(content_body)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let text_response = response.text().await.unwrap();
    if status == StatusCode::OK {
        let tpa_response: TPAResponse = from_str(&text_response).expect("Error while parsing");
        match write_tpa_result(tpa_response).await {
            Ok(tpa_vulnerability) => tpa_vulnerability,
            Err(e) => {
                error!("Failed to write TPA result: {}", e);
                Vec::new()
            }
        }
    } else {
        error!(
            "Error Reaching to TPA: \nError code - {} \nResponse -  {}",
            status, text_response
        );
        Vec::new()
    }
}

pub async fn write_tpa_result(tpa_response: TPAResponse) -> Result<Vec<TPAHeaders>, Box<dyn Error>> {
    info!("Writing TPA Response to output files...");
    let now: chrono::DateTime<chrono::Local> = chrono::offset::Local::now();
    let custom_datetime_format = now.format("%Y%m%y_%H%M%S");
    let file_path = format!("test_results/source/tpa_response_{}", custom_datetime_format);
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(file_path.clone() + ".json")
        .await
        .expect("Error while creating TPA log file");
    let response_str = to_string_pretty(&tpa_response).expect("Error while parsing TPA response to json");
    file.write_all(response_str.as_bytes())
        .await
        .expect("Error writing TPA response to log");
    let mut wtr = Writer::from_path(file_path.clone() + ".csv")?;
    let mut tpa_values: Vec<TPAHeaders> = Vec::new();
    for (purl, packageDetails) in tpa_response.tpa_response {
        for vuln in packageDetails.details {
            for affected in vuln.status.affected {
                for score in affected.scores {
                    tpa_values.push(TPAHeaders {
                        PURL: purl.to_string(),
                        CVE_ID: vuln.identifier.to_string(),
                        OSV_ID: affected.identifier.to_string(),
                        CVSS: score.value.to_string(),
                        CVSSType: score.cvssType.to_string(),
                        Source: affected.labels.importerType.to_string(),
                    });
                }
            }
        }
    }
    for row in &tpa_values {
        wtr.serialize(row)?;
    }
    wtr.flush()?;
    info!("RHTPA: Retrieved Response...");
    Ok(tpa_values)
}
