use serde_derive::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tokio::fs::File;
use tokio::io::AsyncReadExt;

#[derive(Debug, Serialize, Deserialize)]
pub struct externalRef {
    referenceType: String,
    referenceLocator: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Package {
    pub externalRefs: Option<Vec<externalRef>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Packages {
    pub packages: Vec<Package>,
}

pub async fn get_spdx_sbom_package(filepath: &str) -> Packages {
    let mut file = File::open(filepath)
        .await
        .expect("Error reading the file, make sure the path exists");
    let mut content_str = String::new();
    file.read_to_string(&mut content_str).await.expect("");
    let data: Packages = serde_json::from_str(&content_str).expect("Error converting json");
    data
}

pub async fn get_spdx_purl(data: Packages) -> Vec<String> {
    let mut purl_reference: Vec<String> = Vec::new();
    for package in data.packages {
        if let Some(external) = package.externalRefs {
            for er in external {
                if er.referenceType == "purl" {
                    purl_reference.push(er.referenceLocator);
                }
            }
        }
    }
    purl_reference
}
