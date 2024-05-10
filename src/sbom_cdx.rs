use serde_derive::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tokio::fs::File;
use tokio::io::AsyncReadExt;

#[derive(Serialize, Deserialize, Debug)]
pub struct Component {
    name: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Metadata {
    component: Option<Component>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Components {
    pub purl: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Dependencies {
    #[serde(rename = "ref")]
    pub dependency_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dependsOn: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CycloneDXBOM {
    bomFormat: String,
    specVersion: String,
    serialNumber: Option<String>,
    metadata: Option<Metadata>,
    components: Vec<Components>,
    pub dependencies: Option<Vec<Dependencies>>,
}

impl CycloneDXBOM {
    pub fn iter_component(&self) -> impl Iterator<Item = &Components> {
        self.components.iter()
    }
    pub fn iter_dependents(&self) -> impl Iterator<Item = &Dependencies> {
        self.dependencies.iter().flatten()
    }
}

pub async fn get_cdx_purl(filepath: &str) -> CycloneDXBOM {
    let mut file = File::open(filepath).await.expect("Error opening the file");
    let mut content_str = String::new();
    file.read_to_string(&mut content_str).await.expect("");
    let data: CycloneDXBOM = serde_json::from_str(&content_str).expect("Error converting json");
    data
}
