mod exhort;
mod osv;
mod sbom_cdx;
mod compare;
use std::collections::HashMap;
use log::{error, info};
use simplelog::*;
use crate::exhort::ExhortResponse;
use crate::osv::{OSVResults, Vulnerability};

#[tokio::main]
async fn main() {
    let sbom_file = "<SBOM Directory>";
    let exhort_api = "<Exhort API>";
    CombinedLogger::init(vec![
        TermLogger::new(
            LevelFilter::Info,
            Config::default(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        ),
        WriteLogger::new(
            LevelFilter::Info,
            Config::default(),
            std::fs::File::create("exhort_validator.log").unwrap(),
        ),
    ])
    .unwrap();
    let (osvresponse, mut purl_with_vuln) = osv::retrieve_sbom_osv_vulns(&sbom_file).await;
    if !exhort_api.is_empty(){
        let exhort:ExhortResponse = exhort::get_exhort_response(sbom_file, exhort_api).await;
        compare::compare_exhort_osvnvd(exhort, osvresponse, purl_with_vuln).await;
        info!("Validation completed, Please check the logs for the results");
    }    
}
