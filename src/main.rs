mod exhort;
mod osv_nvd;
mod sbom_cdx;
mod compare;
use std::collections::HashMap;
use log::{error, info};
use simplelog::*;
use crate::exhort::ExhortResponse;
use crate::osv_nvd::{OSVResults, Vulnerability};

#[tokio::main]
async fn main() {
    let sbom_file = "<SBOM Directory>";
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
    let (osvresponse, mut purl_with_vuln) = osv_nvd::retrieve_sbom_osv_vulns(&sbom_file).await;
    let exhort:ExhortResponse = exhort::get_exhort_response(sbom_file).await;
    compare::compare_exhort_osvnvd(exhort, osvresponse, purl_with_vuln).await;
}
