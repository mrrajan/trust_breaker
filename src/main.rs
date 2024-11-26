mod exhort;
mod osv;
mod sbom_cdx;
mod compare;
use std::collections::HashMap;
use log::{error, info};
use simplelog::*;
use crate::exhort::ExhortResponse;
use crate::osv::{OSVResults, Vulnerability};
use clap::{Command, Arg};

#[tokio::main]
async fn main() {
    let matches = Command::new("Trust Breaker")
        .about("Validates SBOM files against OSV vulnerabilities and optionally compares with Exhort API results.")
        .arg(
            Arg::new("sbom_file")
                .help("An absolute path to the CycloneDX SBOM file")
                .short('s')
                .long("sbom_file")
                .required(true)
        )
        .arg(
            Arg::new("exhort_api")
                .help("Exhort API URL (optional)")
                .short('e')
                .long("exhort_api")
                .required(false)
        )
        .get_matches();

    let sbom_file = matches.get_one::<String>("sbom_file").unwrap();
    let exhort_api = matches.get_one::<String>("exhort_api").map(|s| s.as_str()).unwrap_or(""); 
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
