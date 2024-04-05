
mod exhort_api_lib;
mod osv_nvd;
mod sbom_cdx;
use log::{info, error};
use simplelog::*;

#[tokio::main]
async fn main(){
    CombinedLogger::init(
        vec![
            TermLogger::new(LevelFilter::Info, Config::default(), TerminalMode::Mixed,ColorChoice::Auto),
            WriteLogger::new(LevelFilter::Info, Config::default(), std::fs::File::create("exhort_validator.log").unwrap()),
        ]
    ).unwrap();
    osv_nvd::retrieve_sbom_purl_vulns("<SBOM file directory>").await;
}

