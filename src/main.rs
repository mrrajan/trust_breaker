
mod snyk_api_lib;
mod exhort_api_lib;
mod provider;
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
    provider::retrieve_sbom_purl_vulns("<SBOM file directory>").await;

    /*
    let snyk_token = "<token-here>";
    println!("--------------------------------------------------------------------------------------------------------");
    snyk_api_lib::pom_synk_response(snyk_token).await;
    println!("--------------------------------------------------------------------------------------------------------");
    exhort_api_lib::exhort_response(snyk_token).await;
    println!("--------------------------------------------------------------------------------------------------------");
     */
}

