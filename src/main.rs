mod compare;
mod exhort;
mod osv;
mod sbom_cdx;
mod sbom_spdx;
use clap::{Arg, Command};
use log::{error, info};
use simplelog::*;

#[tokio::main]
async fn main() {
    let matches = Command::new("Trust Breaker")
        .about("Validates SBOM files against OSV vulnerabilities and optionally compares with Exhort API results.")
        .arg(
            Arg::new("sbom_file")
                .help("An absolute path to the CycloneDX SBOM file")
                .short('s')
                .long("sbom_file")
                .required(true),
        )
        .arg(
            Arg::new("sbom_type")
                .help("SBOM Type")
                .short('t')
                .long("sbom_type")
                .required(true),
        )
        .get_matches();

    let sbom_file = matches.get_one::<String>("sbom_file").unwrap();
    let sbom_type = matches.get_one::<String>("sbom_type").unwrap();
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
    let mut purl: Vec<String> = Vec::new();
    if sbom_type == "cdx" {
        let components = sbom_cdx::get_cdx_components(&sbom_file).await;
        purl.extend(sbom_cdx::get_cdx_purl(components).await);
    } else if sbom_type == "spdx" {
        let packages = sbom_spdx::get_spdx_sbom_package(&sbom_file).await;
        purl.extend(sbom_spdx::get_spdx_purl(packages).await);
    } else {
        error!("Select sbom_type as either `cdx` or `spdx`");
    }
    osv::retrieve_sbom_osv_vulns(purl, &sbom_type).await;
    // todo
    // Retrieve vulnerability information from TPA analyze endpoint
    // Create comparison logic
    // Remove exhort.rs and compare.rs files if not needed
}
