mod compare;
mod exhort;
mod osv;
mod sbom_cdx;
mod sbom_spdx;
mod tpa_analyze;
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
        .arg(
            Arg::new("compare")
                .help("To retrieve the results from RHTPA and Exhort backend for result comparison")
                .short('c')
                .long("compare")
                .required(false)
                .default_value("no"),
        )
        .arg(
            Arg::new("tpa_url")
                .help("RHTPA Base URL")
                .short('r')
                .long("tpa_url")
                .required(false),
        )
        .arg(
            Arg::new("tpa_token")
                .help("RHTPA Access token for the Base URL")
                .short('a')
                .long("tpa_token")
                .required(false),
        )
        .arg(
            Arg::new("exhort_url")
                .help("Exhort Backend URL")
                .short('e')
                .long("exhort_url")
                .required(false),
        )
        .get_matches();

    let sbom_file = matches.get_one::<String>("sbom_file").unwrap();
    let sbom_type = matches.get_one::<String>("sbom_type").unwrap();
    let compare = matches.get_one::<String>("compare").unwrap();

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

    let osv_records = osv::retrieve_sbom_osv_vulns(purl.clone(), &sbom_type)
        .await
        .unwrap_or_else(|e| {
            error!("Error retrieving OSV records: {}", e);
            Vec::new()
        });
    if compare == "yes"{
        let tpa_base_url = matches.get_one::<String>("tpa_url").unwrap();
        let tpa_access_token = matches.get_one::<String>("tpa_token").unwrap();
        let exhort_api = matches.get_one::<String>("exhort_url").unwrap();
        let tpa_records = tpa_analyze::tpa_purl_vuln_analyze(tpa_base_url, tpa_access_token, purl.clone()).await;
        let exhort_records = exhort::get_exhort_response(sbom_type, &sbom_file, exhort_api).await;
        if let Err(e) = compare::compare_sources(osv_records, tpa_records, exhort_records).await {
            error!("Error during comparison: {}", e);
        }
    }

}
