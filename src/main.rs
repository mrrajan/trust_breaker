mod exhort;
mod osv_nvd;
mod sbom_cdx;
use log::{error, info};
use simplelog::*;

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
    osv_nvd::retrieve_sbom_osv_vulns(&sbom_file).await;
    exhort::get_exhort_response(sbom_file).await;
}
