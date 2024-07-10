# Trust Breaker

Trust Breaker is a Rust-based tool designed to generate JSON vulnerability reports from a given CycloneDX SBOM file. It extracts package URLs from the *components* section and flattens the dependencies for each package using the *dependencies* section. By aggregating vulnerability information for each package and its dependencies, Trust Breaker produces a JSON report that includes both direct and transitive vulnerabilities. The vulnerability data for the packages is sourced from the OSV database.\
\
Additionally, the tool can compare the results against a specified [Exhort API](https://github.com/RHEcosystemAppEng/exhort) and generate a log file that highlights any discrepancies.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)

## Pre-Requisites
Make sure [Rust](https://doc.rust-lang.org/book/ch01-01-installation.html) installed on your machine, That's all you need!

## Installation
```sh
git clone https://github.com/mrrajan/trust_breaker.git
cd trust_breaker
cargo build
```
## Usage
- Open the [main.rs](src/main.rs) file under the `src` directory
- Update the CycloneDX SBOM file path on `let sbom_file = "<SBOM Directory>";` The file path should be absolute like `/home/<user>/SBOM/keycloak_cyclonedx_sbom.json`
- Update the Exhort API URL on `let exhort_api = "<Exhort API>";` - This field is optional and by specifying, the tool retrieves the JSON output from Exhort API and runs the comparison between the results. 
- Run the command `cargo run`
## Logs and Outputs
\
The script generates three files,
- *exhort_validator.log:* Log file, captures the events while running the script
- *exhort.json:* Captures the Dependency analytics JSON Response from the Exhort API
- *osv_dep_analysis.json:* Captures the Vulnerability information Json report from the Trust Breaker

### Limitation
The current version of Trust Breaker just supports CycloneDX SBOM format. 
