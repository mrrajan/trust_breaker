# Exhort Validator

Exhort Validator is a rust based validation tool to verify the Dependency analytics report generated from [Exhort API](https://github.com/RHEcosystemAppEng/exhort) for the give CycloneDX SBOM file.\
\
Exhort Validator retrieves the vulnerability information from OSV and NVD Databases for each package URL from the input SBOM file. It is capable of flattening out the dependencies for each package from its child and child of child dependencies.\
By aligning the vulnerability for each package and its dependencies, Exhort Validator produces a Json report with direct and transitive vulnerabilities for each package URL \
\
This information is validated against the Dependency analytics report generated from Exhort API.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)

## Pre-Requisites
Make sure [Rust](https://doc.rust-lang.org/book/ch01-01-installation.html) is installed on your machine, That's all you need!

## Installation
```sh
git clone https://github.com/mrrajan/exhort_validator.git
cd exhort_validator
cargo build
```
## Usage
- Open the [main.rs](src/main.rs) file under the `src` directory
- Update the CycloneDX SBOM file [path](https://github.com/mrrajan/exhort_validator/blob/29c5593d99d4bf46efc999c21fd186aafa806024/src/main.rs#L13) on `let sbom_file = "<SBOM Directory>";` The file path should be absolute like `/home/<user>/SBOM/keycloak_cyclonedx_sbom.json`
- Run the command `cargo run`
## Logs and Outputs
\
The script generates three files,
- *exhort_validator.log:* Log file, captures the events while running the script
- *exhort.json:* Captures the Dependency analytics JSON Response from the Exhort API
- *osv_dep_analysis.json:* Captures the Vulnerability information Json report from the Exhort Validator 

### Limitation
The current version of Exhort validator is capable to consume CycloneDX SBOM format. 