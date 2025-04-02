# Trust Breaker

Trust Breaker is a Rust-based tool designed to generate JSON vulnerability reports from a given CycloneDX SBOM file. It extracts package URLs from the *components* section and flattens the dependencies for each package using the *dependencies* section. By aggregating vulnerability information for each package and its dependencies, Trust Breaker produces a JSON report that includes both direct and transitive vulnerabilities. The vulnerability data for the packages is sourced from the OSV database.\

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
- `cargo run -- -s /home/<user>/SBOM/keycloak_cyclonedx_sbom.json` 
- The `-s`/`--sbom_file` argument is required and should contain an absolute path to your CycloneDX SBOM file.
- The `-t`/`--sbom_type` argument is required and the type of the SBOM file, could be either `cdx` or `spdx`
## Logs and Outputs
\
The script generates three files,
- *exhort_validator.log:* Log file, captures the events while running the script
- *<sbom_type>_osv_<timestamp>.json:* Captures the Affected packages and its vulnerabilities in Json format from OSV database
- *<sbom_type>_osv_<timestamp>.csv:* Captures the Affected packages and its vulnerabilities in CSV format from OSV database

