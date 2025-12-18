# Trust Breaker

Trust Breaker is a Rust-based tool designed to generate JSON vulnerability reports from a given SBOM file. It extracts package URLs from the *components* section and flattens the dependencies for each package using the *dependencies* section. By aggregating vulnerability information for each package and its dependencies, Trust Breaker produces a JSON report that includes both direct and transitive vulnerabilities. The vulnerability data for the packages is sourced from the OSV database.\



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

### Basic Usage (OSV Analysis Only)
```sh
cargo run -- -s /path/to/your/sbom.json -t cdx
# or for SPDX format:
cargo run -- -s /path/to/your/sbom.json -t spdx
```

### With Comparison (OSV vs TPA vs Exhort)
```sh
cargo run -- \
  -s /path/to/your/sbom.json \
  -t cdx \
  -c yes \
  -r <RHTPA_BASE_URL> \
  -a <RHTPA_ACCESS_TOKEN> \
  -e <EXHORT_API_URL>
```

### Arguments
- `-s`, `--sbom_file` (required): Absolute path to your SBOM file (CycloneDX or SPDX format)
- `-t`, `--sbom_type` (required): Type of SBOM file - either `cdx` (CycloneDX) or `spdx` (SPDX)
- `-c`, `--compare` (optional): Set to `yes` to enable comparison with RHTPA and Exhort results
- `-r`, `--tpa_url` (required if compare=yes): RHTPA Base URL
- `-a`, `--tpa_token` (required if compare=yes): RHTPA Access Token
- `-e`, `--exhort_url` (required if compare=yes): Exhort Backend URL
## Logs and Outputs

The tool generates the following output files in the `test_results/source/` directory:

### Log Files
- `exhort_validator.log`: Console and file log capturing all events during execution

### OSV Analysis Output
- `cdx_osv_<timestamp>.json`: OSV vulnerabilities in JSON format (for CycloneDX SBOM)
- `cdx_osv_<timestamp>.csv`: OSV vulnerabilities in CSV format (for CycloneDX SBOM)
- `spdx_osv_<timestamp>.json`: OSV vulnerabilities in JSON format (for SPDX SBOM)
- `spdx_osv_<timestamp>.csv`: OSV vulnerabilities in CSV format (for SPDX SBOM)

### Optional Comparison Output (when using -c yes)
- `tpa_response_<timestamp>.json`: RHTPA API response in JSON format
- `tpa_response_<timestamp>.csv`: RHTPA vulnerabilities in CSV format
- `exhort_response_<timestamp>.log`: Exhort API response in JSON format
- `exhort_response_<timestamp>.csv`: Exhort vulnerabilities in CSV format
- `comparison/comparison_osv_vs_tpa.csv`: Comparison between OSV and RHTPA results
- `comparison/comparison_tpa_vs_exhort.csv`: Comparison between RHTPA and Exhort results

