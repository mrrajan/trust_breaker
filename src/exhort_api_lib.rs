use exhort_validator::run_command;
use reqwest;
use serde_json::{Value, to_string_pretty};
use std::fs::{OpenOptions, File};
use std::io::{Write, Read};


pub async fn exhort_response(snyk_token: &str)-> Value{
    let response:serde_json::Value;
    let command = "mvn";
    let args = &["org.cyclonedx:cyclonedx-maven-plugin:2.7.6:makeBom","-DincludeTestScope=false", "-DoutputFormat=json","-DoutputName=bom","-f", "pom.xml"];
    run_command(command, args);
    let url = "https://exhort-alpha.stage.devshift.net/api/v3/analysis";
    let mut ofile = File::open("./target/bom.json").unwrap();
    let mut request_body = String::new();
    ofile.read_to_string(&mut request_body).expect("msg");
    response =reqwest::Client::new()
        .post(url.to_owned())
        .header("Content-Type", "application/vnd.cyclonedx+json")
        .header("Accept", "application/json")
        .header("ex-snyk-token",snyk_token)
        .body(request_body)
        .send()
        .await
        .unwrap().json().await.expect("msg");
    let mut file = OpenOptions::new().write(true).create(true)
    .append(true)
    .open("x_temp.json").expect("File creation failed");
    let json_str = to_string_pretty(&response).expect("Failed to serialize JSON");
    file.write_all(json_str.as_bytes()).expect("Writing failed");
    response
}