
mod snyk_api_lib;
mod exhort_api_lib;

#[tokio::main]
async fn main(){
    let snyk_token = "<token-here>";
    println!("--------------------------------------------------------------------------------------------------------");
    snyk_api_lib::pom_synk_response(snyk_token).await;
    println!("--------------------------------------------------------------------------------------------------------");
    exhort_api_lib::exhort_response(snyk_token).await;
    println!("--------------------------------------------------------------------------------------------------------");
}

