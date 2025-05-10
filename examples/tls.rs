//! `cargo run --example tls --features=chrome`

#![deny(warnings)]

use reqwest_impersonate::browser::ChromeVersion;

// This is using the `tokio` runtime. You'll need the following dependency:
//
// `tokio = { version = "1", features = ["full"] }`

#[tokio::main]
async fn main() -> Result<(), reqwest_impersonate::Error> {
    // Build a client to mimic Chrome 104
    let client = reqwest_impersonate::Client::builder()
        .chrome_builder(ChromeVersion::V108)
        .build()
        .unwrap();

    // Use the API you're already familiar with
    let res = client.get("https://tls.peet.ws/api/all").send().await?;
    let body = res.text().await?;
    println!("{}", body);

    Ok(())
}
