use reqwest::imp::{Impersonate, ImpersonateOS};

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main]
async fn main() -> Result<(), reqwest::Error> {
    // Build a client to mimic Chrome 104
    let client = reqwest::Client::builder()
        .impersonate(Impersonate::ChromeV104)
        .impersonate_os(ImpersonateOS::Linux)
        .build()
        .unwrap();

    match client.get("https://tls.browserleaks.com/json").send().await {
        Ok(res) => {
            let text = res.text().await?;
            println!("{}", text);
        }
        Err(err) => {
            dbg!(err);
        }
    };

    // Random impersonate 
    let client = reqwest::Client::builder()
        .impersonate_random()
        .build()
        .unwrap();

    match client.get("https://tls.browserleaks.com/json").send().await {
        Ok(res) => {
            let text = res.text().await?;
            println!("{}", text);
        }
        Err(err) => {
            dbg!(err);
        }
    };

    Ok(())
}
