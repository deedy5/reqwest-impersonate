# reqwest-impersonate

A fork of reqwest used to emulate browsers.

**Notice:** This crate depends on patched dependencies. To use it, please add the following to your `Cargo.toml`.

```toml
[patch.crates-io]
hyper = { git = "https://github.com/deedy5/hyper.git", branch = "v0.14.32-patched" }
h2 = { git = "https://github.com/deedy5/h2.git", branch = "0.3.26-patched" }
```



## Example

`Cargo.toml`

```toml
reqwest-impersonate = { git = "https://github.com/deedy5/reqwest-impersonate.git", default-features = false, features = ["chrome"] }
```

`main.rs`

```rs
use reqwest_impersonate::browser::ChromeVersion;

fn main() {
    // Build a client to mimic Chrome 104
    let client = reqwest_impersonate::blocking::Client::builder()
        .chrome_builder(ChromeVersion::V104)
        .build()
        .unwrap();

    // Use the API you're already familiar with
    match client.get("https://yoururl.com").send() {
        Ok(res) => {
            println!("{:?}", res.text().unwrap());
        }
        Err(err) => {
            dbg!(err);
        }
    };
}
```
