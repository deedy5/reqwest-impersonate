//! Settings for impersonating the Chrome browser

pub use crate::imp::Impersonate;
use crate::ClientBuilder;

mod v100;
mod v101;
mod v102;
mod v103;
mod v104;
mod v105;
mod v106;
mod v107;
mod v108;
mod v109;
mod v110;
mod v111;
mod v112;
mod v113;
mod v114;
mod v115;
mod v116;
mod v117;
mod v118;

use std::sync::LazyLock;

static CIPHER_LIST: LazyLock<String> = LazyLock::new(|| {
    const CIPHER_LIST: [&str; 15] = [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_AES_256_CBC_SHA",
    ];
    CIPHER_LIST.join(":")
});

static SIGALGS_LIST: LazyLock<String> = LazyLock::new(|| {
    const SIGALGS_LIST: [&str; 8] = [
        "ecdsa_secp256r1_sha256",
        "rsa_pss_rsae_sha256",
        "rsa_pkcs1_sha256",
        "ecdsa_secp384r1_sha384",
        "rsa_pss_rsae_sha384",
        "rsa_pkcs1_sha384",
        "rsa_pss_rsae_sha512",
        "rsa_pkcs1_sha512",
    ];
    SIGALGS_LIST.join(":")
});

/// Configures Chrome impersonation settings
pub fn configure_impersonate(
    chrome: Impersonate,
    builder: ClientBuilder,
    os_type: Option<crate::imp::ImpersonateOS>,
) -> ClientBuilder {
    // Use random selection for OS if not provided
    let (final_chrome, final_os) = crate::imp::get_random_impersonate_config(Some(chrome), os_type);
    
    let settings = match final_chrome {
        Impersonate::ChromeV100 => v100::get_settings(Some(final_os)),
        Impersonate::ChromeV101 => v101::get_settings(Some(final_os)),
        Impersonate::ChromeV102 => v102::get_settings(Some(final_os)),
        Impersonate::ChromeV103 => v103::get_settings(Some(final_os)),
        Impersonate::ChromeV104 => v104::get_settings(Some(final_os)),
        Impersonate::ChromeV105 => v105::get_settings(Some(final_os)),
        Impersonate::ChromeV106 => v106::get_settings(Some(final_os)),
        Impersonate::ChromeV107 => v107::get_settings(Some(final_os)),
        Impersonate::ChromeV108 => v108::get_settings(Some(final_os)),
        Impersonate::ChromeV109 => v109::get_settings(Some(final_os)),
        Impersonate::ChromeV110 => v110::get_settings(Some(final_os)),
        Impersonate::ChromeV111 => v111::get_settings(Some(final_os)),
        Impersonate::ChromeV112 => v112::get_settings(Some(final_os)),
        Impersonate::ChromeV113 => v113::get_settings(Some(final_os)),
        Impersonate::ChromeV114 => v114::get_settings(Some(final_os)),
        Impersonate::ChromeV115 => v115::get_settings(Some(final_os)),
        Impersonate::ChromeV116 => v116::get_settings(Some(final_os)),
        Impersonate::ChromeV117 => v117::get_settings(Some(final_os)),
        Impersonate::ChromeV118 => v118::get_settings(Some(final_os)),
    };

    builder
        .use_boring_tls(settings.tls_builder_func)
        .http2_initial_stream_window_size(settings.http2.initial_stream_window_size)
        .http2_initial_connection_window_size(settings.http2.initial_connection_window_size)
        .http2_max_concurrent_streams(settings.http2.max_concurrent_streams)
        .http2_max_header_list_size(settings.http2.max_header_list_size)
        .http2_header_table_size(settings.http2.header_table_size)
        .http2_enable_push(settings.http2.enable_push)
        .replace_default_headers(settings.headers)
        .brotli(settings.brotli)
        .gzip(settings.gzip)
        .zstd(settings.zstd)
}

#[cfg(test)]
mod tests {
    use crate::async_impl::client::Client;
    use crate::imp::Impersonate;
    use serde::{Deserialize, Serialize};

    /// BrowserLeaks.com API response structure
    #[derive(Debug, Serialize, Deserialize)]
    pub struct BrowserLeaksResponse {
        pub ja4: String,
        pub akamai_hash: String,
    }

    #[tokio::test]
    async fn test_chrome100() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::builder()
            .impersonate(Impersonate::ChromeV100)
            .build()?;
        let response = client
            .get("https://tls.browserleaks.com/json")
            .send()
            .await?
            .json::<BrowserLeaksResponse>()
            .await?;
        assert_eq!(response.ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(response.akamai_hash, "4f04edce68a7ecbe689edce7bf5f23f3");
        Ok(())
    }

    #[tokio::test]
    async fn test_chrome101() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::builder()
            .impersonate(Impersonate::ChromeV101)
            .build()?;
        let response = client
            .get("https://tls.browserleaks.com/json")
            .send()
            .await?
            .json::<BrowserLeaksResponse>()
            .await?;
        assert_eq!(response.ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(response.akamai_hash, "4f04edce68a7ecbe689edce7bf5f23f3");
        Ok(())
    }

    #[tokio::test]
    async fn test_chrome102() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::builder()
            .impersonate(Impersonate::ChromeV102)
            .build()?;
        let response = client
            .get("https://tls.browserleaks.com/json")
            .send()
            .await?
            .json::<BrowserLeaksResponse>()
            .await?;
        assert_eq!(response.ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(response.akamai_hash, "4f04edce68a7ecbe689edce7bf5f23f3");
        Ok(())
    }

    #[tokio::test]
    async fn test_chrome103() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::builder()
            .impersonate(Impersonate::ChromeV103)
            .build()?;
        let response = client
            .get("https://tls.browserleaks.com/json")
            .send()
            .await?
            .json::<BrowserLeaksResponse>()
            .await?;
        assert_eq!(response.ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(response.akamai_hash, "4f04edce68a7ecbe689edce7bf5f23f3");
        Ok(())
    }

    #[tokio::test]
    async fn test_chrome104() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::builder()
            .impersonate(Impersonate::ChromeV104)
            .build()?;
        let response = client
            .get("https://tls.browserleaks.com/json")
            .send()
            .await?
            .json::<BrowserLeaksResponse>()
            .await?;
        assert_eq!(response.ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(response.akamai_hash, "4f04edce68a7ecbe689edce7bf5f23f3");
        Ok(())
    }

    #[tokio::test]
    async fn test_chrome105() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::builder()
            .impersonate(Impersonate::ChromeV105)
            .build()?;
        let response = client
            .get("https://tls.browserleaks.com/json")
            .send()
            .await?
            .json::<BrowserLeaksResponse>()
            .await?;
        assert!(response.ja4 == "t13d1516h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(response.akamai_hash, "4f04edce68a7ecbe689edce7bf5f23f3");
        Ok(())
    }

    #[tokio::test]
    async fn test_chrome106() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::builder()
            .impersonate(Impersonate::ChromeV106)
            .build()?;
        let response = client
            .get("https://tls.browserleaks.com/json")
            .send()
            .await?
            .json::<BrowserLeaksResponse>()
            .await?;
        assert_eq!(response.ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(response.akamai_hash, "a345a694846ad9f6c97bcc3c75adbe26");
        Ok(())
    }

    #[tokio::test]
    async fn test_chrome107() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::builder()
            .impersonate(Impersonate::ChromeV107)
            .build()?;
        let response = client
            .get("https://tls.browserleaks.com/json")
            .send()
            .await?
            .json::<BrowserLeaksResponse>()
            .await?;
        assert_eq!(response.ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(response.akamai_hash, "a345a694846ad9f6c97bcc3c75adbe26");
        Ok(())
    }

    #[tokio::test]
    async fn test_chrome108() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::builder()
            .impersonate(Impersonate::ChromeV108)
            .build()?;
        let response = client
            .get("https://tls.browserleaks.com/json")
            .send()
            .await?
            .json::<BrowserLeaksResponse>()
            .await?;
        assert_eq!(response.ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(response.akamai_hash, "a345a694846ad9f6c97bcc3c75adbe26");
        Ok(())
    }

    #[tokio::test]
    async fn test_chrome109() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::builder()
            .impersonate(Impersonate::ChromeV109)
            .build()?;
        let response = client
            .get("https://tls.browserleaks.com/json")
            .send()
            .await?
            .json::<BrowserLeaksResponse>()
            .await?;
        assert_eq!(response.ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(response.akamai_hash, "a345a694846ad9f6c97bcc3c75adbe26");
        Ok(())
    }

    #[tokio::test]
    async fn test_chrome110() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::builder()
            .impersonate(Impersonate::ChromeV110)
            .build()?;
        let response = client
            .get("https://tls.browserleaks.com/json")
            .send()
            .await?
            .json::<BrowserLeaksResponse>()
            .await?;
        assert_eq!(response.ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(response.akamai_hash, "a345a694846ad9f6c97bcc3c75adbe26");
        Ok(())
    }

    #[tokio::test]
    async fn test_chrome111() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::builder()
            .impersonate(Impersonate::ChromeV111)
            .build()?;
        let response = client
            .get("https://tls.browserleaks.com/json")
            .send()
            .await?
            .json::<BrowserLeaksResponse>()
            .await?;
        assert_eq!(response.ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(response.akamai_hash, "a345a694846ad9f6c97bcc3c75adbe26");
        Ok(())
    }

    #[tokio::test]
    async fn test_chrome112() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::builder()
            .impersonate(Impersonate::ChromeV112)
            .build()?;
        let response = client
            .get("https://tls.browserleaks.com/json")
            .send()
            .await?
            .json::<BrowserLeaksResponse>()
            .await?;
        assert_eq!(response.ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(response.akamai_hash, "a345a694846ad9f6c97bcc3c75adbe26");
        Ok(())
    }

    #[tokio::test]
    async fn test_chrome113() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::builder()
            .impersonate(Impersonate::ChromeV113)
            .build()?;
        let response = client
            .get("https://tls.browserleaks.com/json")
            .send()
            .await?
            .json::<BrowserLeaksResponse>()
            .await?;
        assert_eq!(response.ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(response.akamai_hash, "a345a694846ad9f6c97bcc3c75adbe26");
        Ok(())
    }

    #[tokio::test]
    async fn test_chrome114() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::builder()
            .impersonate(Impersonate::ChromeV114)
            .build()?;
        let response = client
            .get("https://tls.browserleaks.com/json")
            .send()
            .await?
            .json::<BrowserLeaksResponse>()
            .await?;
        assert_eq!(response.ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(response.akamai_hash, "a345a694846ad9f6c97bcc3c75adbe26");
        Ok(())
    }

    #[tokio::test]
    async fn test_chrome115() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::builder()
            .impersonate(Impersonate::ChromeV115)
            .build()?;
        let response = client
            .get("https://tls.browserleaks.com/json")
            .send()
            .await?
            .json::<BrowserLeaksResponse>()
            .await?;
        assert_eq!(response.ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(response.akamai_hash, "a345a694846ad9f6c97bcc3c75adbe26");
        Ok(())
    }

    #[tokio::test]
    async fn test_chrome116() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::builder()
            .impersonate(Impersonate::ChromeV116)
            .build()?;
        let response = client
            .get("https://tls.browserleaks.com/json")
            .send()
            .await?
            .json::<BrowserLeaksResponse>()
            .await?;
        assert!(response.ja4 == "t13d1516h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(response.akamai_hash, "a345a694846ad9f6c97bcc3c75adbe26");
        Ok(())
    }

    #[tokio::test]
    async fn test_chrome117() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::builder()
            .impersonate(Impersonate::ChromeV117)
            .build()?;
        let response = client
            .get("https://tls.browserleaks.com/json")
            .send()
            .await?
            .json::<BrowserLeaksResponse>()
            .await?;
        assert_eq!(response.ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(response.akamai_hash, "a345a694846ad9f6c97bcc3c75adbe26");
        Ok(())
    }

    #[tokio::test]
    async fn test_chrome118() -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::builder()
            .impersonate(Impersonate::ChromeV118)
            .build()?;
        let response = client
            .get("https://tls.browserleaks.com/json")
            .send()
            .await?
            .json::<BrowserLeaksResponse>()
            .await?;
        assert_eq!(response.ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(response.akamai_hash, "a345a694846ad9f6c97bcc3c75adbe26");
        Ok(())
    }
}
