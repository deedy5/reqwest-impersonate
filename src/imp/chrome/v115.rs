use std::sync::Arc;

use boring::ssl::{SslConnector, SslConnectorBuilder, SslMethod, SslVersion};
use http::{HeaderMap, HeaderName, HeaderValue};

use super::{CIPHER_LIST, SIGALGS_LIST};
use crate::imp::{cert_compressor, BrowserSettings, Http2Data};

pub(super) fn get_settings(os_type: Option<crate::imp::ImpersonateOS>) -> BrowserSettings {
    BrowserSettings {
        tls_builder_func: Arc::new(create_ssl_connector),
        http2: Http2Data {
            initial_stream_window_size: Some(6291456),
            initial_connection_window_size: Some(15728640),
            max_concurrent_streams: Some(1000),
            max_header_list_size: Some(262144),
            header_table_size: Some(65536),
            enable_push: Some(false),
        },
        headers: create_headers(os_type),
        gzip: true,
        brotli: true,
        zstd: false,
    }
}

fn create_ssl_connector() -> SslConnectorBuilder {
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();

    builder.enable_ocsp_stapling();
    builder.enable_signed_cert_timestamps();

    builder.set_grease_enabled(true);

    builder.set_cipher_list(&CIPHER_LIST).unwrap();
    builder.set_sigalgs_list(&SIGALGS_LIST).unwrap();

    builder.set_alpn_protos(b"\x02h2\x08http/1.1").unwrap();

    builder
        .add_certificate_compression_algorithm(cert_compressor::BrotliCompressor::default())
        .unwrap();

    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();

    builder
}

fn create_headers(impersonate_os: Option<crate::imp::ImpersonateOS>) -> HeaderMap {
    let impersonate_os = impersonate_os.unwrap_or_default();
    let mut headers = HeaderMap::new();

    // Chrome 115 headers
    headers.insert(
        HeaderName::from_static("sec-ch-ua"),
        HeaderValue::from_static(
            "\"Chromium\";v=\"115\", \"Google Chrome\";v=\"115\", \"Not;A=Brand\";v=\"99\"",
        ),
    );
    headers.insert(
        HeaderName::from_static("sec-ch-ua-mobile"),
        match impersonate_os {
            crate::ImpersonateOS::Android | crate::ImpersonateOS::IOS => {
                HeaderValue::from_static("?1")
            }
            _ => HeaderValue::from_static("?0"),
        },
    );
    headers.insert(
        HeaderName::from_static("sec-ch-ua-platform"),
        match impersonate_os {
            crate::ImpersonateOS::Windows => HeaderValue::from_static("\"Windows\""),
            crate::ImpersonateOS::MacOS => HeaderValue::from_static("\"macOS\""),
            crate::ImpersonateOS::Linux => HeaderValue::from_static("\"Linux\""),
            crate::ImpersonateOS::Android => HeaderValue::from_static("\"Android\""),
            crate::ImpersonateOS::IOS => HeaderValue::from_static("\"iOS\""),
        },
    );
    headers.insert(HeaderName::from_static("user-agent"),
        match impersonate_os {
            crate::ImpersonateOS::Windows => HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"),
            crate::ImpersonateOS::MacOS => HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"),
            crate::ImpersonateOS::Linux => HeaderValue::from_static("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"),
            crate::ImpersonateOS::Android => HeaderValue::from_static("Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Mobile Safari/537.36"),
            crate::ImpersonateOS::IOS => HeaderValue::from_static("Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1"),
        });
    headers.insert(
        HeaderName::from_static("upgrade-insecure-requests"),
        HeaderValue::from_static("1"),
    );
    headers.insert(
        HeaderName::from_static("sec-fetch-site"),
        HeaderValue::from_static("none"),
    );
    headers.insert(
        HeaderName::from_static("sec-fetch-mode"),
        HeaderValue::from_static("navigate"),
    );
    headers.insert(
        HeaderName::from_static("sec-fetch-user"),
        HeaderValue::from_static("?1"),
    );
    headers.insert(
        HeaderName::from_static("sec-fetch-dest"),
        HeaderValue::from_static("document"),
    );
    headers.insert(HeaderName::from_static("accept"),
                  HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"));
    headers.insert(
        HeaderName::from_static("accept-encoding"),
        HeaderValue::from_static("gzip, deflate, br"),
    );
    headers.insert(
        HeaderName::from_static("accept-language"),
        HeaderValue::from_static("en-US,en;q=0.9"),
    );

    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_v115() {
        let settings = get_settings(None);
        let headers = settings.headers;

        let sec_ch_ua = headers.get("sec-ch-ua").unwrap();
        assert_eq!(
            sec_ch_ua.to_str().unwrap(),
            "\"Chromium\";v=\"115\", \"Google Chrome\";v=\"115\", \"Not;A=Brand\";v=\"99\""
        );
    }
}
