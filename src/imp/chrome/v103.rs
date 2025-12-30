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
            enable_push: None,
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
    headers.insert(
        HeaderName::from_static("sec-ch-ua"),
        HeaderValue::from_static(
            "\"Chromium\";v=\"103\", \" Not A;Brand\";v=\"99\", \"Google Chrome\";v=\"103\"",
        ),
    );
    headers.insert(
        HeaderName::from_static("user-agent"),
        match impersonate_os {
            crate::ImpersonateOS::Windows => HeaderValue::from_static(
                "\"Chromium\";v=\"103\", \" Not A;Brand\";v=\"99\", \"Google Chrome\";v=\"103\"",
            ),
            crate::ImpersonateOS::Linux => HeaderValue::from_static(
                "\"Chromium\";v=\"103\", \" Not A;Brand\";v=\"99\", \"Google Chrome\";v=\"103\"",
            ),
            crate::ImpersonateOS::IOS => HeaderValue::from_static(
                "\"Chromium\";v=\"103\", \" Not A;Brand\";v=\"99\", \"Google Chrome\";v=\"103\"",
            ),
            crate::ImpersonateOS::Android => HeaderValue::from_static(
                "\"Chromium\";v=\"103\", \" Not A;Brand\";v=\"99\", \"Google Chrome\";v=\"103\"",
            ),
            crate::ImpersonateOS::MacOS => HeaderValue::from_static(
                "\"Chromium\";v=\"103\", \" Not A;Brand\";v=\"99\", \"Google Chrome\";v=\"103\"",
            ),
        },
    );
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
    use std::time::Instant;

    #[test]
    fn bench_create_headers() {
        let start = Instant::now();
        for _ in 0..100_000 {
            let _ = create_headers(None);
        }
        let elapsed = start.elapsed();
        println!("create_headers took {} s", elapsed.as_secs_f32());
    }
}
