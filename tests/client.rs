mod support;
use futures_util::stream::StreamExt;
use support::*;

use reqwest_impersonate::Client;

#[tokio::test]
async fn auto_headers() {
    let server = server::http(move |req| async move {
        assert_eq!(req.method(), "GET");

        assert_eq!(req.headers()["accept"], "*/*");
        assert_eq!(req.headers().get("user-agent"), None);
        if cfg!(feature = "gzip") {
            assert!(req.headers()["accept-encoding"]
                .to_str()
                .unwrap()
                .contains("gzip"));
        }
        if cfg!(feature = "brotli") {
            assert!(req.headers()["accept-encoding"]
                .to_str()
                .unwrap()
                .contains("br"));
        }
        if cfg!(feature = "deflate") {
            assert!(req.headers()["accept-encoding"]
                .to_str()
                .unwrap()
                .contains("deflate"));
        }

        http::Response::default()
    });

    let url = format!("http://{}/1", server.addr());
    let res = reqwest_impersonate::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(&url)
        .send()
        .await
        .unwrap();

    assert_eq!(res.url().as_str(), &url);
    assert_eq!(res.status(), reqwest_impersonate::StatusCode::OK);
    assert_eq!(res.remote_addr(), Some(server.addr()));
}

#[tokio::test]
async fn user_agent() {
    let server = server::http(move |req| async move {
        assert_eq!(
            req.headers()["user-agent"],
            "reqwest_impersonate-test-agent"
        );
        http::Response::default()
    });

    let url = format!("http://{}/ua", server.addr());
    let res = reqwest_impersonate::Client::builder()
        .user_agent("reqwest_impersonate-test-agent")
        .build()
        .expect("client builder")
        .get(&url)
        .send()
        .await
        .expect("request");

    assert_eq!(res.status(), reqwest_impersonate::StatusCode::OK);
}

#[tokio::test]
async fn response_text() {
    let _ = env_logger::try_init();

    let server = server::http(move |_req| async { http::Response::new("Hello".into()) });

    let client = Client::new();

    let res = client
        .get(&format!("http://{}/text", server.addr()))
        .send()
        .await
        .expect("Failed to get");
    assert_eq!(res.content_length(), Some(5));
    let text = res.text().await.expect("Failed to get text");
    assert_eq!("Hello", text);
}

#[tokio::test]
async fn response_bytes() {
    let _ = env_logger::try_init();

    let server = server::http(move |_req| async { http::Response::new("Hello".into()) });

    let client = Client::new();

    let res = client
        .get(&format!("http://{}/bytes", server.addr()))
        .send()
        .await
        .expect("Failed to get");
    assert_eq!(res.content_length(), Some(5));
    let bytes = res.bytes().await.expect("res.bytes()");
    assert_eq!("Hello", bytes);
}

#[tokio::test]
#[cfg(feature = "json")]
async fn response_json() {
    let _ = env_logger::try_init();

    let server = server::http(move |_req| async { http::Response::new("\"Hello\"".into()) });

    let client = Client::new();

    let res = client
        .get(&format!("http://{}/json", server.addr()))
        .send()
        .await
        .expect("Failed to get");
    let text = res.json::<String>().await.expect("Failed to get json");
    assert_eq!("Hello", text);
}

#[tokio::test]
async fn body_pipe_response() {
    let _ = env_logger::try_init();

    let server = server::http(move |mut req| async move {
        if req.uri() == "/get" {
            http::Response::new("pipe me".into())
        } else {
            assert_eq!(req.uri(), "/pipe");
            assert_eq!(req.headers()["transfer-encoding"], "chunked");

            let mut full: Vec<u8> = Vec::new();
            while let Some(item) = req.body_mut().next().await {
                full.extend(&*item.unwrap());
            }

            assert_eq!(full, b"pipe me");

            http::Response::default()
        }
    });

    let client = Client::new();

    let res1 = client
        .get(&format!("http://{}/get", server.addr()))
        .send()
        .await
        .expect("get1");

    assert_eq!(res1.status(), reqwest_impersonate::StatusCode::OK);
    assert_eq!(res1.content_length(), Some(7));

    // and now ensure we can "pipe" the response to another request
    let res2 = client
        .post(&format!("http://{}/pipe", server.addr()))
        .body(res1)
        .send()
        .await
        .expect("res2");

    assert_eq!(res2.status(), reqwest_impersonate::StatusCode::OK);
}

#[tokio::test]
async fn overridden_dns_resolution_with_gai() {
    let _ = env_logger::builder().is_test(true).try_init();
    let server = server::http(move |_req| async { http::Response::new("Hello".into()) });

    let overridden_domain = "rust-lang.org";
    let url = format!(
        "http://{}:{}/domain_override",
        overridden_domain,
        server.addr().port()
    );
    let client = reqwest_impersonate::Client::builder()
        .resolve(overridden_domain, server.addr())
        .build()
        .expect("client builder");
    let req = client.get(&url);
    let res = req.send().await.expect("request");

    assert_eq!(res.status(), reqwest_impersonate::StatusCode::OK);
    let text = res.text().await.expect("Failed to get text");
    assert_eq!("Hello", text);
}

#[tokio::test]
async fn overridden_dns_resolution_with_gai_multiple() {
    let _ = env_logger::builder().is_test(true).try_init();
    let server = server::http(move |_req| async { http::Response::new("Hello".into()) });

    let overridden_domain = "rust-lang.org";
    let url = format!(
        "http://{}:{}/domain_override",
        overridden_domain,
        server.addr().port()
    );
    // the server runs on IPv4 localhost, so provide both IPv4 and IPv6 and let the happy eyeballs
    // algorithm decide which address to use.
    let client = reqwest_impersonate::Client::builder()
        .resolve_to_addrs(
            overridden_domain,
            &[
                std::net::SocketAddr::new(
                    std::net::IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                    server.addr().port(),
                ),
                server.addr(),
            ],
        )
        .build()
        .expect("client builder");
    let req = client.get(&url);
    let res = req.send().await.expect("request");

    assert_eq!(res.status(), reqwest_impersonate::StatusCode::OK);
    let text = res.text().await.expect("Failed to get text");
    assert_eq!("Hello", text);
}

#[cfg(feature = "trust-dns")]
#[tokio::test]
async fn overridden_dns_resolution_with_trust_dns() {
    let _ = env_logger::builder().is_test(true).try_init();
    let server = server::http(move |_req| async { http::Response::new("Hello".into()) });

    let overridden_domain = "rust-lang.org";
    let url = format!(
        "http://{}:{}/domain_override",
        overridden_domain,
        server.addr().port()
    );
    let client = reqwest_impersonate::Client::builder()
        .resolve(overridden_domain, server.addr())
        .trust_dns(true)
        .build()
        .expect("client builder");
    let req = client.get(&url);
    let res = req.send().await.expect("request");

    assert_eq!(res.status(), reqwest_impersonate::StatusCode::OK);
    let text = res.text().await.expect("Failed to get text");
    assert_eq!("Hello", text);
}

#[cfg(feature = "trust-dns")]
#[tokio::test]
async fn overridden_dns_resolution_with_trust_dns_multiple() {
    let _ = env_logger::builder().is_test(true).try_init();
    let server = server::http(move |_req| async { http::Response::new("Hello".into()) });

    let overridden_domain = "rust-lang.org";
    let url = format!(
        "http://{}:{}/domain_override",
        overridden_domain,
        server.addr().port()
    );
    // the server runs on IPv4 localhost, so provide both IPv4 and IPv6 and let the happy eyeballs
    // algorithm decide which address to use.
    let client = reqwest_impersonate::Client::builder()
        .resolve_to_addrs(
            overridden_domain,
            &[
                std::net::SocketAddr::new(
                    std::net::IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                    server.addr().port(),
                ),
                server.addr(),
            ],
        )
        .trust_dns(true)
        .build()
        .expect("client builder");
    let req = client.get(&url);
    let res = req.send().await.expect("request");

    assert_eq!(res.status(), reqwest_impersonate::StatusCode::OK);
    let text = res.text().await.expect("Failed to get text");
    assert_eq!("Hello", text);
}
