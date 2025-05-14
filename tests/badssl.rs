#[tokio::test]
async fn test_badssl_modern() {
    let text = reqwest_impersonate::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get("https://mozilla-modern.badssl.com/")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(text.contains("<title>mozilla-modern.badssl.com</title>"));
}

#[tokio::test]
async fn test_badssl_self_signed() {
    let text = reqwest_impersonate::Client::builder()
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .build()
        .unwrap()
        .get("https://self-signed.badssl.com/")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(text.contains("<title>self-signed.badssl.com</title>"));
}
