#![cfg(not(target_arch = "wasm32"))]
mod support;

use http::HeaderValue;
use reqwest::Client;
use std::sync::Arc;

#[cfg(feature = "cookies")]
use reqwest::cookie::Jar;

// Test that ClientMut is properly exported from the public API
use reqwest::ClientMut;

#[tokio::test]
async fn test_client_as_mut() {
    let mut client = Client::new();

    // Test that as_mut() returns a ClientMut
    let mut client_mut = client.as_mut();

    // Verify that we can access the headers_mut method
    let _headers = client_mut.headers();
}

#[tokio::test]
async fn test_client_mut_headers() {
    let mut client = Client::builder().user_agent("test-agent").build().unwrap();

    let mut client_mut = client.as_mut();
    let headers = client_mut.headers();

    // Verify that the user agent header is present
    assert_eq!(headers.get("user-agent").unwrap(), "test-agent");

    // Add a new header
    headers.insert("x-test-header", HeaderValue::from_static("test-value"));

    // Verify the new header is present
    assert_eq!(headers.get("x-test-header").unwrap(), "test-value");
}

#[tokio::test]
async fn test_client_mut_redirect() {
    let mut client = Client::new();

    let mut client_mut = client.as_mut();

    // Test setting a custom redirect policy
    let policy = reqwest::redirect::Policy::none();
    client_mut.redirect(policy);

    // The client should now have the custom redirect policy
    // We can't easily test this without making a request that would redirect
    // but we can at least verify the method doesn't panic
}

#[cfg(feature = "cookies")]
#[tokio::test]
async fn test_client_mut_cookie_provider() {
    use std::sync::Arc;

    let mut client = Client::new();
    let cookie_store = Arc::new(Jar::default());

    let mut client_mut = client.as_mut();
    client_mut.cookie_provider(cookie_store.clone());

    // The client should now have the cookie provider set
    // We can't easily test this without making a request that involves cookies
    // but we can at least verify the method doesn't panic
}

#[tokio::test]
async fn test_client_mut_proxies_set() {
    let mut client = Client::new();

    let mut client_mut = client.as_mut();

    // Test setting proxies
    let proxies = vec![
        reqwest::Proxy::http("http://proxy1.example.com").unwrap(),
        reqwest::Proxy::https("http://proxy2.example.com").unwrap(),
    ];

    client_mut.proxies(proxies.clone());

    // The client should now have the proxies set
    // We can't easily test this without making actual requests
    // but we can at least verify the method doesn't panic
}

#[tokio::test]
async fn test_client_mut_proxies_clear() {
    let mut client = Client::builder()
        .proxy(reqwest::Proxy::http("http://proxy.example.com").unwrap())
        .build()
        .unwrap();

    let mut client_mut = client.as_mut();

    // Test clearing proxies
    client_mut.proxies(None::<Vec<reqwest::Proxy>>);

    // The client should now have no proxies
    // We can't easily test this without making actual requests
    // but we can at least verify the method doesn't panic
}

#[tokio::test]
async fn test_client_mut_proxies_http_auth_detection() {
    let mut client = Client::new();

    let mut client_mut = client.as_mut();

    // Test that proxies with HTTP basic auth are properly detected
    let proxies = vec![
        reqwest::Proxy::http("http://proxy.example.com").unwrap(),
        reqwest::Proxy::http("http://user:pass@proxy-auth.example.com").unwrap(),
    ];

    client_mut.proxies(proxies);

    // The client should detect that one proxy has HTTP auth
    // We can't easily test the internal detection logic
    // but we can at least verify the method doesn't panic
}

#[tokio::test]
async fn test_client_mut_multiple_calls() {
    let mut client = Client::new();

    // Test that we can call as_mut() multiple times in separate scopes
    {
        let mut client_mut1 = client.as_mut();
        let _headers1 = client_mut1.headers();
    }

    {
        let mut client_mut2 = client.as_mut();
        let _headers2 = client_mut2.headers();
    }
}

#[tokio::test]
async fn test_client_clone_with_client_mut() {
    let mut client = Client::new();

    // Modify client through ClientMut
    {
        let mut client_mut = client.as_mut();
        let headers = client_mut.headers();
        headers.insert("x-modified", HeaderValue::from_static("true"));
    }

    // Test that we can get ClientMut from the original client
    {
        let mut client_mut = client.as_mut();
        assert_eq!(client_mut.headers().get("x-modified").unwrap(), "true");
    }

    // Test basic functionality - that as_mut() returns the expected type
    fn type_check(_: reqwest::ClientMut) {}
    let client_mut = client.as_mut();
    type_check(client_mut);
}

#[cfg(feature = "cookies")]
#[tokio::test]
async fn test_client_mut_integration() {
    let mut client = Client::new();

    // Set up cookie store
    let cookie_store = Arc::new(Jar::default());
    {
        let mut client_mut = client.as_mut();
        client_mut.cookie_provider(cookie_store.clone());
    }

    // Modify headers
    {
        let mut client_mut = client.as_mut();
        let headers = client_mut.headers();
        headers.insert("x-custom-header", HeaderValue::from_static("custom-value"));
    }

    // Verify the modifications are in place
    let mut client_mut = client.as_mut();
    assert_eq!(
        client_mut.headers().get("x-custom-header").unwrap(),
        "custom-value"
    );
}

// Public API Tests

#[test]
fn test_client_mut_public_export() {
    // Test that ClientMut type is accessible from the public API
    // This test verifies that the type is properly exported
    let _type_check: Option<ClientMut> = None;
}

#[test]
fn test_client_as_mut_returns_public_type() {
    let mut client = Client::new();

    // Test that as_mut() returns the publicly exported ClientMut type
    let client_mut = client.as_mut();

    // Verify that the returned type is indeed ClientMut
    // This is a compile-time test - if it compiles, the export is working
    fn type_check(_: ClientMut) {}
    type_check(client_mut);
}

#[tokio::test]
async fn test_client_mut_methods_via_public_api() {
    let mut client = Client::new();

    // Test that all ClientMut methods work through the public API
    let mut client_mut = client.as_mut();

    // Test headers method
    let _headers = client_mut.headers();

    // Test redirect method
    let policy = reqwest::redirect::Policy::none();
    client_mut.redirect(policy);

    // Test proxies method
    client_mut.proxies(None::<Vec<reqwest::Proxy>>);
}

#[cfg(feature = "cookies")]
#[tokio::test]
async fn test_client_mut_cookie_provider_via_public_api() {
    use reqwest::cookie::Jar;
    use std::sync::Arc;

    let mut client = Client::new();
    let cookie_store = Arc::new(Jar::default());

    // Test that cookie_provider method works through the public API
    let mut client_mut = client.as_mut();
    client_mut.cookie_provider(cookie_store);
}

// Test that ClientMut is Send + Sync
#[test]
fn test_client_mut_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    assert_send::<ClientMut>();
    assert_sync::<ClientMut>();
}
