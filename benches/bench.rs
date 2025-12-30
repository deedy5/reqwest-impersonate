//! Client creation performance benchmarks for reqwest-impersonate
//!
//! This benchmark suite measures the performance of client initialization operations,
//! focusing on the most fundamental operation: creating HTTP clients.

use std::hint::black_box;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::Client;

#[cfg(feature = "__impersonate")]
use reqwest::imp::{Impersonate, ImpersonateOS};

// ============================================================================
// CLIENT CREATION BENCHMARKS
// ============================================================================

fn bench_client_creation_async(c: &mut Criterion) {
    let mut group = c.benchmark_group("client_creation_async");

    group.bench_function("client_new", |b| {
        b.iter(|| {
            let client = Client::new();
            black_box(client);
        })
    });

    group.bench_function("client_builder_default", |b| {
        b.iter(|| {
            let client = Client::builder().build().unwrap();
            black_box(client);
        })
    });

    group.bench_function("client_builder_with_config", |b| {
        b.iter(|| {
            let mut headers = HeaderMap::new();
            headers.insert(
                "User-Agent",
                HeaderValue::from_static("Reqwest-Benchmark/1.0"),
            );

            let client = Client::builder()
                .timeout(Duration::from_secs(30))
                .pool_idle_timeout(Duration::from_secs(90))
                .default_headers(headers)
                .build()
                .unwrap();
            black_box(client);
        })
    });

    #[cfg(feature = "__impersonate")]
    group.bench_function("client_chrome_impersonation", |b| {
        b.iter(|| {
            let client = Client::builder()
                .impersonate(Impersonate::ChromeV104)
                .impersonate_os(ImpersonateOS::Linux)
                .build()
                .unwrap();
            black_box(client);
        })
    });

    #[cfg(feature = "__impersonate")]
    group.bench_function("client_impersonation_random", |b| {
        b.iter(|| {
            let client = Client::builder()
                .impersonate_random()
                .build()
                .unwrap();
            black_box(client);
        })
    });

    group.finish();
}

// ============================================================================
// BENCHMARK GROUPS
// ============================================================================

fn bench_client_creation(c: &mut Criterion) {
    bench_client_creation_async(c);
}

criterion_group!(benches, bench_client_creation);
criterion_main!(benches);
