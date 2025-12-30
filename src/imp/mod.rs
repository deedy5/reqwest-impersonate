//! Holds structs and information to aid in impersonating a set of browsers

use std::sync::Arc;

use boring::ssl::SslConnectorBuilder;
use http::HeaderMap;
use crate::util::fast_random;

#[cfg(feature = "__impersonate")]
pub use chrome::configure_impersonate;

#[cfg(feature = "__impersonate")]
mod chrome;

mod cert_compressor;

struct BrowserSettings {
    pub tls_builder_func: Arc<dyn Fn() -> SslConnectorBuilder + Send + Sync>,
    pub http2: Http2Data,
    pub headers: HeaderMap,
    pub gzip: bool,
    pub brotli: bool,
    pub zstd: bool,
}

struct Http2Data {
    pub initial_stream_window_size: Option<u32>,
    pub initial_connection_window_size: Option<u32>,
    pub max_concurrent_streams: Option<u32>,
    pub max_header_list_size: Option<u32>,
    pub header_table_size: Option<u32>,
    pub enable_push: Option<bool>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
#[cfg(feature = "__impersonate")]
pub enum Impersonate {
    ChromeV100,
    ChromeV101,
    ChromeV102,
    ChromeV103,
    ChromeV104,
    ChromeV105,
    ChromeV106,
    ChromeV107,
    ChromeV108,
    ChromeV109,
    ChromeV110,
    ChromeV111,
    ChromeV112,
    ChromeV113,
    ChromeV114,
    ChromeV115,
    ChromeV116,
    ChromeV117,
    ChromeV118,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum ImpersonateOS {
    Windows,
    MacOS,
    Linux,
    Android,
    IOS,
}

impl Default for ImpersonateOS {
    fn default() -> Self {
        ImpersonateOS::Windows
    }
}

/// Get a random Impersonate value
pub fn random_impersonate() -> Impersonate {
    const IMPERSONATE_VARIANTS: &[Impersonate] = &[
        Impersonate::ChromeV100,
        Impersonate::ChromeV101,
        Impersonate::ChromeV102,
        Impersonate::ChromeV103,
        Impersonate::ChromeV104,
        Impersonate::ChromeV105,
        Impersonate::ChromeV106,
        Impersonate::ChromeV107,
        Impersonate::ChromeV108,
        Impersonate::ChromeV109,
        Impersonate::ChromeV110,
        Impersonate::ChromeV111,
        Impersonate::ChromeV112,
        Impersonate::ChromeV113,
        Impersonate::ChromeV114,
        Impersonate::ChromeV115,
        Impersonate::ChromeV116,
        Impersonate::ChromeV117,
        Impersonate::ChromeV118,
    ];
    
    let index = (fast_random() as usize) % IMPERSONATE_VARIANTS.len();
    IMPERSONATE_VARIANTS[index]
}

/// Get a random ImpersonateOS value
pub fn random_impersonate_os() -> ImpersonateOS {
    const OS_VARIANTS: &[ImpersonateOS] = &[
        ImpersonateOS::Windows,
        ImpersonateOS::MacOS,
        ImpersonateOS::Linux,
        ImpersonateOS::Android,
        ImpersonateOS::IOS,
    ];
    
    let index = (fast_random() as usize) % OS_VARIANTS.len();
    OS_VARIANTS[index]
}

/// Helper function to get random impersonate values if not already set
pub(crate) fn get_random_impersonate_config(
    chrome: Option<Impersonate>,
    os_type: Option<ImpersonateOS>,
) -> (Impersonate, ImpersonateOS) {
    let final_chrome = chrome.unwrap_or_else(random_impersonate);
    let final_os = os_type.unwrap_or_else(random_impersonate_os);
    
    (final_chrome, final_os)
}


