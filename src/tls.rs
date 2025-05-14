//! TLS configuration
//!
//! By default, a `Client` will make use of system-native transport layer
//! security to connect to HTTPS destinations. This means schannel on Windows,
//! Security-Framework on macOS, and OpenSSL on Linux.
//!
//! - Additional X509 certificates can be configured on a `ClientBuilder` with the
//!   [`Certificate`](Certificate) type.
//! - Client certificates can be add to a `ClientBuilder` with the
//!   [`Identity`][Identity] type.
//! - Various parts of TLS can also be configured or even disabled on the
//!   `ClientBuilder`.
use std::fmt;
use std::sync::Arc;

/// A TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(InnerVersion);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
enum InnerVersion {
    Tls1_0,
    Tls1_1,
    Tls1_2,
    Tls1_3,
}

// These could perhaps be From/TryFrom implementations, but those would be
// part of the public API so let's be careful
impl Version {
    /// Version 1.0 of the TLS protocol.
    pub const TLS_1_0: Version = Version(InnerVersion::Tls1_0);
    /// Version 1.1 of the TLS protocol.
    pub const TLS_1_1: Version = Version(InnerVersion::Tls1_1);
    /// Version 1.2 of the TLS protocol.
    pub const TLS_1_2: Version = Version(InnerVersion::Tls1_2);
    /// Version 1.3 of the TLS protocol.
    pub const TLS_1_3: Version = Version(InnerVersion::Tls1_3);
}

pub(crate) enum TlsBackend {
    BoringTls(Arc<dyn Fn() -> boring::ssl::SslConnectorBuilder + Send + Sync>),
}

impl fmt::Debug for TlsBackend {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TlsBackend::BoringTls(_) => write!(f, "BoringTls"),
        }
    }
}

impl Default for TlsBackend {
    fn default() -> TlsBackend {
        {
            use boring::ssl::{SslConnector, SslConnectorBuilder, SslMethod};

            fn create_builder() -> SslConnectorBuilder {
                SslConnector::builder(SslMethod::tls()).unwrap()
            }
            TlsBackend::BoringTls(Arc::new(create_builder))
        }
    }
}
