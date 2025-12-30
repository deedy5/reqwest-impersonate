#[cfg(feature = "__boring")]
use boring::ssl::{ConnectConfiguration, SslConnectorBuilder};
#[cfg(feature = "__boring")]
use foreign_types::ForeignTypeRef;
#[cfg(feature = "__tls")]
use http::header::HeaderValue;
use http::uri::{Authority, Scheme};
use http::Uri;
use hyper::client::connect::{Connected, Connection};
use hyper::service::Service;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use pin_project_lite::pin_project;
use std::future::Future;
use std::io::{self, IoSlice};
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use crate::dns::DynResolver;
use crate::error::BoxError;
use crate::proxy::{Proxy, ProxyScheme};

pub(crate) type HttpConnector = hyper::client::HttpConnector<DynResolver>;

#[derive(Clone)]
pub(crate) struct Connector {
    inner: Inner,
    proxies: Arc<Vec<Proxy>>,
    verbose: verbose::Wrapper,
    timeout: Option<Duration>,
    #[cfg(feature = "__tls")]
    nodelay: bool,
    #[cfg(feature = "__tls")]
    tls_info: bool,
    #[cfg(feature = "__tls")]
    user_agent: Option<HeaderValue>,
}

#[derive(Clone)]
enum Inner {
    #[cfg(feature = "__boring")]
    BoringTls {
        http: HttpConnector,
        tls: Arc<dyn Fn() -> SslConnectorBuilder + Send + Sync>,
    },
    #[cfg(feature = "__tls")]
    #[allow(dead_code)]
    Http { http: HttpConnector },
}

#[cfg(feature = "__boring")]
fn tls_add_application_settings(conf: &mut ConnectConfiguration) {
    const ALPN_H2: &str = "h2";
    const ALPN_H2_LENGTH: usize = 2;
    unsafe {
        boring_sys::SSL_add_application_settings(
            conf.as_ptr(),
            ALPN_H2.as_ptr(),
            ALPN_H2_LENGTH,
            std::ptr::null(),
            0,
        )
    };
}

impl Connector {
    #[cfg(feature = "__boring")]
    pub(crate) fn new_boring_tls<T>(
        mut http: HttpConnector,
        tls: Arc<dyn Fn() -> SslConnectorBuilder + Send + Sync>,
        proxies: Arc<Vec<Proxy>>,
        user_agent: Option<HeaderValue>,
        local_addr: T,
        nodelay: bool,
        tls_info: bool,
    ) -> Connector
    where
        T: Into<Option<IpAddr>>,
    {
        http.set_local_address(local_addr.into());
        http.enforce_http(false);

        Connector {
            inner: Inner::BoringTls { http, tls },
            proxies,
            verbose: verbose::OFF,
            timeout: None,
            nodelay,
            tls_info,
            user_agent,
        }
    }

    #[cfg(feature = "__tls")]
    #[allow(dead_code)]
    pub(crate) fn new<T>(
        mut http: HttpConnector,
        proxies: Arc<Vec<Proxy>>,
        local_addr: T,
        nodelay: bool,
    ) -> Connector
    where
        T: Into<Option<IpAddr>>,
    {
        http.set_local_address(local_addr.into());
        http.enforce_http(false);

        Connector {
            inner: Inner::Http { http },
            proxies,
            verbose: verbose::OFF,
            timeout: None,
            nodelay,
            tls_info: false,
            user_agent: None,
        }
    }

    #[cfg(not(feature = "__tls"))]
    pub(crate) fn new<T>(
        mut http: HttpConnector,
        proxies: Arc<Vec<Proxy>>,
        local_addr: T,
        nodelay: bool,
    ) -> Connector
    where
        T: Into<Option<IpAddr>>,
    {
        http.set_local_address(local_addr.into());
        http.enforce_http(false);

        Connector {
            inner: Inner::Http { http },
            proxies,
            verbose: verbose::OFF,
            timeout: None,
            nodelay,
            tls_info: false,
            user_agent: None,
        }
    }

    pub(crate) fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.timeout = timeout;
    }

    pub(crate) fn set_verbose(&mut self, enabled: bool) {
        self.verbose.0 = enabled;
    }

    #[cfg(feature = "socks")]
    async fn connect_socks(&self, dst: Uri, proxy: ProxyScheme) -> Result<Conn, BoxError> {
        let dns = match proxy {
            ProxyScheme::Socks5 {
                remote_dns: false, ..
            } => socks::DnsResolve::Local,
            ProxyScheme::Socks5 {
                remote_dns: true, ..
            } => socks::DnsResolve::Proxy,
            ProxyScheme::Http { .. } | ProxyScheme::Https { .. } => {
                unreachable!("connect_socks is only called for socks proxies");
            }
        };

        match &self.inner {
            #[cfg(feature = "__boring")]
            Inner::BoringTls { tls, .. } => {
                if dst.scheme() == Some(&Scheme::HTTPS) {
                    let host = dst.host().ok_or("no host in url")?.to_string();
                    let conn = socks::connect(proxy, dst, dns).await?;
                    let tls_connector = tls().build();

                    let mut conf = tls_connector.configure()?;

                    tls_add_application_settings(&mut conf);

                    let ssl_stream = tokio_boring::connect(conf, &host, conn).await?;
                    let wrapped = hyper_boring::MaybeHttpsStream::Https(ssl_stream);
                    return Ok(Conn {
                        inner: self.verbose.wrap(wrapped),
                        is_proxy: false,
                        tls_info: self.tls_info,
                    });
                }
            }
            #[cfg(feature = "__tls")]
            Inner::Http { .. } => (),
        }

        socks::connect(proxy, dst, dns).await.map(|tcp| Conn {
            inner: self.verbose.wrap(tcp),
            is_proxy: false,
            tls_info: false,
        })
    }

    async fn connect_with_maybe_proxy(self, dst: Uri, is_proxy: bool) -> Result<Conn, BoxError> {
        match self.inner {
            #[cfg(feature = "__boring")]
            Inner::BoringTls { http, tls } => {
                let mut http = http.clone();

                // Disable Nagle's algorithm for TLS handshake
                //
                // https://www.openssl.org/docs/man1.1.1/man3/SSL_connect.html#NOTES
                if !self.nodelay && (dst.scheme() == Some(&Scheme::HTTPS)) {
                    http.set_nodelay(true);
                }

                let mut http = hyper_boring::HttpsConnector::with_connector(http, tls())?;

                http.set_callback(|conf, _| {
                    tls_add_application_settings(conf);
                    Ok(())
                });

                let io = http.call(dst).await?;

                if let hyper_boring::MaybeHttpsStream::Https(stream) = io {
                    if !self.nodelay {
                        let stream_ref = stream.get_ref();
                        stream_ref.set_nodelay(false)?;
                    }
                    let wrapped = hyper_boring::MaybeHttpsStream::Https(stream);
                    Ok(Conn {
                        inner: self.verbose.wrap(wrapped),
                        is_proxy,
                        tls_info: self.tls_info,
                    })
                } else {
                    Ok(Conn {
                        inner: self.verbose.wrap(io),
                        is_proxy,
                        tls_info: false,
                    })
                }
            }
            #[cfg(feature = "__tls")]
            Inner::Http { mut http } => {
                let io = http.call(dst).await?;
                Ok(Conn {
                    inner: self.verbose.wrap(io),
                    is_proxy,
                    tls_info: false,
                })
            }
        }
    }

    async fn connect_via_proxy(
        self,
        dst: Uri,
        proxy_scheme: ProxyScheme,
    ) -> Result<Conn, BoxError> {
        log::debug!("proxy({proxy_scheme:?}) intercepts '{dst:?}'");

        let (proxy_dst, _auth) = match proxy_scheme {
            ProxyScheme::Http { host, auth } => (into_uri(Scheme::HTTP, host), auth),
            ProxyScheme::Https { host, auth } => (into_uri(Scheme::HTTPS, host), auth),
            #[cfg(feature = "socks")]
            ProxyScheme::Socks5 { .. } => return self.connect_socks(dst, proxy_scheme).await,
        };

        #[cfg(feature = "__tls")]
        let auth = _auth;

        match &self.inner {
            #[cfg(feature = "__boring")]
            Inner::BoringTls { http, tls } => {
                if dst.scheme() == Some(&Scheme::HTTPS) {
                    let host = dst.host().ok_or("no host in url")?;
                    let port = dst.port_u16().unwrap_or(443);

                    // 1) Dial the proxy (HTTP or HTTPS).
                    let mut http =
                        hyper_boring::HttpsConnector::with_connector(http.clone(), tls())?;
                    http.set_callback(|conf, _| {
                        tls_add_application_settings(conf);
                        Ok(())
                    });
                    let proxy_conn = http.call(proxy_dst).await?;
                    log::trace!("tunneling HTTPS over proxy");

                    // 2) Tunnel CONNECT through that proxy_conn
                    let tunneled =
                        tunnel(proxy_conn, host.into(), port, self.user_agent.clone(), auth)
                            .await?;

                    // 3) Final TLS handshake to *target* host
                    let mut conf = tls().build().configure()?;
                    tls_add_application_settings(&mut conf);
                    let final_tls = tokio_boring::connect(conf, host, tunneled).await?;

                    // 5) Wrap in hyper_boring's MaybeHttpsStream
                    let wrapped = hyper_boring::MaybeHttpsStream::Https(final_tls);

                    return Ok(Conn {
                        inner: self.verbose.wrap(wrapped),
                        is_proxy: false,
                        tls_info: self.tls_info,
                    });
                }
            }
            #[cfg(feature = "__tls")]
            Inner::Http { .. } => {}
            #[cfg(not(any(feature = "__boring", feature = "__tls")))]
            _ => unreachable!(),
        }

        self.connect_with_maybe_proxy(proxy_dst, true).await
    }

    pub fn set_keepalive(&mut self, dur: Option<Duration>) {
        match &mut self.inner {
            #[cfg(feature = "__boring")]
            Inner::BoringTls { http, .. } => http.set_keepalive(dur),
            #[cfg(feature = "__tls")]
            Inner::Http { http, .. } => http.set_keepalive(dur),
        }
    }
}

fn into_uri(scheme: Scheme, host: Authority) -> Uri {
    // TODO: Should the `http` crate get `From<(Scheme, Authority)> for Uri`?
    http::Uri::builder()
        .scheme(scheme)
        .authority(host)
        .path_and_query(http::uri::PathAndQuery::from_static("/"))
        .build()
        .expect("scheme and authority is valid Uri")
}

async fn with_timeout<T, F>(f: F, timeout: Option<Duration>) -> Result<T, BoxError>
where
    F: Future<Output = Result<T, BoxError>>,
{
    if let Some(to) = timeout {
        match tokio::time::timeout(to, f).await {
            Err(_elapsed) => Err(Box::new(crate::error::TimedOut) as BoxError),
            Ok(Ok(try_res)) => Ok(try_res),
            Ok(Err(e)) => Err(e),
        }
    } else {
        f.await
    }
}

impl Service<Uri> for Connector {
    type Response = Conn;
    type Error = BoxError;
    type Future = Connecting;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        log::debug!("starting new connection: {dst:?}");
        let timeout = self.timeout;
        for prox in self.proxies.iter() {
            if let Some(proxy_scheme) = prox.intercept(&dst) {
                return Box::pin(with_timeout(
                    self.clone().connect_via_proxy(dst, proxy_scheme),
                    timeout,
                ));
            }
        }

        Box::pin(with_timeout(
            self.clone().connect_with_maybe_proxy(dst, false),
            timeout,
        ))
    }
}

#[cfg(feature = "__tls")]
trait TlsInfoFactory {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo>;
}

#[cfg(feature = "__boring")]
impl<I> TlsInfoFactory for hyper_boring::MaybeHttpsStream<I>
where
    I: TlsInfoFactory,
{
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        match self {
            hyper_boring::MaybeHttpsStream::Https(tls) => {
                let peer_certificate = tls.ssl().peer_certificate().and_then(|c| c.to_der().ok());
                Some(crate::tls::TlsInfo { peer_certificate })
            }
            hyper_boring::MaybeHttpsStream::Http(_) => None,
        }
    }
}

#[cfg(feature = "__tls")]
impl TlsInfoFactory for tokio::net::TcpStream {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        None
    }
}

pub(crate) trait AsyncConn:
    AsyncRead + AsyncWrite + Connection + Send + Sync + Unpin + 'static
{
}

impl<T: AsyncRead + AsyncWrite + Connection + Send + Sync + Unpin + 'static> AsyncConn for T {}

#[cfg(feature = "__tls")]
trait AsyncConnWithInfo: AsyncConn + TlsInfoFactory {}
#[cfg(not(feature = "__tls"))]
trait AsyncConnWithInfo: AsyncConn {}

#[cfg(feature = "__tls")]
impl<T: AsyncConn + TlsInfoFactory> AsyncConnWithInfo for T {}
#[cfg(not(feature = "__tls"))]
impl<T: AsyncConn> AsyncConnWithInfo for T {}

type BoxConn = Box<dyn AsyncConnWithInfo>;

pin_project! {
    /// Note: the `is_proxy` member means *is plain text HTTP proxy*.
    /// This tells hyper whether the URI should be written in
    /// * origin-form (`GET /just/a/path HTTP/1.1`), when `is_proxy == false`, or
    /// * absolute-form (`GET http://foo.bar/and/a/path HTTP/1.1`), otherwise.
    pub(crate) struct Conn {
        #[pin]
        inner: BoxConn,
        is_proxy: bool,
        // Only needed for __tls, but #[cfg()] on fields breaks pin_project!
        tls_info: bool,
    }
}

impl Connection for Conn {
    fn connected(&self) -> Connected {
        let connected = self.inner.connected().proxy(self.is_proxy);
        #[cfg(feature = "__tls")]
        if self.tls_info {
            if let Some(tls_info) = self.inner.tls_info() {
                connected.extra(tls_info)
            } else {
                connected
            }
        } else {
            connected
        }
        #[cfg(not(feature = "__tls"))]
        connected
    }
}

impl AsyncRead for Conn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.project();
        AsyncRead::poll_read(this.inner, cx, buf)
    }
}

impl AsyncWrite for Conn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.project();
        AsyncWrite::poll_write(this.inner, cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.project();
        AsyncWrite::poll_write_vectored(this.inner, cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        let this = self.project();
        AsyncWrite::poll_flush(this.inner, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        let this = self.project();
        AsyncWrite::poll_shutdown(this.inner, cx)
    }
}

pub(crate) type Connecting = Pin<Box<dyn Future<Output = Result<Conn, BoxError>> + Send>>;

#[cfg(feature = "__tls")]
async fn tunnel<T>(
    mut conn: T,
    host: String,
    port: u16,
    user_agent: Option<HeaderValue>,
    auth: Option<HeaderValue>,
) -> Result<T, BoxError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = format!(
        "\
         CONNECT {host}:{port} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         "
    )
    .into_bytes();

    // user-agent
    if let Some(user_agent) = user_agent {
        buf.extend_from_slice(b"User-Agent: ");
        buf.extend_from_slice(user_agent.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }

    // proxy-authorization
    if let Some(value) = auth {
        log::debug!("tunnel to {host}:{port} using basic auth");
        buf.extend_from_slice(b"Proxy-Authorization: ");
        buf.extend_from_slice(value.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }

    // headers end
    buf.extend_from_slice(b"\r\n");

    conn.write_all(&buf).await?;

    let mut buf = [0; 8192];
    let mut pos = 0;

    loop {
        let n = conn.read(&mut buf[pos..]).await?;

        if n == 0 {
            return Err(tunnel_eof());
        }
        pos += n;

        let recvd = &buf[..pos];
        if recvd.starts_with(b"HTTP/1.1 200") || recvd.starts_with(b"HTTP/1.0 200") {
            if recvd.ends_with(b"\r\n\r\n") {
                return Ok(conn);
            }
            if pos == buf.len() {
                return Err("proxy headers too long for tunnel".into());
            }
        // else read more
        } else if recvd.starts_with(b"HTTP/1.1 407") {
            return Err("proxy authentication required".into());
        } else {
            return Err("unsuccessful tunnel".into());
        }
    }
}

#[cfg(feature = "__tls")]
fn tunnel_eof() -> BoxError {
    "unexpected eof while tunneling".into()
}

#[cfg(feature = "socks")]
mod socks {
    use std::io;
    use std::net::ToSocketAddrs;

    use http::Uri;
    use tokio::net::TcpStream;
    use tokio_socks::tcp::Socks5Stream;

    use super::{BoxError, Scheme};
    use crate::proxy::ProxyScheme;

    pub(super) enum DnsResolve {
        Local,
        Proxy,
    }

    pub(super) async fn connect(
        proxy: ProxyScheme,
        dst: Uri,
        dns: DnsResolve,
    ) -> Result<TcpStream, BoxError> {
        let https = dst.scheme() == Some(&Scheme::HTTPS);
        let original_host = dst
            .host()
            .ok_or(io::Error::new(io::ErrorKind::Other, "no host in url"))?;
        let mut host = original_host.to_owned();
        let port = match dst.port() {
            Some(p) => p.as_u16(),
            None if https => 443u16,
            _ => 80u16,
        };

        if let DnsResolve::Local = dns {
            let maybe_new_target = (host.as_str(), port).to_socket_addrs()?.next();
            if let Some(new_target) = maybe_new_target {
                host = new_target.ip().to_string();
            }
        }

        let (socket_addr, auth) = match proxy {
            ProxyScheme::Socks5 { addr, auth, .. } => (addr, auth),
            _ => unreachable!(),
        };

        // Get a Tokio TcpStream
        let stream = if let Some((username, password)) = auth {
            Socks5Stream::connect_with_password(
                socket_addr,
                (host.as_str(), port),
                &username,
                &password,
            )
            .await
            .map_err(|e| format!("socks connect error: {e}"))?
        } else {
            Socks5Stream::connect(socket_addr, (host.as_str(), port))
                .await
                .map_err(|e| format!("socks connect error: {e}"))?
        };

        Ok(stream.into_inner())
    }
}

mod verbose {
    use hyper::client::connect::{Connected, Connection};
    use std::cmp::min;
    use std::fmt;
    use std::io::{self, IoSlice};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    pub(super) const OFF: Wrapper = Wrapper(false);

    #[derive(Clone, Copy)]
    pub(super) struct Wrapper(pub(super) bool);

    impl Wrapper {
        pub(super) fn wrap<T: super::AsyncConnWithInfo>(&self, conn: T) -> super::BoxConn {
            if self.0 && log::log_enabled!(log::Level::Trace) {
                Box::new(Verbose {
                    // truncate is fine
                    id: crate::util::fast_random() as u32,
                    inner: conn,
                })
            } else {
                Box::new(conn)
            }
        }
    }

    struct Verbose<T> {
        id: u32,
        inner: T,
    }

    impl<T: Connection + AsyncRead + AsyncWrite + Unpin> Connection for Verbose<T> {
        fn connected(&self) -> Connected {
            self.inner.connected()
        }
    }

    impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for Verbose<T> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            match Pin::new(&mut self.inner).poll_read(cx, buf) {
                Poll::Ready(Ok(())) => {
                    log::trace!("{:08x} read: {:?}", self.id, Escape(buf.filled()));
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Verbose<T> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            match Pin::new(&mut self.inner).poll_write(cx, buf) {
                Poll::Ready(Ok(n)) => {
                    log::trace!("{:08x} write: {:?}", self.id, Escape(&buf[..n]));
                    Poll::Ready(Ok(n))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<Result<usize, io::Error>> {
            match Pin::new(&mut self.inner).poll_write_vectored(cx, bufs) {
                Poll::Ready(Ok(nwritten)) => {
                    log::trace!(
                        "{:08x} write (vectored): {:?}",
                        self.id,
                        Vectored { bufs, nwritten }
                    );
                    Poll::Ready(Ok(nwritten))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }

        fn is_write_vectored(&self) -> bool {
            self.inner.is_write_vectored()
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
        ) -> Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
        ) -> Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[cfg(feature = "__tls")]
    impl<T: super::TlsInfoFactory> super::TlsInfoFactory for Verbose<T> {
        fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
            self.inner.tls_info()
        }
    }

    struct Escape<'a>(&'a [u8]);

    impl fmt::Debug for Escape<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "\"")?;
            for &c in self.0 {
                // https://doc.rust-lang.org/reference.html#byte-escapes
                if c == b'\n' {
                    write!(f, "\\n")?;
                } else if c == b'\r' {
                    write!(f, "\\r")?;
                } else if c == b'\t' {
                    write!(f, "\\t")?;
                } else if c == b'\\' || c == b'"' {
                    write!(f, "\\{}", c as char)?;
                } else if c == b'\0' {
                    write!(f, "\\0")?;
                // ASCII printable
                } else if c >= 0x20 && c < 0x7f {
                    write!(f, "{}", c as char)?;
                } else {
                    write!(f, "\\x{c:02x}")?;
                }
            }
            write!(f, "\"")?;
            Ok(())
        }
    }

    struct Vectored<'a, 'b> {
        bufs: &'a [IoSlice<'b>],
        nwritten: usize,
    }

    impl fmt::Debug for Vectored<'_, '_> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            let mut left = self.nwritten;
            for buf in self.bufs.iter() {
                if left == 0 {
                    break;
                }
                let n = min(left, buf.len());
                Escape(&buf[..n]).fmt(f)?;
                left -= n;
            }
            Ok(())
        }
    }
}

#[cfg(feature = "__tls")]
#[cfg(test)]
mod tests {
    use super::tunnel;
    use crate::proxy;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use tokio::net::TcpStream;
    use tokio::runtime;

    static TUNNEL_UA: &str = "tunnel-test/x.y";
    static TUNNEL_OK: &[u8] = b"\
        HTTP/1.1 200 OK\r\n\
        \r\n\
    ";

    macro_rules! mock_tunnel {
        () => {{
            mock_tunnel!(TUNNEL_OK)
        }};
        ($write:expr) => {{
            mock_tunnel!($write, "")
        }};
        ($write:expr, $auth:expr) => {{
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let connect_expected = format!(
                "\
                 CONNECT {0}:{1} HTTP/1.1\r\n\
                 Host: {0}:{1}\r\n\
                 User-Agent: {2}\r\n\
                 {3}\
                 \r\n\
                 ",
                addr.ip(),
                addr.port(),
                TUNNEL_UA,
                $auth
            )
            .into_bytes();

            thread::spawn(move || {
                let (mut sock, _) = listener.accept().unwrap();
                let mut buf = [0u8; 4096];
                let n = sock.read(&mut buf).unwrap();
                assert_eq!(&buf[..n], &connect_expected[..]);

                sock.write_all($write).unwrap();
            });
            addr
        }};
    }

    fn ua() -> Option<http::header::HeaderValue> {
        Some(http::header::HeaderValue::from_static(TUNNEL_UA))
    }

    #[test]
    fn test_tunnel() {
        let addr = mock_tunnel!();

        let rt = runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("new rt");
        let f = async move {
            let tcp = TcpStream::connect(&addr).await?;
            let host = addr.ip().to_string();
            let port = addr.port();
            tunnel(tcp, host, port, ua(), None).await
        };

        rt.block_on(f).unwrap();
    }

    #[test]
    fn test_tunnel_eof() {
        let addr = mock_tunnel!(b"HTTP/1.1 200 OK");

        let rt = runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("new rt");
        let f = async move {
            let tcp = TcpStream::connect(&addr).await?;
            let host = addr.ip().to_string();
            let port = addr.port();
            tunnel(tcp, host, port, ua(), None).await
        };

        rt.block_on(f).unwrap_err();
    }

    #[test]
    fn test_tunnel_non_http_response() {
        let addr = mock_tunnel!(b"foo bar baz hallo");

        let rt = runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("new rt");
        let f = async move {
            let tcp = TcpStream::connect(&addr).await?;
            let host = addr.ip().to_string();
            let port = addr.port();
            tunnel(tcp, host, port, ua(), None).await
        };

        rt.block_on(f).unwrap_err();
    }

    #[test]
    fn test_tunnel_proxy_unauthorized() {
        let addr = mock_tunnel!(
            b"\
            HTTP/1.1 407 Proxy Authentication Required\r\n\
            Proxy-Authenticate: Basic realm=\"nope\"\r\n\
            \r\n\
        "
        );

        let rt = runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("new rt");
        let f = async move {
            let tcp = TcpStream::connect(&addr).await?;
            let host = addr.ip().to_string();
            let port = addr.port();
            tunnel(tcp, host, port, ua(), None).await
        };

        let error = rt.block_on(f).unwrap_err();
        assert_eq!(error.to_string(), "proxy authentication required");
    }

    #[test]
    fn test_tunnel_basic_auth() {
        let addr = mock_tunnel!(
            TUNNEL_OK,
            "Proxy-Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n"
        );

        let rt = runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("new rt");
        let f = async move {
            let tcp = TcpStream::connect(&addr).await?;
            let host = addr.ip().to_string();
            let port = addr.port();
            tunnel(
                tcp,
                host,
                port,
                ua(),
                Some(proxy::encode_basic_auth("Aladdin", "open sesame")),
            )
            .await
        };

        rt.block_on(f).unwrap();
    }
}
