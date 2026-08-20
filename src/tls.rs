//! Optional TLS transport for `OpenFlow` connections.
//!
//! Enable the `tls` Cargo feature to use the [`rustls`] implementation.  The
//! transport deliberately requires an application-supplied [`ClientConfig`]
//! or [`ServerConfig`]; it never disables certificate verification and never
//! silently falls back to plaintext.  This keeps trust policy outside the
//! wire-protocol layer while allowing the same [`client::Connection`] API to
//! operate over encrypted streams.

use std::io::{Error as IoError, ErrorKind};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::client::{Connection, Error, Result};

/// Maximum time allowed for TCP/TLS setup by the convenience TLS helpers.
pub const DEFAULT_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// A [`Connection`] backed by a rustls client stream.
#[allow(clippy::module_name_repetitions)]
pub type TlsConnection<S> = Connection<ClientTlsStream<S>>;

/// Build a verified rustls client configuration from DER-encoded trust roots.
///
/// The returned configuration does not use the operating system trust store;
/// callers that want system roots can load them with a platform-specific
/// loader and pass the resulting certificates here.  Supplying explicit roots
/// makes the trust boundary visible and deterministic for `OpenFlow` deployments.
///
/// # Errors
///
/// Returns the rustls certificate error if a supplied certificate cannot be
/// added to the root store.
pub fn client_config(
    certificates: impl IntoIterator<Item = CertificateDer<'static>>,
) -> std::result::Result<Arc<ClientConfig>, rustls::Error> {
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots.add(certificate)?;
    }
    let builder =
        ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()?;
    Ok(Arc::new(
        builder.with_root_certificates(roots).with_no_client_auth(),
    ))
}

/// Connect an existing asynchronous stream with TLS without running the
/// `OpenFlow` handshake.
///
/// This is the transport half used by controller connection managers. Callers
/// that need a ready [`Connection`] should use [`connect_stream`] instead.
///
/// # Errors
///
/// Returns [`Error::Io`] for invalid names or transport failures, or
/// [`Error::TlsHandshakeTimeout`] when the TLS handshake exceeds the default
/// deadline.
pub async fn connect_transport<S>(
    stream: S,
    server_name: &str,
    config: Arc<ClientConfig>,
) -> Result<ClientTlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let server_name = ServerName::try_from(server_name.to_owned()).map_err(|error| {
        Error::Io(IoError::new(
            ErrorKind::InvalidInput,
            format!("invalid TLS server name: {error}"),
        ))
    })?;
    tokio::time::timeout(
        DEFAULT_TLS_HANDSHAKE_TIMEOUT,
        TlsConnector::from(config).connect(server_name, stream),
    )
    .await
    .map_err(|_| Error::TlsHandshakeTimeout)?
    .map_err(Into::into)
}

/// Connect an existing asynchronous stream with TLS and complete the
/// `OpenFlow` hello/features handshake.
///
/// `server_name` is used both for TLS certificate verification and SNI.  The
/// returned connection is ready for `OpenFlow` requests when this function
/// succeeds.
///
/// # Errors
///
/// Returns [`Error::Io`] for invalid names or transport failures,
/// [`Error::TlsHandshakeTimeout`] when TLS setup exceeds the default deadline,
/// and the regular client errors when the `OpenFlow` handshake fails.
pub async fn connect_stream<S>(
    stream: S,
    server_name: &str,
    config: Arc<ClientConfig>,
) -> Result<TlsConnection<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let stream = connect_transport(stream, server_name, config).await?;
    let mut connection = Connection::new(stream);
    connection
        .handshake_with_timeout(std::time::Duration::from_secs(10))
        .await?;
    Ok(connection)
}

/// Connect to an `OpenFlow` switch over TCP with TLS and complete the hello /
/// features handshake.
///
/// # Errors
///
/// Returns [`Error::Io`] for address, TCP, or TLS failures, and the regular
/// client errors when the `OpenFlow` handshake fails.
pub async fn connect_tcp(
    address: impl ToSocketAddrs,
    server_name: &str,
    config: Arc<ClientConfig>,
) -> Result<TlsConnection<TcpStream>> {
    let stream = tokio::time::timeout(DEFAULT_TLS_HANDSHAKE_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| {
            Error::Io(IoError::new(
                ErrorKind::TimedOut,
                "timed out connecting to the TLS endpoint",
            ))
        })??;
    connect_stream(stream, server_name, config).await
}

/// Accept an existing asynchronous stream with TLS as an `OpenFlow` server.
///
/// The returned stream is transport-ready; a controller or switch runtime is
/// responsible for running its normal `OpenFlow` handshake on it.  Keeping the
/// accept operation generic permits in-memory tests as well as TCP listeners.
///
/// # Errors
///
/// Returns [`Error::Io`] when the transport fails or
/// [`Error::TlsHandshakeTimeout`] when TLS setup exceeds the default deadline.
pub async fn accept_stream<S>(
    stream: S,
    config: Arc<ServerConfig>,
) -> Result<tokio_rustls::server::TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::time::timeout(
        DEFAULT_TLS_HANDSHAKE_TIMEOUT,
        TlsAcceptor::from(config).accept(stream),
    )
    .await
    .map_err(|_| Error::TlsHandshakeTimeout)?
    .map_err(Into::into)
}

#[cfg(all(test, not(clippy)))]
mod tests {
    use super::*;

    use rcgen::generate_simple_self_signed;
    use rcgen::{date_time_ymd, CertificateParams, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::protocol::codec::Encoder;
    use crate::protocol::constants::{OFPT_FEATURES_REQUEST, OFPT_HELLO, OFP_VERSION_1_5};
    use crate::protocol::features::Reply;
    use crate::protocol::header::Header as WireHeader;

    async fn read_frame<S>(stream: &mut S) -> Vec<u8>
    where
        S: AsyncRead + Unpin,
    {
        let mut header = [0_u8; 8];
        stream.read_exact(&mut header).await.unwrap();
        let parsed = WireHeader::parse(&header).unwrap();
        let mut frame = header.to_vec();
        let mut body = vec![0_u8; usize::from(parsed.length) - 8];
        stream.read_exact(&mut body).await.unwrap();
        frame.extend_from_slice(&body);
        frame
    }

    fn hello(xid: u32) -> Vec<u8> {
        let mut frame = Vec::new();
        WireHeader {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_HELLO,
            length: 8,
            xid,
        }
        .encode(&mut frame);
        frame
    }

    fn server_config() -> (Arc<ServerConfig>, CertificateDer<'static>) {
        let certificate = generate_simple_self_signed(vec![String::from("switch.test")]).unwrap();
        let certificate_der = certificate.cert.der().clone();
        let private_key = PrivateKeyDer::try_from(certificate.signing_key.serialize_der()).unwrap();
        let config =
            ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![certificate_der.clone()], private_key)
                .unwrap();
        (Arc::new(config), certificate_der)
    }

    fn certificate_material(name: &str) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let certificate = generate_simple_self_signed(vec![name.to_owned()]).unwrap();
        let certificate_der = certificate.cert.der().clone();
        let private_key = PrivateKeyDer::try_from(certificate.signing_key.serialize_der()).unwrap();
        (certificate_der, private_key)
    }

    fn authenticated_server_config(
        server_certificate: CertificateDer<'static>,
        server_key: PrivateKeyDer<'static>,
        client_root: CertificateDer<'static>,
    ) -> Arc<ServerConfig> {
        let mut roots = RootCertStore::empty();
        roots.add(client_root).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            rustls::crypto::ring::default_provider().into(),
        )
        .build()
        .unwrap();
        let config =
            ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_client_cert_verifier(verifier)
                .with_single_cert(vec![server_certificate], server_key)
                .unwrap();
        Arc::new(config)
    }

    fn authenticated_client_config(
        server_root: CertificateDer<'static>,
        client_certificate: Option<CertificateDer<'static>>,
        client_key: Option<PrivateKeyDer<'static>>,
    ) -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots.add(server_root).unwrap();
        let builder =
            ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots);
        let config = match (client_certificate, client_key) {
            (Some(certificate), Some(key)) => builder
                .with_client_auth_cert(vec![certificate], key)
                .unwrap(),
            (None, None) => builder.with_no_client_auth(),
            _ => unreachable!("client certificate and key must be provided together"),
        };
        Arc::new(config)
    }

    #[tokio::test]
    async fn tls_stream_completes_openflow_handshake_over_duplex() {
        let (server_io, client_io) = tokio::io::duplex(4096);
        let (server_config, certificate) = server_config();
        let client_config = client_config([certificate]).unwrap();

        let server = tokio::spawn(async move {
            let mut tls = accept_stream(server_io, server_config).await.unwrap();
            let client_hello = read_frame(&mut tls).await;
            let hello_header = WireHeader::parse(&client_hello).unwrap();
            assert_eq!(hello_header.msg_type, OFPT_HELLO);
            tls.write_all(&hello(hello_header.xid)).await.unwrap();

            let features = read_frame(&mut tls).await;
            let features_header = WireHeader::parse(&features).unwrap();
            assert_eq!(features_header.msg_type, OFPT_FEATURES_REQUEST);
            tls.write_all(&Encoder::features_reply(&Reply {
                xid: features_header.xid,
                datapath_id: 1,
                n_buffers: 256,
                n_tables: 4,
                auxiliary_id: 0,
                capabilities: 0,
                reserved: 0,
            }))
            .await
            .unwrap();
        });

        let connection = connect_stream(client_io, "switch.test", client_config)
            .await
            .unwrap();
        assert!(connection.features().is_some());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn invalid_server_name_is_rejected_before_io() {
        let (_server_io, client_io) = tokio::io::duplex(64);
        let (server_config, certificate) = server_config();
        let config = client_config([certificate]).unwrap();
        let error = connect_stream(client_io, "not a valid name", config)
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Io(error) if error.kind() == ErrorKind::InvalidInput));
        drop(server_config);
    }

    #[tokio::test]
    async fn tls_server_accepts_in_memory_stream() {
        let (server_io, client_io) = tokio::io::duplex(4096);
        let (server_config, certificate) = server_config();
        let client_config = client_config([certificate]).unwrap();
        let server =
            tokio::spawn(async move { accept_stream(server_io, server_config).await.unwrap() });
        let client = TlsConnector::from(client_config)
            .connect(
                ServerName::try_from(String::from("switch.test")).unwrap(),
                client_io,
            )
            .await
            .unwrap();
        let server_stream = server.await.unwrap();
        drop(client);
        drop(server_stream);
    }

    #[tokio::test]
    async fn tls_rejects_untrusted_ca_and_hostname_mismatch() {
        let (server_io, client_io) = tokio::io::duplex(4096);
        let (server_policy, _) = server_config();
        let (_, wrong_root) = server_config();
        let client_policy = client_config([wrong_root]).unwrap();
        let server = tokio::spawn(async move { accept_stream(server_io, server_policy).await });
        let result = TlsConnector::from(client_policy)
            .connect(
                ServerName::try_from(String::from("switch.test")).unwrap(),
                client_io,
            )
            .await;
        assert!(
            result.is_err(),
            "an untrusted CA must fail the TLS handshake"
        );
        assert!(server.await.unwrap().is_err());

        let (server_io, client_io) = tokio::io::duplex(4096);
        let (server_policy, certificate) = server_config();
        let client_policy = client_config([certificate]).unwrap();
        let server = tokio::spawn(async move { accept_stream(server_io, server_policy).await });
        let result = TlsConnector::from(client_policy)
            .connect(
                ServerName::try_from(String::from("wrong.test")).unwrap(),
                client_io,
            )
            .await;
        assert!(result.is_err(), "a certificate SAN mismatch must fail");
        assert!(server.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn tls_rejects_expired_server_certificate() {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![String::from("switch.test")]).unwrap();
        params.not_before = date_time_ymd(2000, 1, 1);
        params.not_after = date_time_ymd(2001, 1, 1);
        let certificate = params.self_signed(&key).unwrap();
        let certificate_der = certificate.der().clone();
        let server_key = PrivateKeyDer::try_from(key.serialize_der()).unwrap();
        let server_config = {
            let config = ServerConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der.clone()], server_key)
            .unwrap();
            Arc::new(config)
        };
        let client_config = client_config([certificate_der]).unwrap();
        let (server_io, client_io) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move { accept_stream(server_io, server_config).await });
        let result = TlsConnector::from(client_config)
            .connect(
                ServerName::try_from(String::from("switch.test")).unwrap(),
                client_io,
            )
            .await;
        assert!(
            result.is_err(),
            "an expired certificate must fail validation"
        );
        assert!(server.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn tls_mutual_auth_requires_and_accepts_a_client_certificate() {
        let (server_certificate, server_key) = certificate_material("switch.test");
        let (client_certificate, client_key) = certificate_material("controller.test");
        let server_config = authenticated_server_config(
            server_certificate.clone(),
            server_key,
            client_certificate.clone(),
        );
        let client_config = authenticated_client_config(
            server_certificate.clone(),
            Some(client_certificate),
            Some(client_key),
        );
        let (server_io, client_io) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move { accept_stream(server_io, server_config).await });
        let client = TlsConnector::from(client_config)
            .connect(
                ServerName::try_from(String::from("switch.test")).unwrap(),
                client_io,
            )
            .await
            .unwrap();
        let server_stream = server.await.unwrap().unwrap();
        drop(client);
        drop(server_stream);

        let (server_certificate, server_key) = certificate_material("switch.test");
        let (client_certificate, _) = certificate_material("controller.test");
        let server_config =
            authenticated_server_config(server_certificate.clone(), server_key, client_certificate);
        let client_config = authenticated_client_config(server_certificate, None, None);
        let (server_io, client_io) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move { accept_stream(server_io, server_config).await });
        let result = TlsConnector::from(client_config)
            .connect(
                ServerName::try_from(String::from("switch.test")).unwrap(),
                client_io,
            )
            .await;
        let server_result = server.await.unwrap();
        assert!(
            result.is_err() || server_result.is_err(),
            "missing client authentication must fail at one side of the handshake"
        );
    }
}
