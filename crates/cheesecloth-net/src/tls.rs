//! TLS 1.3 with RFC 7250 raw Ed25519 public keys.
//!
//! - The dialler pins the exact key of the node it's calling.
//! - The acceptor accepts any client that proves it holds an ed25519 key; the
//!   application then decides what that key may do.

use std::sync::Arc;

use anyhow::{Context, Result};
use cheesecloth_core::{ALPN, Identity, NodeId};
use quinn::{
    ClientConfig, Connection, ServerConfig, TransportConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rustls::{
    DigitallySignedStruct, DistinguishedName, SignatureScheme,
    client::{
        AlwaysResolvesClientRawPublicKeys,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::CryptoProvider,
    pki_types::{
        CertificateDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime,
    },
    server::{
        AlwaysResolvesServerRawPublicKeys,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
    sign::CertifiedKey,
};

/// DER prefix of an ed25519 SubjectPublicKeyInfo; the 32-byte key follows.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
/// DER prefix of an ed25519 PKCS#8 v1 private key; the 32-byte seed follows.
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// The server name used when dialling. Ignored by the verifier: peers are
/// identified by key only.
pub const SERVER_NAME: &str = "cheesecloth";
/// The server name used for reachability dial-backs, so the acceptor can tell
/// them apart from real connections.
pub const PROBE_SERVER_NAME: &str = "probe.cheesecloth";

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn presented_key(der: &[u8]) -> Result<NodeId, rustls::Error> {
    let bad = |why: &str| rustls::Error::General(format!("peer identity: {why}"));
    let key = der
        .strip_prefix(&ED25519_SPKI_PREFIX)
        .ok_or(bad("not ed25519"))?;
    Ok(NodeId(key.try_into().map_err(|_| bad("bad key length"))?))
}

fn verify_tls13(
    provider: &CryptoProvider,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, rustls::Error> {
    rustls::crypto::verify_tls13_signature_with_raw_key(
        message,
        &SubjectPublicKeyInfoDer::from(cert.as_ref()),
        dss,
        &provider.signature_verification_algorithms,
    )
}

fn no_tls12() -> Result<HandshakeSignatureValid, rustls::Error> {
    Err(rustls::Error::General("TLS 1.2 is not allowed".into()))
}

fn certified_key(id: &Identity) -> Result<Arc<CertifiedKey>> {
    let pkcs8 = PrivatePkcs8KeyDer::from([&ED25519_PKCS8_PREFIX[..], &id.secret()].concat());
    let signer = rustls::crypto::ring::sign::any_eddsa_type(&pkcs8)?;
    let spki = [&ED25519_SPKI_PREFIX[..], id.node_id().as_bytes()].concat();
    Ok(Arc::new(CertifiedKey::new(
        vec![CertificateDer::from(spki)],
        signer,
    )))
}

#[derive(Debug)]
struct PinnedServer {
    expected: NodeId,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedServer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if presented_key(end_entity)? != self.expected {
            return Err(rustls::Error::General(
                "server presented an unexpected key".into(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        no_tls12()
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13(&self.provider, message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct AnyEd25519Client {
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for AnyEd25519Client {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        presented_key(end_entity)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        no_tls12()
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13(&self.provider, message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

pub fn server_config(me: &Identity, transport: Arc<TransportConfig>) -> Result<ServerConfig> {
    let verifier = Arc::new(AnyEd25519Client {
        provider: provider(),
    });
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(
            certified_key(me)?,
        )));
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut config = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    config.transport_config(transport);
    Ok(config)
}

pub fn client_config(
    me: &Identity,
    expected: NodeId,
    transport: Arc<TransportConfig>,
) -> Result<ClientConfig> {
    let verifier = Arc::new(PinnedServer {
        expected,
        provider: provider(),
    });
    let mut tls = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(
            certified_key(me)?,
        )));
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    config.transport_config(transport);
    Ok(config)
}

/// The authenticated key of the remote side of a connection.
pub fn peer_id(conn: &Connection) -> Result<NodeId> {
    let identity = conn.peer_identity().context("no peer identity")?;
    let certs = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| anyhow::anyhow!("unexpected identity type"))?;
    Ok(presented_key(certs.first().context("empty identity")?)?)
}

/// The server name the client asked for, on an accepted connection.
pub fn requested_server_name(conn: &Connection) -> Option<String> {
    conn.handshake_data()?
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .ok()?
        .server_name
}

#[cfg(test)]
mod tests;
