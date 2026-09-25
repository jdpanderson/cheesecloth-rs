//! Node identity keys and domain-separated signatures.

use std::{fs, io, path::Path};

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::TryRng;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub use ed25519_dalek::Signature;

use crate::{Error, NodeId};

/// What a signature is for. The domain is prefixed to the signed bytes, so a
/// signature made for one purpose can never be replayed as another.
#[derive(Clone, Copy, Debug)]
pub enum Domain {
    Promise,
    Verification,
    /// A command submitted for agreement.
    Command,
    /// A joining node's own member record.
    MemberInfo,
    /// A control-plane message forwarded through a relay.
    Forwarded,
    /// A node's soft state.
    SoftState,
    /// An acceptor's statement that it accepted a value (see *Authenticated
    /// round* in CONSENSUS-SAFETY.md).
    Accept,
}

impl Domain {
    fn tag(self) -> &'static [u8] {
        match self {
            Domain::Promise => b"cheesecloth/2 promise\0",
            Domain::Verification => b"cheesecloth/2 verification\0",
            Domain::Command => b"cheesecloth/2 command\0",
            Domain::MemberInfo => b"cheesecloth/2 member-info\0",
            Domain::Forwarded => b"cheesecloth/2 forwarded\0",
            Domain::SoftState => b"cheesecloth/2 soft-state\0",
            Domain::Accept => b"cheesecloth/2 accept\0",
        }
    }

    fn message(self, bytes: &[u8]) -> Vec<u8> {
        [self.tag(), bytes].concat()
    }
}

/// A node's ed25519 identity key.
pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        rand::rngs::SysRng
            .try_fill_bytes(&mut secret)
            .expect("operating system randomness unavailable");
        Self::from_secret(secret)
    }

    pub fn from_secret(secret: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&secret),
        }
    }

    pub fn secret(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// Loads the key stored at `path`, or creates one there (mode 0600).
    pub fn load_or_create(path: &Path) -> io::Result<Self> {
        match fs::read(path) {
            Ok(bytes) => {
                let secret: [u8; 32] = bytes.try_into().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "identity key must be 32 bytes")
                })?;
                Ok(Self::from_secret(secret))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let id = Self::generate();
                crate::write_private(path, &id.secret())?;
                Ok(id)
            }
            Err(e) => Err(e),
        }
    }

    pub fn node_id(&self) -> NodeId {
        NodeId(self.signing.verifying_key().to_bytes())
    }

    pub fn sign(&self, domain: Domain, bytes: &[u8]) -> Signature {
        self.signing.sign(&domain.message(bytes))
    }

    /// Signs `value`, producing a self-describing envelope.
    pub fn seal<T: Serialize>(&self, domain: Domain, value: &T) -> Signed<T> {
        let body = postcard::to_stdvec(value).expect("serializable");
        Signed {
            signer: self.node_id(),
            sig: self.sign(domain, &body),
            body,
            _marker: std::marker::PhantomData,
        }
    }
}

/// Checks `sig` over `bytes` against the key `signer`.
pub fn verify(signer: &NodeId, domain: Domain, bytes: &[u8], sig: &Signature) -> Result<(), Error> {
    let key = VerifyingKey::from_bytes(&signer.0).map_err(|_| Error::BadSignature)?;
    key.verify(&domain.message(bytes), sig)
        .map_err(|_| Error::BadSignature)
}

/// A value serialized with postcard and signed by `signer`.
///
/// The bytes, not the value, are signed, so the signature stays checkable
/// whatever serde does with the type.
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Signed<T> {
    pub signer: NodeId,
    pub body: Vec<u8>,
    pub sig: Signature,
    #[serde(skip)]
    _marker: std::marker::PhantomData<fn() -> T>,
}

impl<T> Clone for Signed<T> {
    fn clone(&self) -> Self {
        Self {
            signer: self.signer,
            body: self.body.clone(),
            sig: self.sig,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<T> std::fmt::Debug for Signed<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signed")
            .field("signer", &self.signer)
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl<T> PartialEq for Signed<T> {
    fn eq(&self, other: &Self) -> bool {
        self.signer == other.signer && self.body == other.body && self.sig == other.sig
    }
}

impl<T> Eq for Signed<T> {}

impl<T: DeserializeOwned> Signed<T> {
    /// Checks the signature and decodes the value.
    pub fn open(&self, domain: Domain) -> Result<T, Error> {
        verify(&self.signer, domain, &self.body, &self.sig)?;
        postcard::from_bytes(&self.body).map_err(|e| Error::Parse(e.to_string()))
    }

    /// A stable hash of the signed envelope, used to detect replays.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(&self.signer.0);
        h.update(&self.body);
        h.update(&self.sig.to_bytes());
        *h.finalize().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_are_domain_separated() {
        let id = Identity::generate();
        let sealed = id.seal(Domain::Command, &42u32);
        assert_eq!(sealed.open(Domain::Command).unwrap(), 42);
        assert!(sealed.open(Domain::Forwarded).is_err());

        let mut forged = sealed.clone();
        forged.body = postcard::to_stdvec(&43u32).unwrap();
        assert!(forged.open(Domain::Command).is_err());
    }

    #[test]
    fn envelopes_compare_and_hash_by_content() {
        let id = Identity::generate();
        let a = id.seal(Domain::Command, &1u8);
        let b = a.clone();
        assert_eq!(a, b);
        assert_eq!(a.digest(), b.digest());
        let c = id.seal(Domain::Command, &2u8);
        assert_ne!(a, c);
        assert_ne!(a.digest(), c.digest());
        assert!(format!("{a:?}").contains("body_len: 1"));
        // A body that isn't the promised type fails to decode.
        let wrong = id.seal(Domain::Command, &());
        let wrong: Signed<u64> = Signed {
            signer: wrong.signer,
            body: wrong.body,
            sig: wrong.sig,
            _marker: std::marker::PhantomData,
        };
        assert!(matches!(wrong.open(Domain::Command), Err(Error::Parse(_))));
    }

    #[test]
    fn a_non_key_signer_fails_verification() {
        let id = Identity::generate();
        let sig = id.sign(Domain::Command, b"x");
        // Not a valid ed25519 point.
        let bogus = NodeId([0xff; 32]);
        assert!(verify(&bogus, Domain::Command, b"x", &sig).is_err());
        assert!(verify(&id.node_id(), Domain::Command, b"x", &sig).is_ok());
    }

    #[test]
    fn keys_are_created_once_and_reloaded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/identity.key");
        let a = Identity::load_or_create(&path).unwrap();
        let b = Identity::load_or_create(&path).unwrap();
        assert_eq!(a.node_id(), b.node_id());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        std::fs::write(&path, b"short").unwrap();
        let err = Identity::load_or_create(&path).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        // A directory in the way is some other I/O error, passed through.
        assert!(Identity::load_or_create(dir.path()).is_err());
    }
}
