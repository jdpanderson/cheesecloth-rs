//! Fixed-size identifiers: node IDs, cluster IDs and WireGuard public keys.

use std::{fmt, str::FromStr};

use data_encoding::{BASE64, HEXLOWER_PERMISSIVE};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

/// Serializes 32 bytes as lowercase hex in human-readable formats (JSON) and as
/// raw bytes otherwise (postcard).
fn ser_bytes32<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
    if s.is_human_readable() {
        s.serialize_str(&HEXLOWER_PERMISSIVE.encode(bytes))
    } else {
        bytes.serialize(s)
    }
}

fn de_bytes32<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
    if d.is_human_readable() {
        let s = String::deserialize(d)?;
        parse_hex32(&s).ok_or_else(|| D::Error::custom("expected 64 hex digits"))
    } else {
        <[u8; 32]>::deserialize(d)
    }
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    HEXLOWER_PERMISSIVE
        .decode(s.as_bytes())
        .ok()?
        .try_into()
        .ok()
}

macro_rules! bytes32_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub [u8; 32]);

        impl $name {
            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// The first 12 hex digits, for logs and tables.
            pub fn short(&self) -> String {
                HEXLOWER_PERMISSIVE.encode(&self.0[..6])
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&HEXLOWER_PERMISSIVE.encode(&self.0))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.short())
            }
        }

        impl FromStr for $name {
            type Err = crate::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                parse_hex32(s)
                    .map(Self)
                    .ok_or_else(|| crate::Error::Parse(format!("invalid {}", stringify!($name))))
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                ser_bytes32(&self.0, s)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                de_bytes32(d).map(Self)
            }
        }
    };
}

bytes32_id!(
    /// A node's identity: its ed25519 public key.
    NodeId
);

bytes32_id!(
    /// Hash of the genesis command. Checked on every control-plane stream.
    ClusterId
);

bytes32_id!(
    /// Immutable, content-bound approval proposal identifier.
    ProposalId
);

impl ProposalId {
    /// Sequence is only a catch-up hint; authorization compares all 32 bytes.
    pub fn sequence(self) -> u64 {
        u64::from_be_bytes(self.0[..8].try_into().expect("eight bytes"))
    }
}

/// A WireGuard (x25519) public key. Shown in base64, as WireGuard tools do.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct WgKey(#[serde(serialize_with = "ser_wg", deserialize_with = "de_wg")] pub [u8; 32]);

fn ser_wg<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
    if s.is_human_readable() {
        s.serialize_str(&BASE64.encode(bytes))
    } else {
        bytes.serialize(s)
    }
}

fn de_wg<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
    if d.is_human_readable() {
        let s = String::deserialize(d)?;
        BASE64
            .decode(s.as_bytes())
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| D::Error::custom("expected a base64 WireGuard key"))
    } else {
        <[u8; 32]>::deserialize(d)
    }
}

impl fmt::Display for WgKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&BASE64.encode(&self.0))
    }
}

impl fmt::Debug for WgKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WgKey({self})")
    }
}

#[cfg(test)]
mod tests;
