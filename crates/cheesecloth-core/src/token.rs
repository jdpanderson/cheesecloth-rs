//! Invite tokens: what `cheesecloth invite` prints and `cheesecloth join` reads.

use std::{fmt, net::SocketAddr, str::FromStr};

use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};

use crate::{ClusterId, Error, NodeId};

const PREFIX: &str = "cc1";
/// At most this many members are listed in a token.
pub const TOKEN_PEERS: usize = 4;

/// A member the joiner can dial. The node ID is pinned when dialling, so the
/// joiner knows it reached the real cluster.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenPeer {
    pub node_id: NodeId,
    pub addrs: Vec<SocketAddr>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteToken {
    pub cluster_id: ClusterId,
    pub secret: [u8; 32],
    pub peers: Vec<TokenPeer>,
}

impl fmt::Display for InviteToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = postcard::to_stdvec(self).expect("serializable");
        write!(f, "{PREFIX}{}", BASE64URL_NOPAD.encode(&bytes))
    }
}

impl FromStr for InviteToken {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bad = || Error::Parse("not a cheesecloth invite token".into());
        let rest = s.trim().strip_prefix(PREFIX).ok_or_else(bad)?;
        let bytes = BASE64URL_NOPAD.decode(rest.as_bytes()).map_err(|_| bad())?;
        postcard::from_bytes(&bytes).map_err(|_| bad())
    }
}

#[cfg(test)]
mod tests;
