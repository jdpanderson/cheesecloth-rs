//! Reachability probes: "dial me back at this address".

use std::net::{Ipv6Addr, SocketAddr};

use anyhow::{Context, Result, anyhow};
use cheesecloth_core::NodeId;
use quinn::{Endpoint, VarInt};

use crate::{
    Net,
    conn::DIAL_TIMEOUT,
    tls,
    wire::{Kind, ProbeRequest},
};

impl Net {
    /// Asks `via` to dial us back at `addr` from a fresh socket.
    pub async fn probe(&self, via: NodeId, addr: SocketAddr) -> Result<()> {
        let cluster = self.cluster_id().context("not in a cluster")?;
        let conn = self.connect(via).await?;
        let req = postcard::to_stdvec(&ProbeRequest { addr })?;
        self.call(&conn, Kind::Probe, cluster, &req).await?;
        Ok(())
    }

    /// Prober side: dial `addr` from a new ephemeral socket, so the dial looks
    /// unsolicited to any firewall in front of the requester.
    pub(crate) async fn dial_back(&self, requester: NodeId, addr: SocketAddr) -> Result<()> {
        let bind: SocketAddr = if addr.is_ipv6() {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        } else {
            ([0, 0, 0, 0], 0).into()
        };
        let endpoint = Endpoint::client(bind)?;
        let config = tls::client_config(&self.0.identity, requester, self.0.transport.clone())?;
        let res = tokio::time::timeout(
            DIAL_TIMEOUT,
            endpoint.connect_with(config, addr, tls::PROBE_SERVER_NAME)?,
        )
        .await;
        let outcome = match res {
            Ok(Ok(conn)) => {
                conn.close(VarInt::from_u32(0), b"probe ok");
                Ok(())
            }
            Ok(Err(e)) => Err(anyhow!("dial-back to {addr} failed: {e}")),
            Err(_) => Err(anyhow!("dial-back to {addr} timed out")),
        };
        endpoint.wait_idle().await;
        outcome
    }
}
