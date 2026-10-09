//! Kernel WireGuard, configured over netlink: rtnetlink for the link and its
//! addresses, and WireGuard's generic netlink family for keys and peers.

use std::time::SystemTime;

use anyhow::{Context, Result, bail};
use cheesecloth_core::WgKey;
use data_encoding::BASE64;
use futures_util::TryStreamExt;
use nl_wireguard::{
    WireguardHandle, WireguardIpAddress, WireguardParsed, WireguardParsedPeerFlags,
    WireguardPeerParsed,
};
use rtnetlink::{
    LinkUnspec, LinkWireguard,
    packet_route::link::{InfoKind, LinkAttribute, LinkInfo},
};

use crate::{Backend, InterfaceConfig, PeerConfig, PeerStatus, runtime::Runtime};

pub(super) struct Kernel {
    name: String,
    netlink: Netlink,
    runtime: Runtime,
    up: bool,
}

impl Kernel {
    pub fn open(config: &InterfaceConfig) -> Result<Self> {
        let runtime = Runtime::new()?;
        let netlink = Netlink::connect(&runtime)?;
        let (n, c) = (netlink.clone(), config.clone());
        runtime.run(async move { n.create(&c).await })??;
        Ok(Self {
            name: config.name.clone(),
            netlink,
            runtime,
            up: true,
        })
    }

    /// Runs `f` with the netlink handles on this backend's runtime.
    fn run<T, F>(&self, f: impl FnOnce(Netlink, String) -> F) -> Result<T>
    where
        F: Future<Output = Result<T>> + Send + 'static,
        T: Send + 'static,
    {
        self.runtime
            .run(f(self.netlink.clone(), self.name.clone()))?
    }
}

/// Deletes the WireGuard interface `name` that an earlier run left behind.
pub(super) fn remove(name: &str) -> Result<()> {
    let runtime = Runtime::new()?;
    let netlink = Netlink::connect(&runtime)?;
    let name = name.to_owned();
    runtime.run(async move { netlink.delete(&name).await })?
}

impl Backend for Kernel {
    fn set_peer(&mut self, peer: &PeerConfig) -> Result<()> {
        let mut p = WireguardPeerParsed::default();
        p.public_key = Some(peer.key.to_string());
        // The kernel keeps the endpoint it has when none is given.
        p.endpoint = peer.endpoint;
        p.persistent_keepalive = Some(peer.keepalive);
        p.allowed_ips = Some(
            peer.allowed_ips
                .iter()
                .map(|net| WireguardIpAddress {
                    prefix_length: net.prefix_len(),
                    ip_addr: net.addr(),
                    flags: None,
                })
                .collect(),
        );
        p.flags = Some(vec![WireguardParsedPeerFlags::ReplaceAllowedIps]);
        self.run(|netlink, name| async move {
            let mut device = WireguardParsed::default();
            device.iface_name = Some(name);
            device.peers = Some(vec![p]);
            netlink.wireguard.clone().set(device).await?;
            Ok(())
        })
    }

    fn remove_peer(&mut self, key: &WgKey) -> Result<()> {
        let key = key.to_string();
        self.run(|netlink, name| async move {
            netlink.wireguard.clone().remove_peer(&name, &key).await?;
            Ok(())
        })
    }

    fn status(&self) -> Result<Vec<PeerStatus>> {
        let device = self.run(|netlink, name| async move {
            Ok(netlink.wireguard.clone().get_by_name(&name).await?)
        })?;
        device
            .peers
            .unwrap_or_default()
            .into_iter()
            .map(|p| {
                Ok(PeerStatus {
                    key: decode_key(p.public_key.as_deref().context("a peer has no key")?)?,
                    endpoint: p.endpoint,
                    last_handshake: p.last_handshake.map(|t| SystemTime::UNIX_EPOCH + t),
                    rx_bytes: p.rx_bytes.unwrap_or(0),
                    tx_bytes: p.tx_bytes.unwrap_or(0),
                    keepalive: p.persistent_keepalive.unwrap_or(0),
                })
            })
            .collect()
    }

    fn down(&mut self) -> Result<()> {
        if self.up {
            self.run(|netlink, name| async move { netlink.delete(&name).await })?;
            self.up = false;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "kernel"
    }
}

fn decode_key(key: &str) -> Result<WgKey> {
    let bytes = BASE64
        .decode(key.as_bytes())
        .context("decoding a peer key")?;
    Ok(WgKey(
        bytes
            .try_into()
            .ok()
            .context("a peer key is not 32 bytes")?,
    ))
}

#[derive(Clone)]
struct Netlink {
    links: rtnetlink::Handle,
    wireguard: WireguardHandle,
}

impl Netlink {
    /// Opens the netlink sockets. Their connections run on `runtime`.
    fn connect(runtime: &Runtime) -> Result<Self> {
        runtime.run(async {
            let (connection, links, _) = rtnetlink::new_connection()?;
            tokio::spawn(connection);
            let (connection, wireguard, _) = nl_wireguard::new_connection()?;
            tokio::spawn(connection);
            Ok(Self { links, wireguard })
        })?
    }

    /// The index of the WireGuard interface `name`, if there is one. A
    /// non-WireGuard interface with that name is an error: it is not ours.
    async fn wireguard_link(&self, name: &str) -> Result<Option<u32>> {
        let mut links = self
            .links
            .link()
            .get()
            .match_name(name.to_owned())
            .execute();
        let link = match links.try_next().await {
            Ok(Some(link)) => link,
            Ok(None) => return Ok(None),
            Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -libc::ENODEV => {
                return Ok(None);
            }
            Err(e) => return Err(e).context("reading the network interfaces"),
        };
        let wireguard = link.attributes.iter().any(|attribute| {
            matches!(attribute, LinkAttribute::LinkInfo(info)
                if info.contains(&LinkInfo::Kind(InfoKind::Wireguard)))
        });
        if !wireguard {
            bail!("interface {name} exists and is not a WireGuard interface");
        }
        Ok(Some(link.header.index))
    }

    async fn delete(&self, name: &str) -> Result<()> {
        if let Some(index) = self.wireguard_link(name).await? {
            self.links
                .link()
                .del(index)
                .execute()
                .await
                .with_context(|| format!("deleting interface {name}"))?;
        }
        Ok(())
    }

    /// Creates the interface and brings it up fully configured. On failure,
    /// deletes it again, so a userspace fallback or a retry starts clean.
    async fn create(&self, config: &InterfaceConfig) -> Result<()> {
        // An interface with this name was left by a run that ended without
        // cleanup. Start again from a known state.
        self.delete(&config.name).await?;
        self.links
            .link()
            .add(
                LinkWireguard::new(&config.name)
                    .mtu(config.mtu().into())
                    .build(),
            )
            .execute()
            .await
            .context("creating the WireGuard interface")?;
        if let Err(e) = self.configure(config).await {
            if let Err(cleanup) = self.delete(&config.name).await {
                tracing::warn!(
                    "deleting the partly configured interface {}: {cleanup:#}",
                    config.name
                );
            }
            return Err(e);
        }
        Ok(())
    }

    async fn configure(&self, config: &InterfaceConfig) -> Result<()> {
        let index = self
            .wireguard_link(&config.name)
            .await?
            .context("the new interface is missing")?;
        for address in &config.addresses {
            self.links
                .address()
                .add(index, address.addr(), address.prefix_len())
                .execute()
                .await
                .with_context(|| format!("adding address {address}"))?;
        }
        let mut device = WireguardParsed::default();
        device.iface_name = Some(config.name.clone());
        device.private_key = Some(BASE64.encode(&config.private_key));
        device.listen_port = Some(config.listen_port);
        self.wireguard
            .clone()
            .set(device)
            .await
            .context("configuring WireGuard")?;
        self.links
            .link()
            .set(LinkUnspec::new_with_index(index).up().build())
            .execute()
            .await
            .context("bringing the interface up")?;
        Ok(())
    }
}
