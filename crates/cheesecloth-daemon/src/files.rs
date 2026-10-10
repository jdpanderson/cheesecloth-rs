//! The daemon's state directory.

use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use cheesecloth_core::{
    ClusterId,
    fs::{sync_dir, write_private},
    token::TokenPeer,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

/// A join waiting for approvals.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingJoin {
    pub proposal: cheesecloth_core::ProposalId,
    pub peers: Vec<TokenPeer>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClusterFile {
    pub cluster_id: ClusterId,
    #[serde(default)]
    pub pending: Option<PendingJoin>,
}

/// Durable local cleanup intent. It survives partial consensus-file deletion
/// and prevents restart from rejoining a cluster this process already left.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cleanup {
    pub cluster_id: ClusterId,
    pub interface: String,
    pub backend: Option<cheesecloth_wg::BackendKind>,
    pub remaining_members: usize,
    pub forget_cluster: bool,
}

#[derive(Clone, Debug)]
pub struct Files {
    pub dir: PathBuf,
}

impl Files {
    pub fn new(dir: &Path) -> Result<Self> {
        cheesecloth_core::fs::create_private_dir(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    pub fn identity(&self) -> PathBuf {
        self.dir.join("identity.key")
    }

    pub fn wg_key(&self) -> PathBuf {
        self.dir.join("wireguard.key")
    }

    pub fn cluster(&self) -> PathBuf {
        self.dir.join("cluster.json")
    }

    pub fn cleanup(&self) -> PathBuf {
        self.dir.join("cleanup.json")
    }

    pub fn load_cleanup(&self) -> Result<Option<Cleanup>> {
        match fs::read(self.cleanup()) {
            Ok(b) => Ok(Some(
                serde_json::from_slice(&b).context("reading cleanup.json")?,
            )),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save_cleanup(&self, cleanup: &Cleanup) -> Result<()> {
        write_private(&self.cleanup(), &serde_json::to_vec_pretty(cleanup)?)?;
        sync_dir(&self.dir)?;
        Ok(())
    }

    pub fn finish_cleanup(&self, forget_cluster: bool) -> Result<()> {
        if forget_cluster {
            self.delete_cluster()?;
        }
        self.remove_files([self.cleanup()])?;
        sync_dir(&self.dir)?;
        Ok(())
    }

    /// This node's acceptor state (see `pnyx::store`), which holds the latest
    /// agreed state this node has learned. pnyx decides which files it uses.
    pub fn acceptor(&self) -> PathBuf {
        self.dir.join("acceptor")
    }

    /// The acceptor state in the format of cheesecloth 0.1.0 and earlier: one
    /// file, with no header. If it exists, it holds the newest state, and
    /// `Node::start` moves it to the new files (see `node::open_acceptor`).
    pub fn legacy_acceptor(&self) -> PathBuf {
        self.dir.join("acceptor.bin")
    }

    /// The transitions this node has checked (see `node::proof`).
    pub fn transitions(&self) -> PathBuf {
        self.dir.join("transitions.bin")
    }

    pub fn load_cluster(&self) -> Result<Option<ClusterFile>> {
        match fs::read(self.cluster()) {
            Ok(b) => Ok(Some(
                serde_json::from_slice(&b).context("reading cluster.json")?,
            )),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save_cluster(&self, c: &ClusterFile) -> Result<()> {
        write_private(&self.cluster(), &serde_json::to_vec_pretty(c)?)?;
        sync_dir(&self.dir)?;
        Ok(())
    }

    /// Discards a partially prepared admission without removing its pending
    /// record. A failed join can still be retried or cancelled after restart.
    pub fn delete_consensus(&self) -> Result<()> {
        // The old file goes first, and durably: if it came back after the
        // new store was removed, the next start would move it in again.
        self.delete_legacy_acceptor()?;
        let acceptor = self.acceptor();
        pnyx::store::remove(&acceptor)
            .with_context(|| format!("removing the acceptor state {}", acceptor.display()))?;
        self.remove_files([self.transitions()])
    }

    /// Removes the acceptor state in the old format, and syncs the directory.
    pub fn delete_legacy_acceptor(&self) -> Result<()> {
        self.remove_files([self.legacy_acceptor()])?;
        sync_dir(&self.dir)?;
        Ok(())
    }

    /// Cancels a pending join durably. There is no running acceptor. Keep the
    /// pending record until other cleanup succeeds, and sync its deletion
    /// before the caller reports success.
    pub fn delete_pending(&self) -> Result<()> {
        self.delete_consensus()?;
        self.remove_files([self.cluster()])?;
        sync_dir(&self.dir).context("syncing pending join cancellation")
    }

    /// Forgets the cluster (keeps this node's keys).
    pub fn delete_cluster(&self) -> Result<()> {
        self.delete_consensus()?;
        self.remove_files([self.cluster()])?;
        sync_dir(&self.dir)?;
        Ok(())
    }

    fn remove_files(&self, paths: impl IntoIterator<Item = PathBuf>) -> Result<()> {
        for p in paths {
            match fs::remove_file(&p) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).with_context(|| format!("removing {}", p.display())),
            }
        }
        Ok(())
    }

    /// Loads the WireGuard private key, creating one if needed.
    pub fn load_or_create_wg_key(&self) -> Result<[u8; 32]> {
        let path = self.wg_key();
        match fs::read(&path) {
            Ok(b) => b
                .try_into()
                .map_err(|_| anyhow::anyhow!("{} must be 32 bytes", path.display())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let (private, _) = cheesecloth_wg::generate_keypair();
                write_private(&path, &private)?;
                Ok(private)
            }
            Err(e) => Err(e.into()),
        }
    }
}

/// Writes `value` to `path`, so that a crash leaves either the old or the new
/// contents: a new file is written and synced, then renamed over the old one.
pub fn save<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    let bytes = postcard::to_stdvec(value).map_err(io::Error::other)?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut file = fs::File::create(&tmp)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&tmp, path)?;
    // The rename is only durable once the directory is synced.
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    sync_dir(dir)
}

/// Reads a value written by [`save`], or `None` if there is no file.
pub fn load<T: DeserializeOwned>(path: &Path) -> io::Result<Option<T>> {
    match fs::read(path) {
        Ok(bytes) => postcard::from_bytes(&bytes)
            .map(Some)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests;
