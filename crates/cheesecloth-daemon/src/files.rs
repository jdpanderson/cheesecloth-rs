//! The daemon's state directory.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use cheesecloth_core::{ClusterId, token::TokenPeer, write_private};
use serde::{Deserialize, Serialize};

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
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
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
        fs::File::open(&self.dir)?.sync_all()?;
        Ok(())
    }

    pub fn finish_cleanup(&self, forget_cluster: bool) -> Result<()> {
        if forget_cluster {
            self.delete_cluster()?;
        }
        self.remove_files([self.cleanup()])?;
        fs::File::open(&self.dir)?.sync_all()?;
        Ok(())
    }

    /// This node's acceptor state (see `cheesecloth_paxos::store`), which
    /// holds the latest agreed state this node has learned.
    pub fn acceptor(&self) -> PathBuf {
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
        fs::File::open(&self.dir)?.sync_all()?;
        Ok(())
    }

    /// Discards a partially prepared admission without removing its pending
    /// record. A failed join can still be retried or cancelled after restart.
    pub fn delete_consensus(&self) -> Result<()> {
        self.remove_files([self.acceptor(), self.transitions()])
    }

    /// Cancels a pending join durably. There is no running acceptor. Keep the
    /// pending record until other cleanup succeeds, and sync its deletion
    /// before the caller reports success.
    pub fn delete_pending(&self) -> Result<()> {
        let dir = fs::File::open(&self.dir)?;
        self.delete_consensus()?;
        self.remove_files([self.cluster()])?;
        dir.sync_all().context("syncing pending join cancellation")
    }

    /// Forgets the cluster (keeps this node's keys).
    pub fn delete_cluster(&self) -> Result<()> {
        self.delete_consensus()?;
        self.remove_files([self.cluster()])?;
        fs::File::open(&self.dir)?.sync_all()?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cluster_files_round_trip_and_are_forgotten() {
        let tmp = tempfile::tempdir().unwrap();
        let files = Files::new(&tmp.path().join("state")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&files.dir).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        assert!(files.load_cluster().unwrap().is_none());
        let c = ClusterFile {
            cluster_id: ClusterId([3; 32]),
            pending: Some(PendingJoin {
                proposal: cheesecloth_core::ProposalId([4; 32]),
                peers: vec![],
            }),
        };
        files.save_cluster(&c).unwrap();
        fs::write(files.acceptor(), b"acceptor").unwrap();
        let back = files.load_cluster().unwrap().unwrap();
        assert_eq!(back.cluster_id, c.cluster_id);
        assert_eq!(
            back.pending.unwrap().proposal,
            cheesecloth_core::ProposalId([4; 32])
        );
        files.delete_cluster().unwrap();
        assert!(files.load_cluster().unwrap().is_none());
        assert!(!files.acceptor().exists());
        // Already gone: fine.
        files.delete_cluster().unwrap();

        // Files without the optional fields still load.
        fs::write(
            files.cluster(),
            format!("{{\"cluster_id\": \"{}\"}}", ClusterId([3; 32])),
        )
        .unwrap();
        let old = files.load_cluster().unwrap().unwrap();
        assert!(old.pending.is_none());
    }

    #[test]
    fn broken_files_are_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let files = Files::new(tmp.path()).unwrap();
        fs::write(files.cluster(), b"{not json").unwrap();
        let e = files.load_cluster().unwrap_err();
        assert!(format!("{e:#}").contains("cluster.json"), "{e:#}");

        // Something other than a file in the way.
        fs::remove_file(files.cluster()).unwrap();
        fs::create_dir(files.cluster()).unwrap();
        assert!(files.load_cluster().is_err());
        assert!(files.delete_cluster().is_err());

        fs::write(files.wg_key(), b"short").unwrap();
        let e = files.load_or_create_wg_key().unwrap_err();
        assert!(e.to_string().contains("32 bytes"), "{e:#}");
        fs::remove_file(files.wg_key()).unwrap();
        let key = files.load_or_create_wg_key().unwrap();
        assert_eq!(files.load_or_create_wg_key().unwrap(), key);
        fs::remove_file(files.wg_key()).unwrap();
        fs::create_dir(files.wg_key()).unwrap();
        assert!(files.load_or_create_wg_key().is_err());
    }
}
