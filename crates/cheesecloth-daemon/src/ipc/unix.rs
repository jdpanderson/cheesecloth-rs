//! Unix: the local API on a Unix domain socket, 0600 in the 0700 state
//! directory.

use std::{
    io,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};

pub(crate) type ServerStream = tokio::net::UnixStream;
pub(crate) type ClientStream = tokio::net::UnixStream;

pub(super) fn default_address(state_dir: &Path) -> io::Result<PathBuf> {
    Ok(state_dir.join("control.sock"))
}

pub(crate) struct Listener(tokio::net::UnixListener);

impl Listener {
    /// Binds the local API socket at `path`, readable and writable by its
    /// owner only from the start. The socket is created in a private (0700)
    /// directory, restricted to 0600, then moved into place, so nobody can
    /// connect while its permissions are looser. Refuses to replace the
    /// socket of a running daemon.
    pub(crate) fn bind(path: &Path) -> Result<Self> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            bail!(
                "another cheesecloth daemon is already listening on {}",
                path.display()
            );
        }
        let parent = path.parent().context("socket path has no directory")?;
        let staging = parent.join(format!(".cheesecloth-socket-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&staging);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&staging)
            .with_context(|| format!("creating {}", staging.display()))?;
        let result = (|| {
            let tmp = staging.join("control.sock");
            let listener = tokio::net::UnixListener::bind(&tmp)
                .with_context(|| format!("binding {}", tmp.display()))?;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
            std::fs::rename(&tmp, path)
                .with_context(|| format!("moving the socket to {}", path.display()))?;
            Ok(Self(listener))
        })();
        let _ = std::fs::remove_dir_all(&staging);
        result
    }

    pub(crate) async fn accept(&mut self) -> io::Result<ServerStream> {
        Ok(self.0.accept().await?.0)
    }
}

pub(super) async fn connect(socket: &Path) -> Result<ClientStream> {
    tokio::net::UnixStream::connect(socket)
        .await
        .with_context(|| super::unreachable_message(socket))
}
