//! The local API: one JSON request per line on a Unix socket (see `api`).

use std::sync::Arc;

use anyhow::{Context, Result, bail};
#[cfg(unix)]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::info;

use crate::{
    Daemon,
    api::{ApiRequest, ApiResponse},
};

fn to_json<T: serde::Serialize>(value: T) -> Result<serde_json::Value> {
    Ok(serde_json::to_value(value)?)
}

impl Daemon {
    pub async fn handle_api(self: &Arc<Self>, req: ApiRequest) -> ApiResponse {
        let res: Result<serde_json::Value> = async {
            Ok(match req {
                ApiRequest::Status => to_json(self.status().await?)?,
                ApiRequest::Peers => to_json(self.peers()?)?,
                ApiRequest::Init {
                    ipv4_range,
                    strict_security,
                } => to_json(self.init_with_security(ipv4_range, strict_security).await?)?,
                ApiRequest::Invite => to_json(self.invite().await?)?,
                ApiRequest::Join { token } => to_json(self.join(&token).await?)?,
                ApiRequest::Remove { node } => to_json(self.remove(&node).await?)?,
                ApiRequest::Leave { force } => to_json(self.leave(force).await?)?,
                ApiRequest::Pending => to_json(self.pending()?)?,
                ApiRequest::Approve { proposal } => to_json(self.vote(proposal, true).await?)?,
                ApiRequest::Reject { proposal } => to_json(self.vote(proposal, false).await?)?,
                ApiRequest::ConfigGet => to_json(self.config_get()?)?,
                ApiRequest::ConfigSet { key, value } => {
                    to_json(self.config_set(&key, &value).await?)?
                }
            })
        }
        .await;
        match res {
            Ok(v) => ApiResponse::Ok(v),
            Err(e) => ApiResponse::Err(format!("{e:#}")),
        }
    }

    /// Serves the local API until the process exits.
    #[cfg(unix)]
    pub async fn serve_api(self: Arc<Self>) -> Result<()> {
        self.api_work
            .run(async {
                let path = self.opts.socket_path();
                let listener = bind_private_socket(&path)?;
                info!(socket = %path.display(), "local API ready");
                loop {
                    let (stream, _) = listener.accept().await?;
                    let daemon = self.clone();
                    self.api_work.spawn(async move {
                        let (read, mut write) = tokio::io::split(stream);
                        let mut lines = BufReader::new(read).lines();
                        while let Ok(Some(line)) = lines.next_line().await {
                            let resp = match serde_json::from_str::<ApiRequest>(&line) {
                                Ok(req) => daemon.handle_api(req).await,
                                Err(e) => ApiResponse::Err(format!("bad request: {e}")),
                            };
                            let mut out = serde_json::to_string(&resp).expect("serializable");
                            out.push('\n');
                            if write.write_all(out.as_bytes()).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            })
            .await
            .unwrap_or(Ok(()))
    }

    #[cfg(not(unix))]
    pub async fn serve_api(self: Arc<Self>) -> Result<()> {
        bail!("the local API isn't implemented on this platform yet")
    }
}

/// Binds the local API socket at `path`, readable and writable by its owner
/// only from the start. The socket is created in a private (0700) directory,
/// restricted to 0600, then moved into place, so nobody can connect while its
/// permissions are looser. Refuses to replace the socket of a running daemon.
#[cfg(unix)]
fn bind_private_socket(path: &std::path::Path) -> Result<tokio::net::UnixListener> {
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
        Ok(listener)
    })();
    let _ = std::fs::remove_dir_all(&staging);
    result
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shutdown_closes_idle_api_clients_and_releases_the_daemon() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        let (d, _dir) = crate::testing::daemon("api-stop", crate::RelayMode::Never).await;
        let weak = Arc::downgrade(&d);
        let socket = d.opts.socket_path();
        let server = tokio::spawn(d.clone().serve_api());
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !socket.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let client = tokio::net::UnixStream::connect(&socket).await.unwrap();
        let (read, mut write) = client.into_split();
        let mut lines = tokio::io::BufReader::new(read).lines();
        write.write_all(b"\"status\"\n").await.unwrap();
        assert!(lines.next_line().await.unwrap().is_some());
        d.shutdown().await;
        assert!(lines.next_line().await.unwrap().is_none());
        server.await.unwrap().unwrap();
        drop(d);
        assert!(weak.upgrade().is_none());
    }
}
