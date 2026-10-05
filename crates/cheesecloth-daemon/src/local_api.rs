//! The local API: one JSON request per line on a Unix socket (see `api`).

use std::sync::Arc;

use anyhow::{Context, Result, bail};
#[cfg(unix)]
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tracing::info;

use crate::{
    Daemon, Phase,
    api::{ApiRequest, ApiResponse},
};

fn to_json<T: serde::Serialize>(value: T) -> Result<serde_json::Value> {
    Ok(serde_json::to_value(value)?)
}

async fn write_response(
    write: &mut (impl AsyncWrite + Unpin + ?Sized),
    resp: &ApiResponse,
) -> std::io::Result<()> {
    let mut out = serde_json::to_string(resp).expect("serializable");
    out.push('\n');
    write.write_all(out.as_bytes()).await
}

/// The connection of a `stop` request. It is answered after shutdown, so the
/// client knows that cleanup has finished.
pub(crate) struct StopRequest(Box<dyn AsyncWrite + Send + Unpin>);

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
                // `serve_api` keeps the connection to answer after shutdown.
                ApiRequest::Stop => bail!("stop is only served on the API socket"),
            })
        }
        .await;
        match res {
            Ok(v) => ApiResponse::Ok(v),
            Err(e) => ApiResponse::Err(format!("{e:#}")),
        }
    }

    /// Keeps `write` to answer once shutdown has finished, and wakes `serve`.
    fn request_stop(&self, write: impl AsyncWrite + Send + Unpin + 'static) {
        self.stop_requests.lock().push(StopRequest(Box::new(write)));
        self.stop_requested.notify_one();
    }

    /// Answers the `stop` requests. An error says that local cleanup is still
    /// pending.
    pub(crate) async fn answer_stop_requests(&self) {
        let requests = std::mem::take(&mut *self.stop_requests.lock());
        if requests.is_empty() {
            return;
        }
        let resp = match &*self.phase.read() {
            Phase::Stopping { error, .. } => ApiResponse::Err(match error {
                Some(e) => format!("stopped, but local cleanup is pending: {e}"),
                None => "stopped, but local cleanup is pending".into(),
            }),
            _ => ApiResponse::Ok(serde_json::Value::Null),
        };
        for mut request in requests {
            // A client that has gone away doesn't need the answer.
            let _ = write_response(&mut *request.0, &resp).await;
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
                                Ok(ApiRequest::Stop) => {
                                    daemon.request_stop(write);
                                    return;
                                }
                                Ok(req) => daemon.handle_api(req).await,
                                Err(e) => ApiResponse::Err(format!("bad request: {e}")),
                            };
                            if write_response(&mut write, &resp).await.is_err() {
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

    use std::time::Duration;

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    use crate::testing::serve;

    /// Fails the test instead of hanging when `f` never finishes.
    async fn within<F: Future>(f: F) -> F::Output {
        tokio::time::timeout(Duration::from_secs(5), f)
            .await
            .expect("finished in time")
    }

    /// Waits until `n` stop requests are queued.
    async fn queued(d: &Daemon, n: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while d.stop_requests.lock().len() < n {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("queued stop requests");
    }

    #[tokio::test]
    async fn stop_is_answered_after_shutdown_and_ends_serve() {
        let (d, _dir) = crate::testing::daemon("api-stop-request", crate::RelayMode::Never).await;
        let (server, socket) = serve(&d).await;
        let answer: serde_json::Value = within(crate::api::call(&socket, &ApiRequest::Stop))
            .await
            .unwrap();
        assert!(answer.is_null());
        assert!(matches!(&*d.phase.read(), Phase::Stopped));
        within(server).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn every_stop_request_is_answered() {
        let (d, _dir) = crate::testing::daemon("api-stop-twice", crate::RelayMode::Never).await;
        let (server, socket) = serve(&d).await;
        // Holding the operation lock keeps shutdown from starting, so both
        // requests are queued before it answers.
        let op = d.op.lock().await;
        let stop = || {
            let socket = socket.clone();
            tokio::spawn(async move {
                crate::api::call::<serde_json::Value>(&socket, &ApiRequest::Stop).await
            })
        };
        let (first, second) = (stop(), stop());
        queued(&d, 2).await;
        drop(op);
        assert!(within(first).await.unwrap().unwrap().is_null());
        assert!(within(second).await.unwrap().unwrap().is_null());
        within(server).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn stop_follows_other_requests_on_one_connection() {
        let (d, _dir) = crate::testing::daemon("api-stop-after", crate::RelayMode::Never).await;
        let (server, socket) = serve(&d).await;
        let client = tokio::net::UnixStream::connect(&socket).await.unwrap();
        let (read, mut write) = client.into_split();
        let mut lines = tokio::io::BufReader::new(read).lines();
        write
            .write_all(b"{\"cmd\":\"status\"}\n{\"cmd\":\"stop\"}\n")
            .await
            .unwrap();
        let status = within(lines.next_line()).await.unwrap().unwrap();
        assert!(status.starts_with("{\"ok\":{"), "{status}");
        assert_eq!(
            within(lines.next_line()).await.unwrap().unwrap(),
            "{\"ok\":null}"
        );
        assert!(within(lines.next_line()).await.unwrap().is_none());
        within(server).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_stop_client_that_goes_away_does_not_hold_up_shutdown() {
        let (d, _dir) = crate::testing::daemon("api-stop-gone", crate::RelayMode::Never).await;
        let (server, socket) = serve(&d).await;
        let op = d.op.lock().await;
        let mut client = tokio::net::UnixStream::connect(&socket).await.unwrap();
        client.write_all(b"{\"cmd\":\"stop\"}\n").await.unwrap();
        queued(&d, 1).await;
        drop(client);
        drop(op);
        within(server).await.unwrap().unwrap();
        assert!(matches!(&*d.phase.read(), Phase::Stopped));
    }

    #[tokio::test]
    async fn a_signal_shuts_down_without_stop_requests() {
        let (d, _dir) = crate::testing::daemon("api-signal", crate::RelayMode::Never).await;
        within(crate::serve(d.clone(), async {})).await.unwrap();
        assert!(matches!(&*d.phase.read(), Phase::Stopped));
    }

    #[tokio::test]
    async fn handle_api_refuses_stop_without_a_connection() {
        let (d, _dir) = crate::testing::daemon("api-stop-direct", crate::RelayMode::Never).await;
        assert!(matches!(
            d.handle_api(ApiRequest::Stop).await,
            ApiResponse::Err(e) if e.contains("API socket")
        ));
        assert!(d.stop_requests.lock().is_empty());
        d.shutdown().await;
    }
}
