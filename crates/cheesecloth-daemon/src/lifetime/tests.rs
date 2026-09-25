use super::*;

#[tokio::test]
async fn an_unpolled_command_cannot_hold_up_stop_or_resume_after_it() {
    let lifetime = Arc::new(Lifetime::default());
    let command = lifetime.run(std::future::pending::<()>());
    tokio::pin!(command);
    assert!(futures_util::poll!(&mut command).is_pending());
    lifetime.stop().await;
    assert!(command.await.is_err());
    assert!(
        lifetime
            .run(async { panic!("old work resumed") })
            .await
            .is_err()
    );
}

#[tokio::test]
async fn stop_drains_a_write_even_when_its_caller_was_cancelled() {
    let lifetime = Arc::new(Lifetime::default());
    let (release, wait) = std::sync::mpsc::channel();
    let (started, running) = tokio::sync::oneshot::channel();
    let l = lifetime.clone();
    let caller = tokio::spawn(async move {
        l.blocking(move || {
            started.send(()).unwrap();
            wait.recv().unwrap();
        })
        .await
    });
    running.await.unwrap();
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    let stop = lifetime.stop();
    tokio::pin!(stop);
    assert!(futures_util::poll!(&mut stop).is_pending());
    release.send(()).unwrap();
    stop.await;
    assert!(lifetime.enter().is_err());
}
