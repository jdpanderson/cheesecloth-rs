use anyhow::{Context, anyhow};

use super::*;

#[test]
fn a_failure_is_shown_until_it_ends() {
    let p = Problem::new("checking the acceptors");
    assert_eq!(p.warning(), None);
    p.record(Err(anyhow!("timed out")).context("couldn't agree"));
    assert_eq!(
        p.warning().as_deref(),
        Some("checking the acceptors: couldn't agree: timed out")
    );
    // The same failure with another cause: shown with the new cause.
    p.record(Err(anyhow!("no route")).context("couldn't agree"));
    assert_eq!(
        p.warning().as_deref(),
        Some("checking the acceptors: couldn't agree: no route")
    );
    p.record(Ok(()));
    assert_eq!(p.warning(), None);
}
