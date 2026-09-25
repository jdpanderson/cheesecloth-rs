use super::*;

#[test]
fn warns_when_this_nodes_clock_is_off() {
    let (a, b, c) = (NodeId([1; 32]), NodeId([2; 32]), NodeId([3; 32]));
    assert!(warnings(&[]).is_empty());

    // Two of three peers are 5 minutes ahead: our clock is behind.
    let w = warnings(&[(a, 300_000), (b, 300_000), (c, 0)]);
    assert!(w[0].contains("this node's clock is 5 min behind"), "{w:?}");

    // Only one peer is off: that's the peer's problem, and its own
    // status says so.
    assert!(warnings(&[(a, 0), (b, 1000), (c, -600_000)]).is_empty());

    // Within tolerance: nothing.
    assert!(warnings(&[(a, 0), (b, 1000), (c, 5_000)]).is_empty());

    // Short skews in seconds; ahead as well as behind.
    let w = warnings(&[(a, -45_000), (b, -45_000)]);
    assert!(w[0].contains("this node's clock is 45 s ahead of"), "{w:?}");
}
