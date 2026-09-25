# PBFT proposal — superseded

The earlier proposal to replace CASPaxos with a fixed four-voter PBFT system
was not adopted. Cheesecloth keeps member-initiated rounds and adaptive voter
groups, adding signed evidence, durable verification and acceptance certificates.

The selected design permits relaxed operation in small groups and uses the
installed quorum to authorize every transition. `strict_security` prevents
automatic downgrades after protection activates; `buffer_nodes` requests an
outage reserve. This is not a PBFT implementation or a claim of PBFT liveness.

See [consensus safety](CONSENSUS-SAFETY.md) for the current protocol, assumptions
and validation limits. The original exploration remains in Git history.
