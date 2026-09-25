# Consensus safety

Cheesecloth adapts its voter group through authenticated CASPaxos rounds.
**Protected mode targets safety against one Byzantine voter**: a voter that
lies, equivocates or withholds votes. **Relaxed mode has no Byzantine safety
guarantee.** These are protocol design goals, not independently audited claims.

## Voters and quorums

A committed configuration names its voters, sequence number and protection
mode. `acceptors` caps the group at 1–7 voters, default 7. Member count alone
does not determine protection. With the default `buffer_nodes = 0`:

| Installed voters | Mode | Votes required |
| --- | --- | --- |
| 1 | relaxed | 1 |
| 2 | relaxed | 2 |
| 3 | relaxed | 2 |
| 4 | protected | 3 |
| 5 | protected | 4 |
| 6 | protected | 4 |
| 7 | protected | 5 |

Relaxed quorums are `floor(n/2) + 1`, providing crash-fault safety with honest
participants. Protected quorums are `floor((n+1)/2) + 1`; any two intersect
in more than one voter. The fault budget remains **one**, including at seven
voters. Protection assumes authentic signatures, durable honest voting records,
and a common trusted starting history.

A malicious member can still stall changes with competing ballots. A relay can
block communication. Admission policy must preserve the voter fault assumption;
consensus cannot identify several keys controlled by the same attacker.

## Adaptation, buffers and strict mode

Every voter transition requires the **installed quorum** before the new quorum
applies. Ten minutes of absence permits replacing a voter, not deleting its
membership or changing authority without agreement.

| Event, starting with four protected voters | Result |
| --- | --- |
| Two become unreachable together | Three votes are still required; changes pause. |
| One becomes unreachable | Three can commit a relaxed three-voter group if strict mode is off. |
| Another becomes unreachable after that commit | The remaining two can commit a two-voter group. Both votes remain required. |

Strict mode blocks the protected-to-relaxed transition. Losing quorum before
a transition completes pauses changes. Existing WireGuard paths retain the last
learned membership; there is no automatic lost-quorum reset.

`buffer_nodes` is an outage budget from 0 to 3. **All selected voters store
state and vote.** Protection activates only with at least four voters and
`n - protected_quorum >= buffer_nodes`, unless strict mode has already retained
protection. For buffer two, five voters use three votes in relaxed mode; six
use four in protected mode. The selection policy can retain an installed group
through absences within its buffer.

The reserve includes a malicious voter withholding its vote; it is not an
additional allowance. Small groups may not meet the requested reserve. Buffer
three prevents new activation of protection under the seven-voter cap.

`strict_security` defaults to false. Enable it with `init --strict-security`
or `config set strict_security true`. Bootstrap may be relaxed. Once protected,
the certified configuration retains protection through restart, even if the
requested buffer cannot be met. This can prevent a graceful departure that
would leave fewer than four voters. An authorized setting change can disable
strict mode; do so before reducing a protected voter cap below four.

Mode changes are logged after persistence. `status` shows mode, quorum,
reachable voters, paused changes, strict mode and buffer. Reachability can lag
actual failure. Returning to protection cannot repair a fork created while
relaxed; protection begins from a common trusted activation state.

## Authorization

Consensus and permission are separate. With `approvals_required = 0`, any
member may admit or remove others and change settings. Raising the threshold
requires additional member approvals; it does not make relaxed consensus safe.
See [membership and approvals](DESIGN.md#membership-and-approvals).

Approval and rejection signatures name a full 32-byte proposal token. Eight
bytes encode a sequence; 24 bind a BLAKE3 digest of the cluster, creation state,
action, proposer, sequence, time and expiry. Join actions include the signed
identity and WireGuard key. Later votes leave the token unchanged. A signature
for one proposal cannot authorize another action at the same sequence number.

Every non-genesis command signs its cluster ID. Genesis defines that ID from
its signed envelope. Prepare, verification and acceptance signatures use
separate domains, preventing votes from being reused across phases.

## Authenticated round

1. **Prepare.** Voters persist promises before signing the cluster,
   configuration, requested ballot and prior accepted certificate. A reported
   accepted candidate needs quorum evidence at its ballot, normally the
   verification certificate stored with it; one voter's assertion is insufficient.
2. **Select.** The proposer verifies distinct promises and state bodies against
   their signed headers, then selects the highest accepted ballot. Conflicting
   evidence at the same ballot is refused.
3. **Verify.** Each verifier checks the prepare quorum. An unfinished highest
   candidate can only be written back unchanged. A new command requires an
   acceptance certificate for that predecessor, or the preceding configuration's
   closing certificate for a fresh opening. The verifier replays the state change
   and checks configuration policy and local availability observations.
4. **Endorse.** Before signing verification, the voter durably records its
   promise and candidate. It cannot endorse different candidates at one ballot,
   even after restart. Higher ballots can recover abandoned candidates.
5. **Accept.** Voters require a matching verification quorum certificate. They
   save the accepted value and proof together before signing acceptance.
6. **Learn.** An acceptance quorum certificate proves the chosen result.
   Verification votes do not count as acceptance votes. The proposer retains
   closing certificates and reports success only after local persistence.

Certificates bind the cluster, complete voter configuration and mode, ballot,
state version, time, hash and any successor configuration. Thresholds come from
a trusted configuration, not a peer's claimed mode. Certificates contain headers
and signatures without recursively embedding earlier round evidence.

The verification phase adds an exchange and durable write to ordinary CASPaxos.
Prepare replies include accepted state bodies. The 320 KiB state cap reserves
space in the 1 MiB message limit for a candidate, certified base and evidence.
[Resource bounds](DESIGN.md#discovery-and-resource-bounds) also constrain peer hints.

## Validation and limits

The safety argument relies on quorum intersection. Two verification quorums
share an honest voter whose durable endorsement excludes conflicting candidates
at one ballot. Prepare and acceptance quorums also share an honest voter, which
reports its accepted value or promises the new ballot before an older acceptance
quorum can form. Quorum evidence prevents a faulty voter inventing an unsupported
higher accepted ballot. New commands extend chosen predecessors; recovery writes
back unfinished candidates. A closing certificate anchors the next configuration.

This is an implementation argument, **not a machine-checked Byzantine proof**.
Tests cover forged and replayed evidence, phase confusion, proposal substitution,
durable endorsements, partial acceptance, configuration recovery and adaptive
policy. Model checks cover the generic engine's crash faults and reconfiguration;
they do not model the daemon's Byzantine evidence layer.

The design draws on [CASPaxos](https://arxiv.org/html/1802.07000v9) and
[Byzantizing Paxos by Refinement](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/12/Byzantizing-Paxos-by-Refinement.pdf).
Neither proves this implementation. The [earlier PBFT proposal](PBFT.md) was
superseded; Cheesecloth does not implement PBFT or claim its liveness properties.

Wire and disk formats are unstable during development. The current control
protocol is `cheesecloth/2`; older protocol versions cannot join it.
