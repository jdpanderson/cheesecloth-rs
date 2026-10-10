# Design

This document describes the current implementation. Start with the
[README](README.md) to run it and [consensus safety](CONSENSUS-SAFETY.md) for
the fault model. Cheesecloth has one cluster per daemon, no central service,
and no permanent consensus leader.

## Components

| Crate | Responsibility |
| --- | --- |
| `cheesecloth-core` | Identity, signed commands, invites, deterministic cluster state. |
| `cheesecloth-net` | QUIC connections, authentication, forwarding and reachability probes. |
| `cheesecloth-wg` | WireGuard backends, path planning and NAT openers. |
| `cheesecloth-daemon` | Authenticated consensus rounds, membership, discovery, reconciliation and local API. |
| `cheesecloth` | CLI and daemon entry point. |

The CASPaxos engine and the durable acceptor storage are the separate
[`pnyx`](https://crates.io/crates/pnyx) crate, which does not depend on the
transport.

The CLI sends JSON requests to a Unix socket, normally
`<state-dir>/control.sock`, with mode `0600`. The state directory is `0700`.
On Windows it uses a named pipe instead, named after the canonical state
directory, so separate instances get separate pipes. The daemon creates the
pipe as its first instance, and fails if the name is in use. The pipe's access
list allows only SYSTEM, Administrators and the daemon's user. Before it sends
a request, the CLI checks that the pipe server runs as SYSTEM, an
administrator or the CLI's user. `--json` returns structured responses. See
the [README](README.md) for platform validation status.

## Identity and state

A node creates an Ed25519 identity and a separate WireGuard key at first start.
Its node ID is its Ed25519 public key. Signed member records bind that identity
to the WireGuard key, name, control addresses, port and initial relay role.
Keys survive leaving; automatic key rotation is not implemented.

The cluster ID is a hash of the signed genesis command. Every non-genesis
command signs that ID. Commands, member records, forwarding envelopes and
consensus evidence use separate signature domains.

Two kinds of state serve different purposes:

- **Agreed state:** membership, assigned IPv4 addresses, settings, invites,
  pending proposals and recent command results. Voter configurations and
  certificates determine which changes are authoritative.
- **Soft state:** signed discovery hints, including addresses, relay role,
  connections, observed WireGuard endpoints and learned state version. These
  hints guide routing and fetching; they cannot authorize membership changes.

There is no complete operation log or audit history. Current membership records
who admitted each member; transition certificates support configuration recovery.

## Cluster settings

Read settings with `cheesecloth config get [key]`; change them with
`cheesecloth config set <key> <value>`. Changes use the current approval policy.
Daemon options such as ports and relay mode are local, not cluster settings.

| Setting | Default | Meaning |
| --- | --- | --- |
| `approvals_required` | `0` | Additional member approvals for joins, removals and setting changes. |
| `acceptors` | `7` | Cap on voters, from 1 to 7; the installed group may be smaller. |
| `strict_security` | `false` | Once protected, refuse automatic transitions to relaxed mode. |
| `buffer_nodes` | `0` | Requested outage reserve, from 0 to 3. |
| `catch_up_days` | `30` | Retention of configuration transition proofs, from 1 to 3650 days. |

`ipv4_range` and `ipv6_prefix` are readable but cannot be changed after creation.
The [safety guide](CONSENSUS-SAFETY.md#voters-and-quorums) defines how the voter
cap, strict mode and reserve interact.

## Membership and approvals

`init` creates a one-member cluster. The founder is its initial trust anchor,
with no special authority after bootstrap. An invite carries a secret, cluster
ID and contact keys and addresses. A joiner pins a contact's identity and trusts
the admitting member's initial certified state.

Invites expire after 30 minutes. A committed redemption consumes the invite
before attempting admission, including when that attempt fails or awaits
approvals. An unknown secret is rejected before starting consensus.

With `approvals_required = N`, a join, removal or setting change needs N
approvals from distinct members other than its proposer. A removal target
cannot approve or reject its own removal proposal. Any other member can reject
a proposal with one vote. Proposals expire after 24 hours. These are signed
cluster changes and still require consensus.

Approvals name the complete proposal token displayed by `pending`. The token
binds the action and its creation context; later approvals do not change it.
A join approval binds the joining identity and WireGuard key.

The threshold cannot be set above member count minus one. Because a removal
also excludes its target, it needs at least N + 2 members. Departures can make
the threshold impossible to satisfy; it is never lowered automatically. If
eligible members cannot approve new joins or a lower threshold, rebuild the
cluster. Temporary absence alone does not remove membership.

## Consensus and recovery

Any member may propose a change. The daemon adds signed prepare evidence,
durable verification votes and acceptance certificates to the CASPaxos engine,
[pnyx](https://docs.rs/pnyx/0.1/pnyx/). The engine alone assumes honest
participants. The full round and safety
argument are in [the safety guide](CONSENSUS-SAFETY.md#authenticated-round).

A new voter configuration must be certified by the installed quorum. Its
closing certificate establishes the next configuration's starting state.
Voter selection keeps eligible existing voters and prefers reachable members
and relays when choosing candidates. The lowest-ID reachable voter checks
selection every ten seconds. Ten minutes of absence makes a member eligible
for replacement as a voter, subject to the buffer and strict policy.
Each verifier checks its own availability observations and a reachable new
quorum; disagreement can delay a transition.

A node learns a state only after verifying its acceptance certificate and the
configuration chain from its trusted state. State and proof are saved together
before local progress is reported. Conflicting states at one version are
refused. Intermediate closing certificates are retained during recovery.

Acceptors receive commit notices; other members fetch when soft state advertises
a newer version. Fetches carry a bounded prefix of transitions, allowing repeated
requests to catch up. An unavailable or unhelpful source gets exponential
backoff from 2 to 256 seconds; new advertisements do not clear it. Verified
state or transition progress clears the backoff, and other sources remain usable.

Transition proofs are retained for `catch_up_days`. If a returning node cannot
bridge an expired chain, remove and invite it again. If the installed quorum
is permanently lost, rebuild the cluster. There is no automatic quorum reset
or merging of divergent histories. Existing WireGuard paths use the last
learned membership while changes are paused.

## Lifecycle and recovery

`leave` never needs approvals. A leaving voter first transfers its role, then
waits for the new quorum to persist the state, then commits its own removal.
If it is the last member, it only performs local cleanup. A failed cluster step
normally leaves it running; retrying handles a removal whose reply was lost.
`leave --force` proceeds to local cleanup despite cluster failures, which can
leave the remaining cluster without quorum.

When a join is still pending, `leave` cancels it locally without contacting the
cluster. The remote proposal and consumed invite remain unchanged. Polling stops,
and late replies cannot revive that attempt. A daemon restart resumes an
uncancelled pending join.

Members stop accepting control traffic from a removed identity once they learn
its removal. They also revoke its WireGuard key. A reachable removed node is
sent the certified result so it can clean up. A node removed while offline may
never learn that result; use `leave --force` on that node to clean up locally.
Backend errors can delay WireGuard revocation, as described below.

Stopping membership blocks new work, cancels and joins background tasks, and
waits for disk writes already running. Work from an old membership cannot
resume against a later one. Cleanup is recorded durably before removing the
interface and cluster files. If cleanup fails:

- Status reports `stopping` and the error; normal cluster work is blocked.
- `leave` retries unfinished leave cleanup, including after restart.
- `--force` reports the failure and cannot permit reuse before cleanup finishes.

Ordinary daemon shutdown uses the same mechanism but keeps membership files.
On restart, unfinished shutdown cleanup must succeed before membership resumes.

| State file | Contents |
| --- | --- |
| `identity.key`, `wireguard.key` | Persistent node keys; retained after leave. |
| `cluster.json` | Cluster identity and, when applicable, pending join. |
| `acceptor.0`, `acceptor.1` | Durable voting state and latest learned state with proof, in two checksummed copies. |
| `acceptor.bin` | The same state in the format of 0.1.0 and earlier; moved to `acceptor.0` and `acceptor.1` at start. |
| `transitions.bin` | Verified configuration transition certificates. |
| `cleanup.json` | Unfinished interface and state cleanup. |

Durable writes use atomic replacement and file/directory synchronization.
Windows skips the directory synchronization (see [Windows](#windows)).
Startup checks that persisted consensus and cluster identity agree.

## Clocks and retries

Keep clocks synchronized with NTP or equivalent. Proposers timestamp state
changes monotonically. Verifiers allow a new timestamp no later than the greater
of the base state's time and their own clock plus 30 seconds. Invite and proposal
expiry is evaluated as changes are applied; idle clusters need no expiry rounds.

Signed commands must be within ten minutes of the applied timestamp. Recent
results are retained for twenty minutes so protocol retries can recover the
result of the same signed command. Reissuing a CLI command creates a new request;
a timeout does not establish whether the earlier operation committed.

Control exchanges measure clock offsets without extra requests. Status and logs
warn when the median measured skew exceeds 30 seconds. Measurements may be old
in an idle cluster, and Cheesecloth does not correct the host clock.

## Control plane

Each node uses one UDP socket for QUIC, with a connection table keyed by peer
identity. Dialers pin the peer's Ed25519 raw public key. Receivers require proof
of key possession; only cluster members may use member services. Non-members
may redeem invites or query their own pending joins.

Every member connects to every relay. Other members connect directly only on
the same LAN, or when the cluster has no relay. Forwarded requests and
responses are signed end to end. A relay can drop or delay traffic; forwarding
replay tracking is in memory and resets on restart.

The ALPN is `cheesecloth/2`. Each stream starts with its kind, cluster ID and
sender's clock; a wrong cluster is refused. Responses carry the responder's
clock. Payloads use Postcard encoding.

| Stream | Purpose |
| --- | --- |
| `direct` | Member RPCs: consensus, state transfer and punch coordination. |
| `state` | One-way signed soft-state updates. |
| `forward`, `deliver` | Relay requests and delivery of signed envelopes. |
| `join` | Invite redemption and join status; the only guest service. |
| `probe` | Public reachability checks through a fresh dial-back socket. |

The transport tries another route only when the request could not have arrived
in full. A lost reply after delivery is returned as an uncertain outcome.
Consensus retries retain the signed command for result lookup.

With `--relay auto`, a node is a relay when it is publicly reachable. Its
candidate addresses are its global interface addresses, its `--advertise`
addresses and a router mapping of its control port. Another member checks them
by dialing back from a new socket, which the node's firewall sees as an
unsolicited connection. The check runs every ten minutes, and again when the
candidates change. After a restart, the node keeps its last result until a new
check finishes. An isolated founder has nobody to ask, so it counts as public
if it has a candidate.

Members on the node's own network cannot confirm it, because their dial-backs
do not cross its router. A member is on the node's network when the node is
connected to it at an address inside one of its interface networks, or when one
of the member's global addresses is inside one. Private addresses that a member
only publishes do not count: every site uses the same private ranges. When only
such members are connected, the check waits, and `status` shows a warning.

The check tests only the control port. The WireGuard port at the same address
is assumed to behave the same way, because both are behind the same router and
firewall.

`always` forces relay participation; `never` disables forwarding even on a public
node. Signed soft state overrides the member record's initial relay role.
Disabling relaying leaves direct services and WireGuard paths available.

A node publishes the addresses of its running interfaces, except loopback,
link-local and overlay addresses. An interface that is not running, such as a
Docker bridge with no containers, carries no traffic, so its address is left
out. Its network still counts when `init` chooses an overlay range.

QUIC keepalive is always 25 seconds. Idle consensus sends no rounds, but discovery,
reachability checks, port mapping and WireGuard maintain their own traffic.

## Discovery and resource bounds

Nodes publish signed soft state only when its content changes. Newer entries
spread through existing connections; a new connection receives the table in
bounded batches. Unknown members' entries are held in a bounded cache until
membership catches up. Soft state is discovery evidence, not consensus proof.

| Resource | Limit |
| --- | --- |
| Agreed state | 320 KiB; an already oversized state cannot grow. |
| Wire request or response | 1 MiB; application payload reserves 1 KiB for framing. |
| Join request | 64 KiB. |
| Transitions per fetch | 256 KiB. |
| Signed soft-state body | 128 KiB. |
| Each soft-state address list | 32 unique addresses. |
| Soft-state connections / observations | 1,024 unique IDs / targets each. |
| Soft-state batch / admission seed | 256 KiB / 64 KiB. |
| Parked unknown soft-state entries | 256. |

Admission seeds prefer the admitting node and relays; normal synchronization
supplies the rest. Discovery limits do not truncate agreed membership.
Member names are limited to 32 bytes and member records to 16 control addresses.

Non-members are limited to 64 connections per node and eight per source IPv4
address or IPv6 /64. Each gets two streams, a 256 KiB receive window, 30 seconds
to send a request, a 30-second application idle limit and a two-minute lifetime.
Guessing an invite does not trigger a consensus round.

Ballot requests and untrusted rejection hints are bounded to a counter step of
`2^20`. Feedback must match the outstanding request. Saved or certified ballots
supply the recovery floor; a single extreme hint cannot exhaust the counter.
Large legitimate promise gaps can be crossed over several rounds.

## WireGuard and NAT traversal

Overlay IPv6 addresses derive from the cluster and node IDs. IPv4 allocation
is agreed through consensus. By default, `init` selects a random /24 inside
`100.64.0.0/10`, avoiding the founder's existing routes; it has 254 usable
addresses. Use `init --ipv4-range CIDR` to select a suitable range explicitly.

The reconciler computes desired peers and routes on changes and every second.
It serializes backend writes with punch handlers and indexes endpoint observations
once per pass. Public, unmapped observers take preference over mapped observers.

Cheesecloth owns its interface exclusively. Unexpected keys are removed, and
missing authorized peers are restored when their path requires them. Failed
removals remain pending and are retried, even if status reads fail. Status and
logs report errors. Revocation is complete only after backend success or a fresh
read confirms absence; backend failure can temporarily leave access in place.

Paths use LAN addresses, public endpoints or NAT punching. For two NATed peers,
a relay shares observed endpoints and coordinates raw UDP openers from each
WireGuard port. The lower-ID member then starts the handshake; the other enables
keepalive after success. Only IPv4 openers are implemented.

Failed or stale punched paths are removed before retrying. A 35-second quiet
period starts only after peer removal is confirmed, so WireGuard retries cannot
keep the old NAT mapping alive. Incoming offers cannot shorten that wait.
Repeated failures back off to five-minute retries. There is no WireGuard relay
fallback; some NATs require a port mapping, manual forwarding or a public endpoint.

Automatic IPv4 router mappings use UPnP or PCP and are released on
shutdown. A WireGuard mapping supplies a public endpoint; a control-port mapping
supplies a relay candidate that still needs the reachability check. Disable
mapping with `--no-port-mapping`. For each port, `status` shows the router's
address and the protocol (UPnP or PCP), the last error, or that the daemon is
still asking the router.

WireGuard keepalive defaults to 25 seconds behind NAT and off when public.
When the router maps the WireGuard port, it is 300 seconds: the mapping should
not need a keepalive, and this tests that while still sending a first handshake.
`--keepalive` overrides these defaults. Punched paths always keep a keepalive:
`--keepalive` if it is not 0, otherwise 25 seconds.

The default backend tries kernel WireGuard, then userspace; macOS, Windows
and FreeBSD use userspace directly. Kernel WireGuard is configured over
netlink. Userspace WireGuard is GotaTun inside the daemon, on its own tokio
runtime, with a TUN device (Wintun on Windows, which needs `wintun.dll` beside
the executable). Each interface address's prefix routes the overlay into the
interface on every OS. No per-peer ACLs are implemented: use host firewalls to
restrict overlay access.

## Windows

Windows lacks some things that other systems have, so these parts are weaker
there:

- **No directory sync.** Windows has no documented way to sync a directory.
  File data is still synced, but creating, renaming or removing a file is
  less durable after a power loss.
- **No NAT openers.** Windows limits raw sockets, so the raw UDP openers are
  not available and hole punching is weaker. More pairs of NATed peers need a
  port mapping, manual forwarding or a public endpoint, and their control
  messages go through relays.
- **Elevated CLI for a SYSTEM daemon.** When the daemon runs as SYSTEM, the
  CLI must run in an elevated shell to open the pipe.
- **Console stop only.** The daemon stops cleanly on Ctrl-C or Ctrl-Break
  (or `cheesecloth stop`). It does not handle console close, log-off or
  system shutdown: Windows ends the process a few seconds after these, so a
  clean shutdown is not certain. Running the daemon as a Windows service will
  fix this.
- **Access lists instead of modes.** The state directory, keys and state
  files allow only SYSTEM, Administrators and the daemon's user, with
  inheritance from the parent removed. Files the daemon creates in the
  directory inherit that list.
- **IPv4-mapped bind is IPv6-only.** A bind address like `::ffff:a.b.c.d` is
  IPv6-only on Windows. Only the unspecified address `[::]` is dual-stack.
