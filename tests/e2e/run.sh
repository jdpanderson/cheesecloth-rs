#!/usr/bin/env bash
# End-to-end test: real cheesecloth daemons with kernel WireGuard, behind
# simulated NAT routers, in podman.
#
#                         wan 10.99.0.0/24 ("the internet")
#    ┌───────────────┬──────────────┬──────────────┬──────────────────┬──────────────────────┐
#  relay r        router ra      router rb      router rc          router rd
#  10.99.0.10        │              │           (fully-random)     (fully-random + miniupnpd:
#                  lan-a          lan-b          lan-c              UPnP, NAT-PMP, PCP)
#                 │      │          │              │                  │
#                n1     n4         n2             n3                 n5
#
# r advertises its wan address, like a cloud VM behind 1:1 NAT (10.99.0.0/24
# is private, so it wouldn't otherwise be a relay candidate); it then works out
# for itself that it's public and becomes a relay. Every other node runs with
# no options at all. n3 can't be punched to (its NAT gives every destination a
# new port); n5 sits behind the same kind of NAT, but its router grants port
# mappings. Routers masquerade out of the wan side with WAN_DELAY of
# latency; with FIREWALL=1 (default) they also drop unsolicited inbound traffic.
#
# Env: FIREWALL=0, WAN_DELAY=20ms, SKIP_BUILD=1 (reuse the image), KEEP=1,
#      LOG=<daemon log filter> (default info).
set -euo pipefail
cd "$(dirname "$0")/../.."

IMAGE=localhost/cheesecloth-e2e
P=cce2e
WAN=10.99.0
NAT_TIMEOUT=30
FIREWALL=${FIREWALL:-1}
WAN_DELAY=${WAN_DELAY:-20ms}
NODES="r n1 n2 n3 n4 n5"

lan() { case $1 in a) echo 10.99.1 ;; b) echo 10.99.2 ;; c) echo 10.99.3 ;; d) echo 10.99.4 ;; esac; }

failures=0
pass() { printf 'PASS  %s\n' "$1"; [[ -n ${2:-} ]] && printf '      %s\n' "$2"; return 0; }
fail() { printf 'FAIL  %s\n' "$1"; [[ -n ${2:-} ]] && printf '      %s\n' "$2"; failures=$((failures + 1)); }
ex() { podman exec "$P-$1" sh -c "$2"; }
cc() { local n=$1; shift; podman exec "$P-$n" cheesecloth "$@"; }

remove_lab() {
    podman rm -f -t 0 $(podman ps -aq --filter "name=^$P-") >/dev/null 2>&1 || true
    podman network rm $P-wan $P-lan-a $P-lan-b $P-lan-c $P-lan-d >/dev/null 2>&1 || true
}
cleanup() {
    [[ ${KEEP:-0} == 1 ]] && { echo "KEEP=1: leaving lab running"; return; }
    remove_lab
}
trap cleanup EXIT

dump_logs() {
    local n
    for n in $NODES; do
        echo "----- $n"
        podman logs --tail 40 "$P-$n" 2>&1 | sed 's/^/      /'
    done
}

# ------------------------------------------------------------------ lab setup

remove_lab
if [[ ${SKIP_BUILD:-0} != 1 ]]; then
    echo "building $IMAGE (release build, a few minutes the first time)"
    podman build -q -f tests/e2e/Containerfile -t $IMAGE . >/dev/null
fi
podman network create --internal --subnet $WAN.0/24 $P-wan >/dev/null
for l in a b c d; do
    podman network create --internal --subnet $(lan $l).0/24 $P-lan-$l >/dev/null
done

# router <name> <lan> <wan-ip> <masquerade flags>
router() {
    podman run -d --name $P-$1 --cap-add NET_ADMIN \
        --sysctl net.ipv4.ip_forward=1 \
        --sysctl net.netfilter.nf_conntrack_udp_timeout=$NAT_TIMEOUT \
        --sysctl net.netfilter.nf_conntrack_udp_timeout_stream=$NAT_TIMEOUT \
        --network $P-wan:ip=$3 --network $P-lan-$2:ip=$(lan $2).2 \
        $IMAGE >/dev/null
    local fw=""
    if [[ $FIREWALL == 1 ]]; then
        fw='
        table ip filter {
            chain input { type filter hook input priority filter; policy accept;
                iifname "eth0" ct state established,related accept; iifname "eth0" drop; }
            chain forward { type filter hook forward priority filter; policy accept;
                iifname "eth0" ct state established,related accept;
                iifname "eth0" ct status dnat accept; iifname "eth0" drop; }
        }'
    fi
    ex $1 "nft -f - <<EOF
table ip nat {
    chain post { type nat hook postrouting priority srcnat; oifname \"eth0\" masquerade $4; }
}
$fw
EOF
    tc qdisc add dev eth0 root netem delay $WAN_DELAY"
}

# upnp <router> <lan>: run miniupnpd (UPnP IGD, NAT-PMP and PCP) on a router.
upnp() {
    ex $1 "nft -f - <<EOF
table inet filter {
    chain forward { type filter hook forward priority 0; policy accept; jump miniupnpd; }
    chain miniupnpd { }
    chain prerouting { type nat hook prerouting priority -100; policy accept; jump prerouting_miniupnpd; }
    chain postrouting { type nat hook postrouting priority 100; policy accept; jump postrouting_miniupnpd; }
    chain prerouting_miniupnpd { }
    chain postrouting_miniupnpd { }
}
EOF
    cat > /etc/miniupnpd/lab.conf <<EOF
ext_ifname=eth0
listening_ip=eth1
ext_allow_private_ipv4=yes
enable_upnp=yes
enable_pcp_pmp=yes
secure_mode=yes
system_uptime=yes
uuid=6f9d3a52-5a0b-4c61-9d1b-2f0e8c7a4b10
allow 1024-65535 $(lan $2).0/24 1024-65535
deny 0-65535 0.0.0.0/0 0-65535
EOF"
    podman exec -d $P-$1 miniupnpd -f /etc/miniupnpd/lab.conf -d
}

# daemon <name> <podman args...> -- <daemon args...>
daemon() {
    local name=$1; shift
    local net=()
    while [[ $1 != -- ]]; do net+=("$1"); shift; done
    shift
    podman run -d --name $P-$name --hostname $name --cap-add NET_ADMIN --cap-add NET_RAW \
        --sysctl net.ipv6.conf.all.disable_ipv6=0 \
        "${net[@]}" $IMAGE cheesecloth daemon --log "${LOG:-info}" "$@" >/dev/null
}

daemon r --network $P-wan:ip=$WAN.10 --sysctl net.ipv4.ip_forward=0 -- --advertise $WAN.10
router ra a $WAN.11 ""
router rb b $WAN.12 ""
router rc c $WAN.13 "fully-random"
router rd d $WAN.14 "fully-random"
upnp rd d
daemon n1 --network $P-lan-a:ip=$(lan a).10 --
daemon n4 --network $P-lan-a:ip=$(lan a).11 --
daemon n2 --network $P-lan-b:ip=$(lan b).10 --
daemon n3 --network $P-lan-c:ip=$(lan c).10 --
daemon n5 --network $P-lan-d:ip=$(lan d).10 --
for n in n1 n4; do ex $n "ip route add default via $(lan a).2"; done
ex n2 "ip route add default via $(lan b).2"
ex n3 "ip route add default via $(lan c).2"
ex n5 "ip route add default via $(lan d).2"

wait_for() {  # wait_for <secs> <command...>
    local deadline=$((SECONDS + $1)); shift
    until "$@" >/dev/null 2>&1; do
        ((SECONDS < deadline)) || return 1
        sleep 1
    done
}
for n in $NODES; do wait_for 20 cc $n status; done
echo "lab up: firewall=$FIREWALL, wan delay=$WAN_DELAY per router, NAT UDP timeout=${NAT_TIMEOUT}s"

# ------------------------------------------------------------------ helpers

json() { cc $1 --json "${@:2}"; }
members() { json $1 status | sed -n 's/.*"members": \([0-9]*\).*/\1/p'; }
has_members() { [[ $(members $1) == "$2" ]]; }
ipv4_of() { json $1 status | sed -n 's/.*"ipv4": "\([0-9.]*\)".*/\1/p'; }
# peer_field <on> <peer-name> <field>
peer_field() {
    json $1 peers | tr -d '\n ' | sed 's/},{/}\n{/g' | grep "\"name\":\"$2\"" \
        | sed -n "s/.*\"$3\":\"\{0,1\}\([^,\"}]*\).*/\1/p"
}
can_ping() { ex $1 "ping -c 1 -W 2 $2 >/dev/null 2>&1"; }
both_ping() { can_ping $1 $(ipv4_of $2) && can_ping $2 $(ipv4_of $1); }

# ------------------------------------------------------------------ tests

cc r init --ipv4-range 100.64.7.0/24 >/dev/null
[[ $(ipv4_of r) == 100.64.7.1 ]] && pass "init creates the cluster" "r is 100.64.7.1" \
    || fail "init creates the cluster" "$(cc r status)"

for n in n1 n2 n3 n4 n5; do
    token=$(cc r invite 2>/dev/null)
    if out=$(cc $n join "$token" 2>&1); then
        pass "$n joins" "$out"
    else
        fail "$n joins" "$out"
    fi
done
if out=$(cc n1 invite 2>/dev/null) && cc n1 join "$out" >/dev/null 2>&1; then
    fail "a member can't join twice"
else
    pass "a member can't join twice"
fi

all_see_6() { for n in $NODES; do has_members $n 6 || return 1; done; }
if wait_for 60 all_see_6; then
    pass "every node sees 6 members"
else
    fail "every node sees 6 members" "$(for n in $NODES; do echo -n "$n=$(members $n) "; done)"
fi

acceptors() { json r status | tr -d '\n ' | sed -n 's/.*"acceptors":\[\([^]]*\)\].*/\1/p' | tr ',' '\n' | grep -c .; }
has_acceptors() { [[ $(acceptors) == "$1" ]]; }
if wait_for 30 has_acceptors 6; then pass "6 acceptors chosen automatically"; else fail "6 acceptors" "$(cc r status)"; fi

protected() { json r status | grep -q '"security": "protected"'; }
if wait_for 30 protected; then pass "six-voter cluster activates protection"; else fail "protected mode" "$(cc r status)"; fi

relay_flag() { json r status | grep -q '"relay": true'; }
if wait_for 30 relay_flag; then pass "r detects it's public and becomes a relay"; else fail "relay auto-detection" "$(cc r status)"; fi

relay_ok=1
for n in n1 n2 n3 n4 n5; do wait_for 30 both_ping $n r || relay_ok=0; done
((relay_ok)) && pass "every NATed node reaches the relay over WireGuard" \
    || fail "NATed nodes reach the relay" "$(cc n1 peers)"

if wait_for 30 both_ping n1 n4 && [[ $(peer_field n1 n4 path) == lan ]]; then
    pass "same-LAN members use their LAN addresses" "n1 sees n4 at $(peer_field n1 n4 wg_endpoint)"
else
    fail "same-LAN members use their LAN addresses" "$(cc n1 peers)"
fi

t0=$SECONDS
if wait_for 90 both_ping n1 n2; then
    pass "NAT-to-NAT path punched through the relay's coordination" \
        "n1 ↔ n2 after ~$((SECONDS - t0))s more; n1 sees n2 at $(peer_field n1 n2 wg_endpoint) ($(peer_field n1 n2 path_state))"
else
    fail "NAT-to-NAT path punched" "$(cc n1 peers; echo; cc n2 peers)"
fi
if wait_for 60 both_ping n4 n2; then pass "second NAT-to-NAT pair punched (n4 ↔ n2)"; else fail "n4 ↔ n2 punched" "$(cc n4 peers)"; fi

[[ $(ex r "cat /proc/sys/net/ipv4/ip_forward") == 0 ]] && pass "the relay never forwards WireGuard (ip_forward=0)" \
    || fail "relay ip_forward" ""

if both_ping n1 n3; then
    fail "fully-random NAT has no direct path (expected limitation)" "unexpectedly connected"
else
    pass "fully-random NAT has no direct path (expected limitation)" "n1 reports: $(peer_field n1 n3 path_state)"
fi

# Port mapping: n5's router maps its WireGuard and control ports, so n5 is
# reachable despite its fully-random NAT, and its dial-back makes it a relay.
mappings() { json n5 status | tr -d '\n' | sed -n 's/.*"port_mappings": *\[\([^]]*\)\].*/\1/p'; }
has_mappings() { [[ $(mappings) == *wireguard* && $(mappings) == *control* ]]; }
if wait_for 90 has_mappings; then
    pass "n5's router grants port mappings" "$(cc n5 status | sed -n 's/^mapped *//p' | paste -sd ',' - | sed 's/,/, /g')"
else
    fail "n5's router grants port mappings" "$(cc n5 status; ex rd 'nft list table inet filter')"
fi
n5_relay() { json n5 status | grep -q '"relay": true'; }
if wait_for 60 n5_relay; then
    pass "a mapped control port makes n5 a relay (confirmed by dial-back)"
else
    fail "n5 becomes a relay through its mapping" "$(cc n5 status)"
fi
if wait_for 60 both_ping n1 n5 && wait_for 30 both_ping n3 n5 && [[ $(peer_field n1 n5 path) == public ]]; then
    pass "nodes reach n5 through its mapped WireGuard port" \
        "n1 sees n5 at $(peer_field n1 n5 wg_endpoint); even n3 (fully-random, unmapped) reaches it"
else
    fail "nodes reach n5 through its mapping" "$(cc n1 peers; cc n5 peers)"
fi

# The control plane works between NATed members: n2 reaches the acceptors
# through the relay.
if out=$(cc n2 invite 2>/dev/null) && [[ $out == cc1* ]]; then
    pass "NATed members can make changes through the relay"
else
    fail "NATed members can make changes" "$out"
fi

# Removal (from a NATed member) propagates everywhere.
n4id=$(json n4 status | sed -n 's/.*"node_id": "\([0-9a-f]*\)".*/\1/p')
n4key=$(ex n4 "wg show cheesecloth0 public-key")
cc n2 remove "${n4id:0:12}" >/dev/null
gone() { [[ $(json n4 status | sed -n 's/.*"phase": "\([a-z]*\)".*/\1/p') == none ]] && ! ex n4 "ip link show cheesecloth0" >/dev/null 2>&1; }
if wait_for 30 gone && wait_for 30 has_members n1 5; then
    pass "a removed node leaves the cluster and drops its interface"
else
    fail "removal" "$(cc n4 status)"
fi
n4_peer_gone() { for n in r n1 n2 n5; do ex $n "wg show cheesecloth0 peers" | grep -qF "$n4key" && return 1; done; return 0; }
if wait_for 20 n4_peer_gone; then
    pass "the other members drop its WireGuard peer"
else
    fail "the other members drop its WireGuard peer" "$(ex n1 "wg show cheesecloth0 peers")"
fi

# Leaving skips approvals, even with approvals_required = 1.
cc r config set approvals_required 1 >/dev/null
if cc n3 leave >/dev/null 2>&1 && wait_for 30 has_members r 4; then
    pass "a member leaves even when approvals are required"
else
    fail "leave" "$(cc r status)"
fi

# A restarted daemon comes back as a member and its paths recover.
podman restart -t 5 $P-n1 >/dev/null
ex n1 "ip route add default via $(lan a).2"
if wait_for 30 has_members n1 4 && wait_for 90 both_ping n1 n2; then
    pass "a restarted node rejoins with its state and re-punches"
else
    fail "restart" "$(cc n1 status; cc n1 peers)"
fi

# `cheesecloth stop` ends n5's daemon cleanly and releases its router mappings.
# n5's daemon is the container's first process, so the container exits with it,
# and the stop command itself may be killed before it prints its answer.
n5_rules() { ex rd "nft list table inet filter" | grep -c "$(lan d)\.10" || true; }
rules_before=$(n5_rules)
cc n5 stop >/dev/null 2>&1 || true
n5_exit=$(timeout 30 podman wait $P-n5 || echo timeout)
if [[ $n5_exit == 0 ]] && podman logs $P-n5 2>&1 | grep -q "shutting down: stop requested"; then
    pass "stop ends the daemon cleanly"
else
    fail "stop ends the daemon cleanly" "exit status: $n5_exit"
fi
if ((rules_before > 0)) && [[ $(n5_rules) == 0 ]]; then
    pass "stop releases n5's router mappings" "$rules_before router rules before, none after"
else
    fail "stop releases n5's router mappings" "$rules_before rules before; now: $(ex rd 'nft list table inet filter')"
fi

echo
if ((failures)); then
    echo "$failures check(s) failed; recent daemon logs:"
    dump_logs
    exit 1
fi
echo "all checks passed"
