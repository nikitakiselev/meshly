# Firewall

meshly enforces its policy in nftables. This document covers the table it owns, the path a packet takes through
it, how meshly coexists with a host firewall (the *profiles*), what it refuses to run alongside, and Docker.

- [The `inet meshly` table](#the-inet-meshly-table)
- [Packet path](#packet-path)
- [During an invite](#during-an-invite)
- [Per-interface sysctls](#per-interface-sysctls)
- [Profiles](#profiles)
- [Unsupported configurations](#unsupported-configurations)
- [Docker](#docker)
- [When the table disappears](#when-the-table-disappears)

## The `inet meshly` table

meshly owns exactly one nftables table, `inet meshly`, and never modifies any other table or chain. Each change
replaces the whole table in a single nft transaction:

```text
table inet meshly          # make the delete below valid if the table does not exist
delete table inet meshly
table inet meshly { … }    # the new definition
```

The kernel applies the script atomically. Packets see either the old or the new policy, never a mix. The script is
passed on stdin to `/usr/sbin/nft -f -` (fixed path, fixed arguments, no shell). Every value in it is a validated,
typed value, so a configuration value can never inject nft syntax.

The first rule of `guard_pre` carries an ownership marker comment, `meshly:v1 net=<network id> hash=<policy hash>`.
meshly treats a table named `inet meshly` as its own only when the marker matches. A foreign table with the same
name is a conflict (exit code 5), not something to overwrite. The hash covers the whole policy, so status and the
check timer can tell when the table was modified outside meshly.

This is the table for a node `10.100.0.1` with peer `10.100.0.2` and the rules `allow 22/tcp`, `allow 53/udp` and
`allow ping` from that peer:

```nft
table inet meshly {
	comment "managed by meshly; do not edit (network 0123456789abcdef0123456789abcdef)"

	set peers      { type ipv4_addr; elements = { 10.100.0.2 } }
	set allow_in   { type ipv4_addr . inet_proto . inet_service; elements = { 10.100.0.2 . tcp . 22, 10.100.0.2 . udp . 53 } }
	set allow_ping { type ipv4_addr; elements = { 10.100.0.2 } }

	chain guard_pre {
		type filter hook prerouting priority -180; policy accept;
		meta mark & 0x10000000 == 0x10000000 meta mark set meta mark & 0xefffffff comment "meshly:v1 net=… hash=…"
		iifname "meshly0" jump from_vpn
		iifname != { "lo", "meshly0" } ip daddr 10.100.0.1 counter drop comment "vpn address reachable only through the vpn"
		iifname != { "lo", "meshly0" } ip saddr 10.100.0.0/24 counter drop comment "spoofed vpn source"
		udp dport 51820 fib daddr type local counter meta mark set meta mark | 0x10000000 comment "wireguard transport"
	}

	chain from_vpn {
		meta nfproto != ipv4 counter drop comment "no ipv6 inside the vpn"
		ip saddr != @peers counter drop comment "unknown or spoofed peer address"
		ip daddr != 10.100.0.1 counter drop comment "only the local vpn address"
		ct state invalid,untracked counter drop
		ct direction reply ct state established meta mark set meta mark | 0x10000000 accept comment "replies to locally initiated connections"
		ct state related icmp type { destination-unreachable, time-exceeded, parameter-problem } meta mark set meta mark | 0x10000000 accept
		ct direction original meta l4proto { tcp, udp } ip saddr . meta l4proto . th dport @allow_in meta mark set meta mark | 0x10000000 accept
		ct direction original icmp type echo-request ip saddr @allow_ping meta mark set meta mark | 0x10000000 accept
		counter drop comment "default deny"
	}

	chain guard_in {
		type filter hook input priority -180; policy accept;
		iifname "meshly0" ip daddr != 10.100.0.1 counter drop comment "rewritten destination"
		iifname "meshly0" ct status dnat counter drop comment "dnat from the vpn is not supported"
	}

	chain guard_fwd {
		type filter hook forward priority -300; policy accept;
		iifname "meshly0" counter drop comment "no forwarding from the vpn"
		oifname "meshly0" counter drop comment "no forwarding into the vpn"
	}

	chain guard_out {
		type filter hook output priority -180; policy accept;
		meta mark & 0x10000000 == 0x10000000 meta mark set meta mark & 0xefffffff
		oifname "meshly0" jump to_vpn
		udp sport 51820 meta mark set meta mark | 0x10000000 comment "wireguard transport"
	}

	chain to_vpn {
		meta nfproto != ipv4 counter drop
		ip saddr != 10.100.0.1 counter drop
		ip daddr != @peers counter drop
		ct state invalid,untracked counter drop
		ct direction original meta mark set meta mark | 0x10000000 accept comment "locally initiated"
		ct status & (snat | dnat) != 0 counter drop
		ct direction reply ct state established meta l4proto { tcp, udp } ip daddr . meta l4proto . th sport @allow_in meta mark set meta mark | 0x10000000 accept
		ct direction reply ct state established icmp type echo-reply ip daddr @allow_ping meta mark set meta mark | 0x10000000 accept
		ct state related icmp type { destination-unreachable, time-exceeded, parameter-problem } meta mark set meta mark | 0x10000000 accept
		counter drop comment "replies of denied connections"
	}
}
```

The sets are condensed here for reading. `meshly allow … --dry-run` prints the exact table for your node.

## Packet path

**Inbound through the tunnel** (a packet that WireGuard decrypted on `meshly0`):

1. `guard_pre` (prerouting, priority −180) runs after conntrack (−200) and before mangle (−150) and DNAT (−100).
   The policy therefore sees the *original* destination, before any DNAT rule (Docker's included) can rewrite it.
2. `from_vpn` allows only IPv4 from a known peer address to this node's own VPN address. Inside those limits it
   accepts:
   - replies to connections this node started;
   - ICMP errors related to them;
   - new or established flows that match `allow_in` exactly (peer, protocol, port);
   - echo requests from peers in `allow_ping`.

   Everything else is dropped. The allow check runs on **every packet**, not only on the first one of a
   connection, so `meshly deny` stops established flows immediately.
3. `guard_in` (input) drops anything whose destination was rewritten on the way: DNAT or REDIRECT from the
   tunnel is refused. While an invite waits, it also guards the pairing port (see
   [During an invite](#during-an-invite)).
4. `guard_fwd` (forward, priority −300) drops all forwarding from or into `meshly0`. The peer can never reach the
   LAN, Docker networks or anything behind this node.

**Outbound into the tunnel:** `guard_out` sends packets for `meshly0` to `to_vpn`. That chain allows packets that
this node originates and replies to connections the peer was allowed to open. It drops replies of denied
connections and NATed traffic, so the peer cannot obtain responses through any side path.

**Other interfaces:** packets to the VPN address or from the VPN range that arrive on any interface other than
`meshly0` (or `lo`) are dropped, so a host on the LAN cannot spoof the peer. WireGuard's cryptokey routing also
binds each peer to its single `/32`.

**WireGuard transport:** the encrypted UDP packets to and from the listen port are only marked (below), never
filtered by meshly. Your own firewall decides whether the port is reachable.

### The meshly mark

Every packet that meshly's policy accepts gets bit `0x10000000` set in the packet mark. In the native nftables
profile, your own chains use this mark to let meshly traffic through without understanding the VPN themselves.
meshly clears the bit at the start of its prerouting and output chains. A mark set by anything else, for example
a local process using `SO_MARK`, therefore never passes the integration rule. The mark is part of the
configuration (`firewall.mark`, exactly one bit). This version always uses `0x10000000` and has no command to
change it.

## During an invite

While `meshly invite` waits, the table of the inviting node carries temporary elements and one temporary rule for
the address the joining node will get (here `10.100.0.2`). With no peer yet, the sets and `guard_in` look like
this:

```nft
	set peers      { type ipv4_addr; elements = { 10.100.0.2 } }
	set allow_in   { type ipv4_addr . inet_proto . inet_service; elements = { 10.100.0.2 . tcp . 51820 } }

	chain guard_in {
		type filter hook input priority -180; policy accept;
		iifname "meshly0" ip daddr != 10.100.0.1 counter drop comment "rewritten destination"
		iifname "meshly0" ct status dnat counter drop comment "dnat from the vpn is not supported"
		ip daddr 10.100.0.1 tcp dport 51820 iifname . ip saddr != { "meshly0" . 10.100.0.2 } counter drop comment "reachable only from its peer through the vpn"
	}
```

The set elements let the joining node reach the pairing port, TCP 51820 on this node's VPN address, through the
temporary WireGuard tunnel, and nothing else. Only a node that has the invite code can send from `10.100.0.2`
through `meshly0`, and `guard_pre` drops packets for the VPN address that arrive on any other interface but `lo`,
so the port is not reachable from the internet or the LAN. In profile `nftables` these packets carry the mark like
any other allowed VPN traffic.

The last rule of `guard_in` closes the port to the processes of this node, root's included. They reach the VPN
address over `lo`, which `guard_pre` lets through as local traffic. The rule drops every packet for TCP 51820 on
the VPN address unless it arrives on `meshly0` from `10.100.0.2`: from `lo`, from any other interface, after DNAT,
and also with a forged source `10.100.0.2` that did not come through the tunnel. It is in `guard_in` because the
input hook sees local traffic too, and sees the destination after DNAT. The listener is a second layer: it closes
every connection whose source is not `10.100.0.2` without reading or answering it.

`TestPairingClosedToLocalUsers` checks this on a real kernel. As `nobody` and as root on the inviting node, a
connection to `10.100.0.1:51820` fails, and the rule's counter grows with each attempt. With the rule deleted, the
same connection succeeds, so the rule alone keeps the port closed; a `hello` sent then gets no answer, and the
invite keeps waiting. `TestRenderExclusive` and `TestOverlayPeerAndAllow` check that the rule exists only while
the invite's temporary state is applied, and that without it the table is exactly the table of the saved
configuration.

The joining node's own temporary table has the inviting node's address in `@peers` and no allow rule: its
connection to the pairing port is locally initiated, and the replies come back as such.

The temporary elements and the rule are never saved in the configuration. They go when the invite ends, in every
way it can end. If the invite was killed, `meshly-check.timer` removes them within a minute, and `sudo meshly
start` removes them at once. `meshly status` shows the table as present *with the open invite's temporary rules*
while the invite waits.

## Per-interface sysctls

meshly sets these on `meshly0` only. It changes no global sysctl.

| Sysctl | Value | Why |
|---|---|---|
| `net.ipv4.conf.meshly0.forwarding` | `0` | No routing through the VPN interface (second layer after `guard_fwd`) |
| `net.ipv4.conf.meshly0.rp_filter` | `1` | Strict reverse-path filtering |
| `net.ipv4.conf.meshly0.accept_redirects` | `0` | |
| `net.ipv4.conf.meshly0.send_redirects` | `0` | |
| `net.ipv4.conf.meshly0.accept_source_route` | `0` | |
| `net.ipv6.conf.meshly0.disable_ipv6` | `1` | No IPv6 inside the VPN (skipped when the host has no IPv6) |

## Profiles

Preflight reads the whole ruleset (`nft -j list ruleset`) and classifies every foreign base chain on the
`prerouting`, `input`, `output` and `postrouting` hooks in the `ip`, `ip6` and `inet` families:

| Status | Meaning |
|---|---|
| `compatible` | The chain cannot drop meshly traffic: policy accept, and no rule that could match it |
| `needs-integration` | The chain may drop meshly traffic: policy drop, or rules that may match it |
| `integrated` | The chain has the integration rule before any rule that could drop meshly traffic |
| `misplaced-integration` | The integration rule exists, but a dropping rule comes before it |
| `unsupported` | The chain is managed by iptables, or it runs before meshly (prerouting/output at priority ≤ −180), so integration is impossible |

The analysis is conservative. A rule matching a source range that could include the peer's public endpoint, or
`udp dport 53 reject` where an allowed VPN service could be on 53, counts as "may drop".

The profile is chosen with `--firewall` at `init`/`join`. `auto` (the default) picks `nftables` when any chain
needs, has, or misplaces integration, and `none` otherwise.

### `none`: no filtering firewall on the host

The host has no chain that could drop meshly traffic, which covers most fresh VPS images and Docker hosts that run
only Docker's own chains. meshly's table is the entire policy for VPN traffic. If a filtering chain appears later,
`meshly doctor` reports it as a problem.

### `nftables`: your own nftables ruleset

The host has its own ruleset, typically `/etc/nftables.conf` with `policy drop` on input. You add one rule to each
chain that preflight reports, before any rule that drops or rejects:

```nft
meta mark & 0x10000000 == 0x10000000 accept comment "meshly"
```

`meshly doctor` prints this rule for every chain that needs it, with the right mark if you changed it. For example:

```nft
table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		meta mark & 0x10000000 == 0x10000000 accept comment "meshly"
		ct state established,related accept
		iif "lo" accept
		tcp dport 22 accept
	}
}
```

The rule accepts only packets that meshly's own policy already accepted: VPN traffic allowed by `meshly allow`, and
the WireGuard transport on the listen port. Your firewall still decides everything else, and meshly keeps deciding
everything on the VPN.

This profile **fails closed**: if the meshly table is missing, no packet carries the mark, so your `policy drop`
blocks all VPN traffic until meshly re-applies its table.

## Unsupported configurations

These are detected before any change. `init`, `invite` and `join` then exit with code 3 and change nothing.

| Configuration | Why |
|---|---|
| **ufw** enabled | ufw rewrites its iptables chains on its own schedule; meshly cannot guarantee its policy next to them |
| **firewalld** active | Same; firewalld has no meshly adapter in this version |
| **iptables-legacy** rules | Invisible to nftables. meshly cannot analyse them |
| **iptables-nft** chains that may drop meshly traffic (`ip filter INPUT` with policy drop, …) | Managed by iptables, which would remove an integration rule. Not supported in this version |
| Foreign chains before meshly (prerouting/output at priority ≤ −180) that may drop | They run before meshly's guard, so no integration rule can help |
| A **flowtable** containing `meshly0` | Offloaded flows bypass the policy |
| A foreign table named `inet meshly` | Ownership conflict (exit code 5) |

`netdev` chains are reported as a warning: they run before everything else and may drop the WireGuard transport.

## Docker

Docker is supported as a neighbour on a host with profile `none` (Docker's own chains are `compatible`). Through
the tunnel:

- **Published container ports are not reachable** (`docker run -p 8080:80` …). A published port works through
  DNAT. meshly's policy runs before DNAT and allows only this node's own VPN address and the listed ports.
  `guard_in` drops anything whose destination was rewritten. A port forwarded with DNAT to another host is
  forwarded traffic, and `guard_fwd` drops it.
- **Container networks are not reachable.** There is no forwarding from or into `meshly0`.
- To make a container service available to the peer, have it listen on the host itself, with `network_mode: host`
  or a host-level reverse proxy in front of it. Then run `meshly allow <port>/tcp from <peer>`. Publishing on the VPN
  address (`-p 10.100.0.1:8080:80`) still uses DNAT and is therefore refused as well.

`meshly doctor` reports Docker as information with the number of DNAT rules it found. The integration tests check
both Docker-style `dnat` and `redirect` rules from the tunnel with real packets (`TestCompromisedPeerContained`).

## When the table disappears

`systemctl restart nftables`, `nft flush ruleset` or another tool can remove the meshly table. meshly reacts as
follows:

- **Restart or start of `nftables.service`:** meshly installs a drop-in,
  `/etc/systemd/system/nftables.service.d/50-meshly.conf`. Right after nftables loads its ruleset, it asks
  `meshly.service` to re-apply the table. Through `PartOf=`, stopping or restarting nftables also stops or restarts
  meshly.
- **`systemctl reload nftables`** propagates to `meshly.service` (`ReloadPropagatedFrom=`), which re-applies the
  table.
- **Anything else** (a manual `nft flush ruleset`, another tool): `meshly-check.timer` notices the missing or
  modified table within about a minute and re-applies it.

Until the table is back:

- With profile **`nftables`**, VPN traffic is blocked: no mark, so your `policy drop` applies.
- With profile **`none`**, nothing filters the VPN interface. During that window, the peer can reach every host
  service that listens on all addresses (`0.0.0.0`). The window lasts until the next check (at most about a
  minute), or is near zero after a `systemctl restart nftables`. If that window is unacceptable, use the
  `nftables` profile with a `policy drop` input chain, or bind host services to specific addresses. The
  [threat model](threat-model.md) lists this as a known limitation.

If `/etc/nftables.conf` starts with `flush ruleset`, `meshly doctor` points out this window. Replacing it with
`table inet filter; delete table inet filter` (one pair per table you define) reloads your ruleset without
touching the meshly table.

The integration tests cover the following (`TestSystemdLifecycle`, `TestNativeNftablesProfile`):

- start, reload and restart of `nftables.service` with a `flush ruleset` config;
- the check restoring a deleted table;
- a native nftables ruleset that fails closed.
