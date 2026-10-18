# Firewall

meshly enforces its policy in nftables. This document covers the table it owns, the path a packet takes through
it, how meshly coexists with a host firewall (the *profiles*, iptables and UFW), what it refuses to run alongside,
and Docker.

- [The `inet meshly` table](#the-inet-meshly-table)
- [Packet path](#packet-path)
- [During an invite](#during-an-invite)
- [Per-interface sysctls](#per-interface-sysctls)
- [Profiles](#profiles)
- [iptables and UFW](#iptables-and-ufw)
- [Unsupported configurations](#unsupported-configurations)
- [Docker](#docker)
- [When the table disappears](#when-the-table-disappears)

## The `inet meshly` table

meshly owns exactly one nftables table, `inet meshly`. Outside it, meshly adds a single rule at the top of the
iptables `INPUT` and `OUTPUT` chains (and `FORWARD`, on a node with Docker networks) when the host filters with
iptables or UFW (see [iptables and UFW](#iptables-and-ufw)), and modifies nothing else. Each change replaces the
whole table in a single nft transaction:

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

On a node with Docker networks (here `docker0` and the bridge of a compose network), the table also has the set
`docker_ifs`, more rules in `guard_fwd` and two chains on the postrouting hook, `nat_out` at priority 99 (srcnat − 1)
and `guard_post` at 101 (srcnat + 1). On a node without Docker networks none of this exists, and the table is the
same as before meshly supported Docker (see [Docker](#docker)):

```nft
	set docker_ifs { type ifname; elements = { "br-3f1c2a9b7d01", "docker0" } }

	chain guard_fwd {
		type filter hook forward priority -300; policy accept;
		iifname "meshly0" ct state invalid,untracked counter drop
		oifname "meshly0" ct state invalid,untracked counter drop
		iifname "meshly0" oifname @docker_ifs ct direction original ct status dnat ct original ip daddr 10.100.0.1 meta mark set meta mark | 0x10000000 accept comment "published container port"
		iifname "meshly0" oifname @docker_ifs ct direction reply ct status snat meta mark set meta mark | 0x10000000 accept comment "replies to containers"
		oifname "meshly0" iifname @docker_ifs ct direction original ip daddr @peers meta mark set meta mark | 0x10000000 accept comment "connections from containers"
		oifname "meshly0" iifname @docker_ifs ct direction reply ct status dnat meta mark set meta mark | 0x10000000 accept comment "replies of published container ports"
		iifname "meshly0" counter drop comment "no forwarding from the vpn"
		oifname "meshly0" counter drop comment "no forwarding into the vpn"
	}

	chain nat_out {
		type nat hook postrouting priority 99; policy accept;
		oifname "meshly0" ip saddr != 10.100.0.1 counter snat ip to 10.100.0.1 comment "containers appear as this node"
	}

	chain guard_post {
		type filter hook postrouting priority 101; policy accept;
		oifname "meshly0" ip saddr != 10.100.0.1 counter drop comment "only the vpn address into the vpn"
		oifname "meshly0" iifname @docker_ifs ct direction reply ct status dnat meta l4proto { tcp, udp } ip daddr . meta l4proto . th sport != @allow_in counter drop comment "replies of denied container ports"
	}
```

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
4. `guard_fwd` (forward, priority −300) drops all forwarding from or into `meshly0`. On a node with Docker
   networks, it lets through only the connections of published container ports and of containers (see
   [Docker](#docker)). The peer cannot reach the LAN, a container's own address or anything else behind this
   node.

**Outbound into the tunnel:** `guard_out` sends packets for `meshly0` to `to_vpn`. That chain allows packets that
this node originates and replies to connections the peer was allowed to open. It drops replies of denied
connections and NATed traffic, so the peer cannot obtain responses through any side path. What containers send
into the tunnel is forwarded, not sent by this node: `guard_fwd`, `nat_out` and `guard_post` decide it (see
[Docker](#docker)).

**Other interfaces:** packets to the VPN address or from the VPN range that arrive on any interface other than
`meshly0` (or `lo`) are dropped, so a host on the LAN cannot spoof the peer. WireGuard's cryptokey routing also
binds each peer to its single `/32`.

**WireGuard transport:** the encrypted UDP packets to and from the listen port are only marked (below), never
filtered by meshly. With the mark they pass the integration rule of your host firewall, so the host firewall needs
no rule of its own for the port. A cloud firewall in front of the server still has to let them through.

### The meshly mark

Every packet that meshly's policy accepts gets bit `0x10000000` set in the packet mark. In the native nftables
profile, your own chains use this mark to let meshly traffic through without understanding the VPN themselves; in
iptables and UFW chains, meshly's own rule does the same.
meshly clears the bit at the start of its prerouting and output chains. A mark set by anything else before them, for
example a local process using `SO_MARK`, therefore never passes the integration rule. Your own rules must not set
this bit: a `MARK` rule in `mangle` runs after meshly's chains, and a packet it marks passes the integration rule.
The mark is part of the
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
| `net.ipv4.conf.meshly0.forwarding` | `0`; `1` while the node has Docker networks | Without Docker networks, no routing through the VPN interface (second layer after `guard_fwd`). With them, the kernel must forward between the tunnel and the containers; policy routing becomes the second layer (see [Policy routing](#policy-routing-table-109)) |
| `net.ipv4.conf.meshly0.rp_filter` | `1` | Strict reverse-path filtering |
| `net.ipv4.conf.meshly0.accept_redirects` | `0` | |
| `net.ipv4.conf.meshly0.send_redirects` | `0` | |
| `net.ipv4.conf.meshly0.accept_source_route` | `0` | |
| `net.ipv6.conf.meshly0.disable_ipv6` | `1` | No IPv6 inside the VPN (skipped when the host has no IPv6) |

meshly turns `forwarding` on only after its routing rule exists, and off before it removes the rule. Writing the
global `net.ipv4.ip_forward` sets `forwarding` on every interface, `meshly0` included. Docker writes it whenever it
turns forwarding on: at its first start after each boot, unless forwarding is already on (see the
[threat model](threat-model.md)). Without Docker networks, meshly sees `forwarding=1` as drift and sets `0` again.

## Profiles

Preflight reads the whole ruleset (`nft -j list ruleset`) and classifies every foreign base chain on the
`prerouting`, `input`, `output` and `postrouting` hooks in the `ip`, `ip6` and `inet` families. The iptables
`filter` chains `INPUT` and `OUTPUT` are classified too, but they are not part of the profile: meshly puts its rule
into them itself (see [iptables and UFW](#iptables-and-ufw)). On a node with Docker networks, chains on the
`forward` hook are classified as well. They are never part of the profile either and never stop a command (see
[The forward hook](#the-forward-hook)).

| Status | Meaning |
|---|---|
| `compatible` | The chain cannot drop meshly traffic: policy accept, and no rule that could match it |
| `needs-integration` | The chain may drop meshly traffic: policy drop, or rules that may match it |
| `integrated` | The chain has the integration rule before any rule that could drop meshly traffic |
| `misplaced-integration` | The integration rule exists, but a dropping rule comes before it |
| `unsupported` | The chain may drop meshly traffic and integration is impossible: it belongs to iptables but is not `filter INPUT` or `filter OUTPUT` (a `DROP` in `mangle`, for example), or it runs before meshly (prerouting/output at priority ≤ −180) |

The analysis is conservative. A rule matching a source range that could include the peer's public endpoint, or
`udp dport 53 reject` where an allowed VPN service could be on 53, counts as "may drop". Until a peer is known
(`init`, `invite`, `join`), a rule on the peer's address counts only if it holds an address of the VPN network. A
ban list, such as fail2ban's, never needs integration (see [fail2ban and other ban lists](#fail2ban-and-other-ban-lists)).

The profile is chosen with `--firewall` at `init`/`join`. `auto` (the default) picks `nftables` when any native
nftables chain needs, has, or misplaces integration, and `none` otherwise.

### `none`: no native nftables firewall on the host

The host has no native nftables chain that could drop meshly traffic. This covers most fresh VPS images, Docker
hosts that run only Docker's own chains, hosts that filter only with iptables or UFW, and hosts with fail2ban. Without iptables rules,
meshly's table is the entire policy for VPN traffic. If a native filtering chain appears later, `meshly doctor`
reports it as a problem.

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

## iptables and UFW

UFW is a front end to iptables. On Debian 12 and Ubuntu 24.04, iptables writes its rules into nftables tables (the
`iptables-nft` backend, the default): `ip filter` and `ip6 filter`. meshly handles them the same way whatever wrote
the rules: UFW, `iptables-persistent`, or a script.

Into every `filter` chain `INPUT` and `OUTPUT`, IPv4 and IPv6, that has a `DROP` policy or any rule, meshly puts
one rule at the top and keeps it there:

```text
-A INPUT -m mark --mark 0x10000000/0x10000000 -m comment --comment "meshly:v1 integration" -j ACCEPT
```

It is the integration rule of the `nftables` profile, added by meshly itself. It accepts only packets that meshly's
table already accepted: VPN traffic allowed by `meshly allow`, and the WireGuard transport on the listen port. You
need no `ufw allow 51820/udp` and no rule for the VPN. Your rules still decide all other traffic: a port that UFW
opens to the internet stays closed to the peer through the VPN until `meshly allow` opens it.

While the node has Docker networks, meshly keeps the same rule at the top of the IPv4 `filter` chain `FORWARD`
too. Docker sets the policy of that chain to `DROP` when it turns forwarding on itself, and UFW does the same; the
rule lets through the container traffic that meshly accepted ([Docker](#docker)). Docker's `DOCKER-USER` chain and
UFW's rules therefore never see it: on the VPN, meshly decides, as on `INPUT`. Without Docker networks, meshly keeps
no rule in `FORWARD` and removes one left over. The IPv6 `FORWARD` chain never carries VPN traffic and gets no
rule.

meshly writes no file of UFW or iptables: the rule lives in the kernel. `ufw status` does not list it;
`iptables -S INPUT` shows it. `meshly status` shows each chain as `ok`, `MISSING` or `NOT FIRST`. `meshly stop` and
`meshly reset` remove the rule.

If you save the iptables rules (`netfilter-persistent save`), the saved file contains meshly's rule too. While meshly
is installed this does no harm: at boot meshly replaces the restored copy, or removes it when the link is stopped.
After `meshly reset` it would come back at every boot, so `reset` warns when `/etc/iptables/rules.v4` or `rules.v6`
contains it: run `sudo netfilter-persistent save` again to save the rules without it.

The rule can disappear when something reloads the iptables rules. meshly puts it back:

| Event | What happens |
|---|---|
| `ufw allow`, `ufw reload`, `ufw disable` and `enable`, `systemctl restart ufw` | Nothing: UFW rewrites only its own `ufw-*` chains, and the rule stays |
| Reboot | UFW and netfilter-persistent load their rules before `network-pre.target`; `meshly.service` starts after them and adds the rule |
| `systemctl restart netfilter-persistent` | `iptables-restore` removes the rule; the drop-in `/etc/systemd/system/netfilter-persistent.service.d/50-meshly.conf` asks `meshly.service` to put it back at once |
| Docker starts or restarts | Docker inserts its own jumps at the top of `FORWARD`; the drop-in `/etc/systemd/system/docker.service.d/50-meshly.conf` asks `meshly.service` to re-apply once Docker is up, and meshly's rule is first again |
| A Docker network is created (`docker network create`, `docker compose up`) | Docker puts its jumps at the top of `FORWARD` again; `meshly-watch.service` moves meshly's rule back within seconds |
| `iptables-restore` or `netfilter-persistent reload` by hand, `iptables -F` | `meshly-check.timer` puts it back within about a minute |
| A rule inserted above it (`iptables -I INPUT 1 …`) | `meshly-check.timer` moves meshly's rule back to the top |
| UFW enabled after meshly | `meshly-check.timer` adds the rule within about a minute; `sudo systemctl reload meshly` adds it at once |

`meshly-watch.service` runs with `meshly.service` on every node, not only on Docker hosts. It follows the changes of
the network interfaces and of nftables, iptables-nft's included, and runs the same check as `meshly-check.timer` a
second after they settle (at most 5 seconds after the first one). So the rows that name the timer usually take
seconds, not a minute; the timer stays as the fallback. The watch's output is in `journalctl -u meshly-watch`.

Until the rule is back, VPN packets meet your own rules and your `DROP` policy: the VPN **fails closed**. Ports
that your firewall opens on all interfaces stay as reachable to the peer as to any internet host.

meshly integrates only `filter INPUT` and `filter OUTPUT`, and `ip filter FORWARD` on a node with Docker networks.
A chain of another iptables table that may drop meshly traffic (a `DROP` in `mangle`, for example) is refused, and
so are rules of the legacy backend (see below). On the forward hook, such a chain is only a warning (see
[The forward hook](#the-forward-hook)).

`TestUFW` checks this with real UFW 0.36.2 on Debian 12 and Ubuntu 24.04, `TestIptablesHost` with hand-written
iptables rules, and `TestSystemdUFW` across a reboot and a restart of `netfilter-persistent.service`. With a real
Docker daemon, `TestDockerAfterMeshly` checks the `FORWARD` rule after Docker starts and restarts,
`TestDockerNetworkLifecycle` after a new network, and `TestDockerUFW` with UFW (see [testing.md](testing.md)).

## fail2ban and other ban lists

fail2ban bans an address by adding it to a named set. With its `nftables` actions, the default on Ubuntu 24.04, the
sets and the rules that use them are in the table `inet f2b-table`:

```nft
table inet f2b-table {
	set addr-set-sshd {
		type ipv4_addr
		elements = { 192.0.2.66 }
	}

	chain f2b-chain {
		type filter hook input priority filter - 1; policy accept;
		tcp dport 22 ip saddr @addr-set-sshd reject with icmp port-unreachable
	}
}
```

meshly treats such a rule as a ban list: it drops packets whose source address (on output, the destination) is in a
named set, and the set holds no range that overlaps the VPN network. A ban list needs no integration rule, because
it drops meshly traffic only from the addresses in the set. The same holds for sshguard, CrowdSec's nftables bouncer
and your own blocklists.

The bans hold for traffic through meshly too: a peer that fails SSH logins through the VPN is banned like any other
address. While a ban hits a peer (its VPN address or its endpoint), commands that check the firewall and
`meshly doctor` warn, but never refuse:

```text
meshly: warning: firewall-ban: fail2ban has banned 10.100.0.2 (peer home) in set addr-set-sshd of table inet f2b-table: its traffic through meshly is dropped until the ban ends
         fix: sudo fail2ban-client unban 10.100.0.2   (to never ban it, add it to ignoreip in /etc/fail2ban/jail.local)
```

fail2ban's jails match only TCP by default (also its "all ports" actions), so its bans do not touch the WireGuard
transport.

Two kinds of sets are not ban lists. A set that holds a range over the VPN network (a "drop private sources" set
with `10.0.0.0/8`, for example) would drop all VPN traffic, and an anonymous set written in the rule
(`ip saddr { … } drop`) is judged like any other match. Preflight reports their chains as it reports any other chain
that may drop meshly traffic.

With fail2ban's iptables actions (`iptables-multiport`, the default on Debian 12) its jumps are in the iptables
`INPUT` chain, below meshly's rule (see [iptables and UFW](#iptables-and-ufw)), so its bans do not apply to traffic
that meshly accepted. When fail2ban starts, it inserts its jump above meshly's rule; `meshly-check.timer` moves
meshly's rule back to the top.

`TestFail2ban` checks this with real fail2ban 1.0.2 and its nftables actions on Debian 12 and Ubuntu 24.04, and
`TestFail2banIptables` with its iptables actions (see [testing.md](testing.md)).

## Unsupported configurations

These are detected before any change. `init`, `invite` and `join` then exit with code 3 and change nothing.

| Configuration | Why |
|---|---|
| **firewalld** active | firewalld rewrites its tables on its own schedule and has no meshly adapter in this version |
| **iptables-legacy** rules (also UFW on the legacy backend) | Invisible to nftables. meshly cannot analyse them. Switch to the default backend: `update-alternatives --set iptables /usr/sbin/iptables-nft` (and `ip6tables`), then reload the rules |
| **iptables-nft** chains outside `filter INPUT`/`OUTPUT` that may drop meshly traffic (a `DROP` in `mangle`, …) | meshly integrates only the `filter` chains `INPUT` and `OUTPUT` (and `ip filter FORWARD`, for containers) |
| Foreign chains before meshly (prerouting/output at priority ≤ −180) that may drop | They run before meshly's guard, so no integration rule can help |
| A **flowtable** containing `meshly0` | Offloaded flows bypass the policy |
| A foreign table named `inet meshly` | Ownership conflict (exit code 5) |

`netdev` chains are reported as a warning: they run before everything else and may drop the WireGuard transport.
Chains on the forward hook are never refused, whatever they contain (see [The forward hook](#the-forward-hook)).

## Docker

meshly treats a running container like a program installed on the server. A port that Docker publishes is a port
of the server, and a container that connects somewhere is a program that connects somewhere. `meshly allow` is the
only thing to do:

```yaml
services:
  mysqld-exporter:
    image: prom/mysqld-exporter
    ports: ["9104:9104"]
```

```console
admin@vps:~$ docker compose up -d
admin@vps:~$ sudo meshly allow 9104/tcp from home
```

A Prometheus container on home, on its usual bridge network, can now scrape `10.100.0.1:9104`. Nothing else is
needed: no meshly flag, no change to the compose file or to `daemon.json`, and no command after `docker compose up`,
`down` or a recreated container. Docker can be installed before or after meshly and restarted at any time.

- **Published ports.** A port published with `-p` or `ports:` on all addresses or on this node's VPN address is
  reachable by the peer after `meshly allow <port>/<proto> from <peer>`, exactly like the port of a program on the
  host. The port in `allow` is the host port: the left number of `-p 9104:9104`. `meshly deny` and `revoke` close
  it, connections that are already established included.
- **Containers as clients.** A container connects to the peer's VPN address like a program on the host, to the
  ports that the peer allows this node: services of the peer's host and ports published by the peer's containers.
  The peer sees this node's VPN address as the source, never a container's address.
- **New networks.** A new Docker network, for example of a new compose project, works through the tunnel within
  seconds, without a command (see [Docker networks](#docker-networks)).

What stays closed, as for programs on the host:

- the LAN behind this node and any other host, also when a DNAT rule on an allowed port points there;
- a container's own address (`172.18.0.5`), and container ports that are not published;
- a port published only on `127.0.0.1`, like a program that listens on localhost only;
- every port without `meshly allow`;
- the tunnel, for anything forwarded from the LAN or from any other interface that is not a Docker network;
- this node's own VPN address, for its own containers. `guard_pre` drops packets for it that come from a bridge:
  letting them through with meshly's mark would open every port of the host to the containers, past the host
  firewall. A container reaches its own host as usual in Docker, through the gateway address of its bridge (for
  example with `--add-host host.docker.internal:host-gateway`).

### Publishing a port only to the VPN

`-p 9104:9104` publishes the port on all addresses, so it is open to the internet too: Docker's rules bypass UFW,
and meshly does not change that. To publish a port only to the VPN, bind it to this node's VPN address, which
`meshly status` shows:

```sh
docker run -d -p 10.100.0.1:9104:9104 prom/mysqld-exporter
```

In compose, that is `ports: ["10.100.0.1:9104:9104"]`. Docker binds this address when it starts the container, so
the address must exist at that moment. While the meshly interface does not exist (after `meshly stop`, or in safe
mode), a container that starts or restarts fails with `cannot assign requested address`. Docker 29.9.1 then also
disconnects the container from its network, and starting it again runs it without one. So once the link is up,
create the container again: `docker rm -f` and `docker run`, or `docker compose up -d --force-recreate`. At boot this
is not a problem while the link is meant to run: `meshly.service` comes up before `network-online.target`, and
`docker.service` starts after it.

### Packet path through the tunnel

**Peer → published port.** The peer connects to `10.100.0.1:9104`, which Docker publishes from a container at
`172.18.0.5`:

1. `guard_pre` and `from_vpn` (priority −180, before DNAT) check the packet as for any port of the host: the peer's
   address, this node's VPN address and `allow_in`, on every packet. An accepted packet gets meshly's mark.
2. Docker's DNAT (−100) rewrites the destination to the container.
3. The kernel forwards the packet: `forwarding` is `1` on `meshly0`, and [policy routing](#policy-routing-table-109)
   knows only Docker networks. `guard_fwd` accepts it only from `meshly0` into a bridge in `@docker_ifs`, for a
   connection in the original direction that DNAT rewrote and whose original destination is this node's VPN
   address ("published container port"). Everything else from the tunnel hits "no forwarding from the vpn".
4. The container's reply is forwarded from the bridge into `meshly0` ("replies of published container ports").
   After Docker's NAT has restored its source to `10.100.0.1:9104` on postrouting, `guard_post` drops it if the
   peer, protocol and port are no longer in `allow_in` ("replies of denied container ports"). So `meshly deny` stops
   the replies too, as `to_vpn` does for the services of the host.

**Container → peer.** A container at `172.18.0.7` connects to `10.100.0.2:3100`:

1. The packet comes from a bridge and is forwarded into `meshly0`. `guard_fwd` accepts it only in the original
   direction, from `@docker_ifs` to an address in `@peers` ("connections from containers").
2. `nat_out` (srcnat − 1, before Docker's masquerade) rewrites the source to this node's VPN address ("containers
   appear as this node"). It does not rely on Docker's masquerade, which can be turned off per network.
   `guard_post` drops anything that would leave through `meshly0` with another source ("only the vpn address into
   the vpn").
3. The peer's own policy decides, as for a program on this host.
4. The peer's reply passes `from_vpn` as a reply to a connection of this node. NAT gives it the container's address
   back, and `guard_fwd` forwards it to the bridge ("replies to containers").

Before these rules, `guard_fwd` drops forwarded packets from or into `meshly0` in conntrack state `invalid` or
`untracked`. Every packet it accepts gets meshly's mark, so it passes the integration rule of the host firewall
(see [The forward hook](#the-forward-hook)).

### Policy routing (table 109)

Both paths need `forwarding=1` on `meshly0`, so on a node with Docker networks that sysctl is no longer a second
layer. Policy routing takes its place:

```text
rule       iif meshly0 lookup 109          (priority 109, protocol 109)
table 109  172.17.0.0/16 dev docker0
           172.18.0.0/16 dev br-3f1c2a9b7d01
           unreachable default
```

Whatever the kernel would forward from the tunnel is routed with table 109, which knows only the subnets of the
Docker bridges. The LAN, the other interfaces and the internet have no route from the tunnel, also while table
`inet meshly` is missing (after a foreign `nft flush ruleset`, until meshly re-applies it) and when the policy of
`FORWARD` accepts. Packets for this node's own VPN address are delivered through the `local` table, which the kernel
consults before this rule, so they are not affected.

- meshly owns the rule and the routes by their protocol, `109`, as it owns its other routes. The subnets are taken
  from the addresses of the bridges and follow them. Every check compares the rule and the routes and repairs them
  as drift.
- Without Docker networks there is neither the rule nor a route in table 109. On a node with Docker networks,
  routes of another program in table 109 are a conflict (exit code 5); without Docker networks meshly leaves the
  table alone.
- The rule exists before `forwarding` goes on, and is removed only after `forwarding` is off, also when a step
  fails.
- The rule does not change the reverse-path check (`rp_filter`) of packets that come from the tunnel: the kernel
  does not look up their source as coming from `meshly0`. It does change the check of packets that would be
  forwarded *into* the tunnel, whose source the kernel looks up as if it came from `meshly0`, so in table 109. On a
  host with `rp_filter` on (`1` or `2`; Ubuntu sets `2`), a packet from the LAN to the tunnel therefore has no
  reverse path and is dropped before the forward hook. Containers are not affected: table 109 routes their subnets
  back to their bridges.

`TestDockerHostContained` checks this layer with real packets, also without the meshly table and without the rule
(where `guard_fwd` alone drops), and `TestDockerNetworkLifecycle` checks that rule and routes follow the networks.

### The forward hook

Forwarded packets also pass the forward chains of the host firewall. meshly marks the packets it accepts and keeps
its rule at the top of `ip filter FORWARD`, whose policy Docker and UFW set to `DROP` (see
[iptables and UFW](#iptables-and-ufw)); `meshly status` shows whether it is first. While the node has Docker
networks, preflight and `meshly doctor` also analyse the other chains on the forward hook. A problem there concerns
containers only: the tunnel between the hosts does not pass the forward hook. So whatever may drop container traffic
there is a warning (`firewall-forward`) with the fix, never a refusal, in both profiles: `init`, `allow` and
`service start` go on.

| Chain | Finding | Fix |
|---|---|---|
| A native nftables chain that may drop container traffic, for example `chain forward` with `policy drop` in your `table inet filter` | warning | Add the integration rule to that chain before any drop or reject rule, as `doctor` prints it: `meta mark & 0x10000000 == 0x10000000 accept comment "meshly"`. The same in both profiles |
| A chain that meshly cannot integrate: one of another iptables table that may drop (a `DROP` in `mangle FORWARD`), or one at priority −300 or lower, which runs before `guard_fwd` | warning: containers cannot use the VPN through this chain | Remove or narrow the rule that drops |
| The chains of Docker's own nftables firewall backend (table `ip docker-bridges`) | information | — |

Docker's nftables firewall backend (`"firewall-backend": "nftables"` in `/etc/docker/daemon.json`) works with meshly
as its iptables rules do. With Docker CE 29.9.1 on Debian 12 and Ubuntu 24.04, a published port is closed until
`allow` and reachable after it, and containers reach the peer (`TestDockerNftablesBackend`). `doctor` lists Docker's
chains as information, because rules you add to them can still block container traffic.

`TestDockerNativeForwardChain` checks a native forward chain with `policy drop`: the tunnel between the hosts keeps
working, `doctor` warns and prints the rule, and once the rule is added the published port works.

### Docker networks

meshly finds the Docker networks itself, in the kernel. A Docker network is an interface of kind `bridge` named
`docker0` or `br-` plus 12 hexadecimal digits: the names Docker gives its default network and every user-defined or
compose network. meshly does not use the Docker API or `docker.sock`, and does not need Docker running. Bridges of
other programs (`br-lan`, `vmbr0`, `virbr0`, `lxdbr0`, `podman0`) do not match.

The networks are part of the desired state, besides the configuration. A network that appears or goes away is
drift, and meshly repairs it in a journaled `check-repair` operation that names the change, for example
`Docker networks changed: +br-3f1c2a9b7d01` in `meshly logs`:

- `meshly-watch.service` applies a change within seconds of the bridge appearing or going. If another meshly
  command or an open `meshly invite` holds the lock, it waits and applies the change right after.
  `meshly-check.timer` repairs the same within a minute when the watch is not running.
- The drop-in `/etc/systemd/system/docker.service.d/50-meshly.conf` re-applies meshly after Docker starts.
- Until meshly has applied a new network, its containers cannot use the tunnel: a bridge that is not in the table
  stays closed.

`meshly status` lists the networks (`docker networks`), and `meshly doctor` names them in its `docker` finding.
When the ruleset has Docker's rules but no bridge with one of Docker's names, `doctor` warns instead.

Not supported:

- networks with a custom bridge name (`com.docker.network.bridge.name`): their containers cannot use the VPN;
- macvlan, ipvlan and overlay (swarm) networks; Podman, containerd/nerdctl, LXC/LXD, Kubernetes and the bridges of
  virtual machines;
- reaching a container by its address, a port that is not published, or a whole Docker network from the peer;
- IPv6 inside the VPN, as for the host.

Containers on the host's network (`--network host`) use the network of the host and are programs on the host in every
respect.

The integration tests run a real Docker daemon in the lab nodes on Debian 12 and Ubuntu 24.04: Docker CE from
download.docker.com, 29.9.1 when this was written (see [testing.md](testing.md) and the
[threat model](threat-model.md)).

## When the table disappears

`systemctl restart nftables`, `nft flush ruleset` or another tool can remove the meshly table. meshly reacts as
follows:

- **Restart or start of `nftables.service`:** meshly installs a drop-in,
  `/etc/systemd/system/nftables.service.d/50-meshly.conf`. Right after nftables loads its ruleset, it asks
  `meshly.service` to re-apply the table. Through `PartOf=`, stopping or restarting nftables also stops or restarts
  meshly.
- **`systemctl reload nftables`** propagates to `meshly.service` (`ReloadPropagatedFrom=`), which re-applies the
  table.
- **Anything else** (a manual `nft flush ruleset`, another tool): `meshly-watch.service` sees the nftables change
  and re-applies the table, usually within seconds; `meshly-check.timer` notices the missing or modified table
  within about a minute if the watch did not.

Until the table is back:

- With profile **`nftables`**, VPN traffic is blocked: no mark, so your `policy drop` applies.
- With profile **`none`**, nothing filters the VPN interface unless iptables or UFW do. Without them, during that
  window, the peer can reach every host service that listens on all addresses (`0.0.0.0`). The window lasts until the
  watch or the next check re-applies the table (usually seconds, at most about a minute), or is near zero after a
  `systemctl restart nftables`. If that window is unacceptable, use the
  `nftables` profile with a `policy drop` input chain, or bind host services to specific addresses. The
  [threat model](threat-model.md) lists this as a known limitation.
- On a node with Docker networks, in either profile, the peer can also reach the ports that Docker publishes on all
  addresses or on the VPN address, unless a forward chain of your own drops them: Docker's rules let them through,
  as they let the former through from the internet. The LAN stays closed, because
  [policy routing](#policy-routing-table-109) does not depend on the table. Container addresses do have a route
  then, and only Docker's own rules keep them closed (the tested Docker drops packets for a container that arrive on
  another interface).

If `/etc/nftables.conf` starts with `flush ruleset`, `meshly doctor` points out this window. Replacing it with
`table inet filter; delete table inet filter` (one pair per table you define) reloads your ruleset without
touching the meshly table.

The integration tests cover the following (`TestSystemdLifecycle`, `TestNativeNftablesProfile`,
`TestDockerHostContained`):

- start, reload and restart of `nftables.service` with a `flush ruleset` config;
- the check restoring a deleted table;
- a native nftables ruleset that fails closed;
- a Docker host without the table, whose LAN stays closed to the peer.
