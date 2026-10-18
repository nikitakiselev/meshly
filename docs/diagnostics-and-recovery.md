# Diagnostics and recovery

This document explains how to read `meshly status` and `meshly doctor`, what
the journal records, how interrupted operations and safe mode are handled,
and what to do when the link or a service stops working. Architecture
background: [architecture.md](architecture.md). Exit codes of all commands:
[cli.md](cli.md). Firewall details: [firewall.md](firewall.md).

## Is the link up?

Start with `sudo meshly nodes`. It shows each other node as one of:

- `online`: a handshake within the last 3 minutes;
- `offline`;
- `never connected`;
- `link stopped`.

It also shows what each node may use on this one.

Then check the path with `sudo meshly ping <node>`. When no reply comes, meshly tells two cases apart:

- the link is down, because there is no recent handshake. Run `meshly doctor`.
- the link works, but the other node does not allow ping. Run `meshly allow ping from <this node>` there.

To check a TCP service rather than ICMP, use `meshly doctor --probe <port>/tcp`.

## `meshly status`

`status` shows the saved configuration and the observed kernel state side by
side. Configuration correctness and connectivity are reported separately: a
node can be configured correctly and still have no handshake because the
peer is switched off.

```
Configuration (saved, revision 4, 2026-10-18T20:31:40Z)
  network      homelab  10.100.0.0/24  (id b5cf94172d66)
  this node    vps  10.100.0.1  udp/51820  endpoint 203.0.113.10:51820
  public key   bWcWhZaUNdCDGVVlpXq8o/ep9g9jtumd2jC7Zsju9C4=
  admin state  up   firewall profile none   2 allow rule(s)
Service
  meshly.service active/enabled, check timer active   (systemd state says nothing about connectivity)
Interface
  meshly0  up, mtu 1420, addresses 10.100.0.1/32, listen udp/51820, key ok
Firewall
  table inet meshly  present, matches config
Peer home
  address 10.100.0.2   public key Z4YzTt5wXZdSfsyoVJhIk0Q8KYaqf3moKZi95pr9DmA=
  wireguard configured, allowed-ips 10.100.0.2/32, route ok, keepalive 25s
  endpoint 198.51.100.20:51820
  connectivity: last handshake 6s ago, rx 180 B, tx 124 B
  may use here: ping, 22/tcp
Transaction
  none pending; last: allow commit at 2026-10-18T20:31:40Z
Drift
  none: kernel state matches the configuration
```

- **public key** is this node's WireGuard public key, and the peer's is in
  its section. The private key is never shown.
- **admin state** is `up` after `init`, `join` or `start` and `down` after
  `meshly stop`.
- **Service** is the systemd state only. `active` means the last start
  succeeded, not that the peer is reachable.
- **Firewall** compares the live `inet meshly` table with the configuration
  (ownership marker hash and the content hash recorded after the last apply).
  On a host with UFW, iptables rules or Docker it also names the iptables
  chains that carry meshly's rule, and whether the rule is first in each
  (`ok`, `NOT FIRST` or `MISSING`). On a host with Docker networks it lists
  them; `status --json` has them in `firewall.docker_networks`:

  ```
  Firewall
    table inet meshly  present, matches config
    iptables chains   meshly rule first: ip filter INPUT ok, ip filter FORWARD ok
    docker networks   br-3f1c2a9b7d01, docker0
  ```
- **connectivity** is one of `handshake-recent` (within 180 s; WireGuard
  re-keys every 120 s while traffic flows), `handshake-stale`, `no-handshake`
  or `unknown` (not observable: interface down or not running as root).
- **Transaction** shows an interrupted operation, if any, and the last
  operation with its outcome.
- **Drift** lists every step that would be needed to make the kernel match
  the configuration. It is empty in normal operation.

While `meshly invite` waits on this node, `status` says so. The invite holds
meshly's lock, its temporary rules are in the firewall table, and drift is
not checked:

```
! another meshly operation is in progress
Configuration (saved, revision 1, 2026-10-18T20:30:00Z)
  network      homelab  10.100.0.0/24  (id b5cf94172d66)
  this node    vps  10.100.0.1  udp/51820  endpoint 203.0.113.10:51820
  public key   bWcWhZaUNdCDGVVlpXq8o/ep9g9jtumd2jC7Zsju9C4=
  admin state  up   firewall profile none   0 allow rule(s)
Service
  meshly.service active/enabled, check timer active   (systemd state says nothing about connectivity)
Interface
  meshly0  up, mtu 1420, addresses 10.100.0.1/32, listen udp/51820, key ok
Firewall
  table inet meshly  present, with the open invite's temporary rules
Transaction
  none pending; last: init commit at 2026-10-18T20:30:00Z
Invite open until 2026-10-18T20:40:00Z: waiting for a node to join (run `sudo meshly join` on the other node).
```

`status --json` then has an `invite` object with `expires_at`. Only the
expiry of an invite is ever shown, never its code.

Without root, `status` works with reduced detail (no keys, WireGuard or
firewall inspection).

## `meshly doctor`

`doctor` runs the preflight checks, inspects the configuration, keys,
firewall, service, journal and kernel state, and prints one finding per line:

```
✓ wireguard            kernel WireGuard module is loaded
! peer:vps             last handshake 412s ago (idle or peer unreachable); the peer may be down, or UDP is blocked [possible]
                       → check the peer: `meshly status` there
```

`✓` ok, `·` info, `!` warning, `✗` problem. The line after `→` is the
suggested fix.

### Observed and inferred findings

Each finding has a certainty:

- `observed` (not shown in text output): a fact read from the system, such as
  a missing table, a counter value or a file mode.
- `likely` / `possible` (shown in brackets): an inference. meshly cannot see
  the other node or the network path, so causes such as "UDP is blocked by a
  cloud firewall" or "the peer is down" are offered as possibilities. Check
  them on the other node or at the provider.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | no warnings or problems (info findings allowed) |
| 11 | warnings only |
| 12 | at least one problem |

Other failures (for example a usage error) use the general exit codes in
[cli.md](cli.md).

### JSON output

`meshly status --json`, `meshly doctor --json` and `meshly logs --json`
print objects with a `schema` field: `meshly.status/v1`, `meshly.doctor/v1`,
`meshly.logs/v1`. Scripts should check `schema` and use the `id`, `status`
and `certainty` fields of doctor findings rather than the human text, which
may change. The intent is that fields are only added within a schema
version; a renamed or removed field gets a new schema version. JSON output
never contains private keys.

### Doctor checks

| ID | Meaning | Typical fix |
|---|---|---|
| `os` | meshly runs only on Linux. | — |
| `privileges` | Root is needed to inspect kernel state (warning when run without root). | `sudo meshly doctor` |
| `wireguard` | Kernel WireGuard module loaded or available. | Use the distribution kernel or `modprobe wireguard`; meshly installs no packages. |
| `nftables` | `/usr/sbin/nft` exists and is version 1.0.6 or newer. | `apt install nftables` |
| `systemd` | systemd is PID 1; without it there is no autostart. | — |
| `config` | `/etc/meshly/meshly.json` is valid (or: not initialized). | Restore from `/var/lib/meshly/history/`, or `meshly reset`. Not initialized: `meshly init` or `sudo meshly join`. |
| `keys` | The key file is root-owned `0600` in a `0700` directory and matches the public key in the configuration. | Restore the original key; changing the key requires pairing again (`meshly reset`, then `join` again). |
| `nftables-ruleset` | The ruleset could not be read. | Check that `nf_tables` is available in the kernel. |
| `firewall-manager` | firewalld is active; there is no adapter for it. | Disable it and use UFW, iptables or native nftables, or do not use meshly on this host. |
| `ufw` | UFW is enabled (information): meshly keeps its rule at the top of the iptables `INPUT` and `OUTPUT` chains, and of `FORWARD` while there are Docker networks. | — |
| `fail2ban` | fail2ban's nftables table exists (information): the addresses it bans stay banned for traffic through meshly. | — |
| `iptables-legacy` | Legacy iptables rules exist (or cannot be inspected). | Switch iptables to the `iptables-nft` backend (`update-alternatives --set iptables /usr/sbin/iptables-nft`, the same for `ip6tables`) and reload the rules. |
| `firewall-table` | A table `inet meshly` exists that meshly did not create. | Rename or delete it; meshly never takes over foreign objects. |
| `flowtable` | A flowtable offloads traffic of the meshly interface, which would bypass the policy. | Remove the interface from the flowtable devices. |
| `firewall-chain` | A foreign chain is outside the supported profiles (for example an iptables-nft `mangle` chain that drops). | See [firewall.md](firewall.md). |
| `firewall-iptables` | iptables chains filter traffic (information): meshly keeps its rule at the top of them. | — |
| `firewall-integration` | A foreign base chain would drop meshly traffic: integration rule missing, misplaced (after a drop), or profile `none` on a host with a filtering firewall. | Add `meta mark & 0x10000000 == 0x10000000 accept comment "meshly"` before any drop/reject rule in that chain and reload nftables. |
| `firewall-ban` | A ban list (fail2ban's, or a named set of addresses) holds a peer's VPN address or endpoint, so its traffic is dropped (warning, never a refusal). | fail2ban: `sudo fail2ban-client unban <address>`, or add it to `ignoreip`; another set: `sudo nft delete element <family> <table> <set> { <address> }` |
| `firewall-profile` | Summary of the firewall profile (`none` or native `nftables`; iptables chains are not part of it). | — |
| `docker` | Information: the Docker networks found, whose published ports the peer reaches after `meshly allow <port>`, and whose containers reach the other node like programs on this host. A warning when the ruleset has Docker's rules but no bridge named `docker0` or `br-<id>`: containers on networks with custom bridge names cannot use the VPN. | Networks that set `com.docker.network.bridge.name`: use networks without it ([firewall.md](firewall.md#docker-networks)). |
| `firewall-forward` | Only while there are Docker networks. A forward chain of the host firewall may drop container traffic through meshly (warning, never a refusal: the tunnel between the hosts does not pass the forward hook). If meshly cannot integrate the chain (another iptables table, or a priority of −300 or lower), containers cannot use the VPN through it. The chains of Docker's own nftables backend are information. | Add the integration rule that `doctor` prints to that chain, before any drop/reject rule; for a chain meshly cannot integrate, remove or narrow the rule that drops ([firewall.md](firewall.md#the-forward-hook)). |
| `netdev` | A netdev chain exists; it runs before meshly and may drop WireGuard transport. | Review that chain. |
| `nftables-reload` | `/etc/nftables.conf` contains `flush ruleset` and nftables.service is enabled. Starting or reloading nftables removes the meshly table until meshly re-applies it. With profile `none` the VPN is unfiltered during that window; with profile `nftables` it is closed. | Prefer `table inet filter; delete table inet filter` over `flush ruleset`. |
| `service` | `meshly.service` installed, enabled and active. | `meshly start`; `journalctl -u meshly` |
| `transaction` | An operation did not finish (problem), or the last one ended in rollback or safe mode (warning). | `meshly recover`, or fix the cause and repeat; `meshly start` re-applies the configuration. |
| `link` | The link is stopped by the administrator. | `meshly start` |
| `invite` | An invite is open until the time shown; the drift check is skipped while it waits (info). | *"let it finish, or cancel it with Ctrl+C in its terminal"* |
| `drift` | The kernel differs from the configuration; the finding lists the differences. | `meshly start` (or wait for the check timer). |
| `routes` | Routes on the meshly interface that meshly did not create; traffic to them is dropped. | Remove them (`ip route show dev meshly0`). |
| `mtu` | The interface MTU is larger than the smallest outer MTU minus 80 bytes of WireGuard overhead. | `meshly set mtu <n>` on both nodes. |
| `peer` | No peer yet. | `sudo meshly invite` on this node and `sudo meshly join` on the other. |
| `peer:<name>` | Handshake state of the peer; see [No handshake](#no-handshake). | Depends on the finding. |
| `policy` | Number of packets from the VPN dropped by the default-deny policy since the table was loaded. | If a peer needs a service: `meshly allow <port>/<proto> from <peer>`. |
| `service:<port>/<proto>` | For each allow rule: a service listens on the VPN address or on all addresses (ok), only on another address, or nothing listens. | Bind the service to the VPN address or `0.0.0.0`; start it. |
| `probe:<port>/<proto>` | Result of `--probe` (see below). | Depends on the finding. |

Preflight checks that run before `init`, `join`, `start` and `set cidr`, but
not in `doctor`: `interface` (name taken by a foreign interface), `addresses`
(VPN network overlaps local addresses or routes) and `listen-port` (UDP port
in use).

### Active probe

`meshly doctor --probe <port>/<tcp|udp> [--peer NAME]` connects from this
node's VPN address to the peer's VPN address. It opens no listening port.

| Result | Meaning |
|---|---|
| connected / answered | The peer allows the port and a service answers. |
| refused / port unreachable | The peer allows the port, but nothing listens there (`likely`). |
| TCP timeout with a recent handshake | The peer's policy does not allow this port (`likely`): run `meshly allow <port>/tcp from <this node>` on the peer. |
| timeout without a recent handshake | The peer is down or unreachable (`possible`). |
| UDP: no answer | Inconclusive: the service may not reply, or the port is not allowed. |

## The journal: `meshly logs`

Every mutating operation writes a `begin` record (operation, arguments,
actor uid and `SUDO_USER`, recovery direction, plan, full target
configuration) and a terminal record: `commit`, `rolled-back`, `safe-mode`
or `recovered`. Events outside a transaction are recorded as `audit`
records: `invite` (opened, with its expiry, and closed: `joined <name>`,
`cancelled`, `expired`, `failed` or `interrupted`), `upgrade` and
`upgrade-rollback`, `reset`, `restart` and `service-stop`. The journal never
contains private keys or an invite code.

```
$ sudo meshly logs -n 6
2026-10-18 20:30:00  audit        invite          (uid=0 sudo_user=admin)  — opened, expires 2026-10-18T20:40:00Z
2026-10-18 20:31:05  begin        invite         peer=home  (uid=0 sudo_user=admin)
2026-10-18 20:31:05  commit       invite
2026-10-18 20:31:06  audit        invite          (uid=0 sudo_user=admin)  — closed: joined home
2026-10-18 20:31:40  begin        allow          22/tcp from home  (uid=0 sudo_user=admin)
2026-10-18 20:31:40  commit       allow

Service output: journalctl -u meshly -u meshly-check
```

On the joining node the same pairing is one `join` transaction.

The journal is `/var/lib/meshly/journal.jsonl` (rotated at 4 MiB to
`journal.jsonl.1`). `meshly reset` keeps it for audit. Output of the systemd
units is in the system journal:

```
journalctl -u meshly -u meshly-check -u meshly-watch
```

## Interrupted operations: `meshly recover`

If meshly is killed or the machine loses power during an operation, the
journal has a `begin` without a terminal record. The next mutating command,
the next service start (also at boot) and the next check timer run recover
it automatically before doing anything else, and print, for example:

```
meshly: recovered interrupted operation "allow": rolled-back
```

- Operations that grant access (`init`, `invite`, `join`, `allow`, `start`,
  `set`) are rolled back unless their configuration had already been saved,
  in which case they are completed.
- Operations that reduce access (`deny`, `revoke`, `stop`, `reset`, and
  `invite-undo` and `join-undo`, which remove a node that joined but did not
  confirm) are always completed (`rolled-forward`).

An invite that was killed (`kill -9`, or a power loss) holds no transaction,
but leaves its temporary peer and firewall rule in the kernel and its marker
`/run/meshly/invite.json`. The next command that takes the lock removes the
marker and journals `invite` `closed: interrupted`. The check timer removes
the temporary state within a minute, as drift; `sudo meshly start` removes it
at once. A node that the invite had already added stays: its `invite`
transaction had committed.

`meshly recover` runs only this step, and is useful after a crash before
looking at anything else. `doctor` reports an unfinished operation as
`transaction`.

## Safe mode

If an operation fails and the rollback (or, for access-reducing operations,
the retry) fails too, meshly enters safe mode and exits with 8:

- the meshly table is replaced by a lockdown version (no peers, no rules: all
  traffic on the interface is dropped). It does not mark the WireGuard
  transport either, so the integration rule of your firewall, or meshly's
  rule in the iptables chains, no longer opens the listen port;
- the WireGuard interface is deleted;
- nothing else on the host is changed, and the saved configuration is kept.

To leave safe mode, find the cause with `meshly doctor` and
`journalctl -u meshly`, fix it, and run:

```
sudo meshly start
```

While `meshly.service` is active, the check timer also sees the missing
interface as drift and attempts the same repair about once a minute. If the
cause persists, each attempt fails, is rolled back or ends in safe mode
again, and is visible in `meshly logs`. The re-applied configuration is the
last committed one, so the change that failed is not part of it
(`TestSystemdLifecycle/safe-mode-retried-by-check`).

## Drift and the check timer

`meshly-check.timer` runs `meshly service check` every minute (first run
2 minutes after boot) while `meshly.service` is active. It compares the
kernel with the configuration and repairs differences in a journaled
`check-repair` operation, for example:

- the meshly table was deleted, flushed or edited by hand;
- a per-interface sysctl was changed (such as `forwarding=1` on a node
  without Docker networks);
- the interface, its address, WireGuard peers or routes were changed outside
  meshly;
- meshly's rule in an iptables chain is missing, not first or duplicated;
- a Docker network appeared or went away (`Docker networks changed:
  +br-3f1c2a9b7d01`), or the policy routing rule or the routes of table 109
  differ from the Docker networks.

It skips the run if another meshly operation holds the lock, for example
while `meshly invite` waits, and never starts a link that was stopped
(`meshly stop` or `systemctl stop meshly`). To repair immediately instead of
waiting: `sudo meshly start`.

`meshly-watch.service` runs the same check within seconds of a change: it
follows netlink link events and nftables events, waits until no other
change came for a second (at most 5 seconds after the first), and then
checks. While another operation holds the lock it tries again every
2 seconds. After a failed check it ignores changes for a minute and leaves
the retry to the timer. It runs while `meshly.service` is active and stops
with it. A check that finds nothing to repair writes no journal entry. Its
output is in `journalctl -u meshly-watch`.

## After an nftables reload or `flush ruleset`

Most `/etc/nftables.conf` files start with `flush ruleset`, which also
removes the meshly table.

- `systemctl reload nftables` and `systemctl restart nftables` reload or
  restart `meshly.service` (`ReloadPropagatedFrom=`, `PartOf=`), which
  re-applies the table.
- `systemctl start nftables` triggers the drop-in
  `nftables.service.d/50-meshly.conf`, which reloads meshly if it is active.
- A manual `nft flush ruleset` or `nft -f` of a file with `flush ruleset` is
  usually repaired by `meshly-watch.service` within seconds, otherwise by
  the check timer within about a minute, or immediately with
  `sudo meshly start` or `sudo systemctl reload meshly`.

Until the table is back, the VPN is open to the peer without filtering with
profile `none`, and closed with profile `nftables` (fail-closed; see
[firewall.md](firewall.md)). On a node with Docker networks, ports that
Docker publishes on all addresses are open to the peer meanwhile in either
profile; the LAN stays closed
([firewall.md](firewall.md#when-the-table-disappears)). To avoid the window,
replace `flush ruleset` in your own configuration with deleting only your
own tables, for example `table inet filter` followed by
`delete table inet filter`.

## Runbooks

### Pairing fails

`meshly join` changes nothing on the joining node unless it says otherwise.
By exit code:

- **13, the inviting node did not answer** within 30 seconds. Either the
  invite is no longer open (expired, cancelled or already used: run `sudo
  meshly invite` there again), or UDP to the WireGuard port does not get
  through: open it in the cloud firewall or security group and check that
  the inviting node's endpoint in `meshly status` is the address you expect
  (`sudo meshly set endpoint IP` there, then a new invite). From the joining
  node the two cases look the same.
- **4, invalid invite code.** The code is damaged or incomplete (copy the
  whole line again: whitespace and line breaks do not matter), it expired
  (open a new invite; if the new code is refused as expired too, check this
  node's clock), it was made by another meshly version (upgrade both
  nodes), or another node already used it.
- **5, conflict.** The name is taken by the inviting node (`--name`), or
  this node is already a member of a network (`meshly status`; `meshly
  reset` to leave it).
- **3, preflight.** Something on this node conflicts with the network, for
  example a route that overlaps the VPN CIDR or an unsupported firewall. The
  message names it; nothing was sent to the inviting node.
- **7, rolled back.** The real tunnel did not come up after the switch to
  this node's own key. This node was rolled back; the invite undoes its side
  after a minute and keeps waiting while the code is valid, so `sudo meshly
  join` with the same code may be run again until then.
- **1, joined, but not acknowledged.** The tunnel works, but the
  confirmation got no answer. Check `meshly status` on both nodes. If the
  inviting node lists no peer, run `sudo meshly reset` here and pair again.

On the inviting node, `invite` exits 5 when the network already has a peer
or the link is stopped, and 2 when the node has no public endpoint. A
running invite blocks other changing commands (exit 6) until it ends.

### No handshake

Run `sudo meshly doctor` on both nodes and look at `peer:<name>`:

1. *No WireGuard UDP packet reached this host on port N* (observed). The
   packets are dropped before the host: open UDP N in the cloud security
   group or provider firewall, or the router's port forwarding. meshly does
   not manage these. Also check that the peer has joined: its `meshly
   status` must list this node.
2. *UDP packets arrived but no handshake completed* (likely). The packets
   come from a key this node does not know: the peer was reset or a different
   node is sending. Compare the WireGuard public keys in `meshly status` on
   both nodes; if they differ, `revoke` the peer and pair again.
3. *Handshake initiations are sent but nothing comes back* (possible). The
   peer is down, UDP is blocked on the path, the configured endpoint is wrong,
   or the peer revoked this node. Check the peer with `meshly status`; fix the
   endpoint with `meshly set peer-endpoint`.
4. *No handshake yet and no traffic was attempted*. Generate traffic, for
   example with `meshly doctor --probe 22/tcp`, or wait for the keepalive.

`sudo wg show meshly0` is a safe read-only cross-check. Do not change the
interface with `wg set`: meshly treats it as drift and reverts it.

### Handshake works, but a service is unreachable

On the node that runs the service:

- `meshly rules` must list `allow <port>/<proto> from <peer>`. Without it, the
  connection is dropped by default deny, and the `policy` finding counts the
  dropped packets.
- `service:<port>/<proto>` warns when the service listens only on another
  address (often `127.0.0.1`). Bind it to the VPN address or to `0.0.0.0`.
- With a host firewall (profile `nftables`), `firewall-integration` must not
  report a missing or misplaced rule.

On the client node, `meshly doctor --probe <port>/<proto>` tells "not
allowed" (timeout) from "nothing listening" (refused). Rules apply only in the
direction peer → this node; to let both nodes use a service on each other,
add a rule on each node.

### A Docker container cannot use the VPN

For a port published by a container, on the node that runs it:

- `meshly allow` takes the host port: the left number of `-p 9104:8080`.
  A port published on `127.0.0.1` only stays closed, like a program that
  listens on localhost only.
- `meshly status` must list the container's network under
  `docker networks`. A new network shows there within seconds; if it does
  not, check `systemctl status meshly-watch` and
  `journalctl -u meshly-watch`. A network with a custom bridge name is not
  supported (`doctor` warns with `docker`).
- `doctor` must not report `firewall-forward`: a forward chain of the host
  firewall that drops container traffic needs the integration rule that
  `doctor` prints.

For a container that connects to the other node, the other node must allow
the port from this node, as for a program on this host. A container cannot
reach its own node's VPN address; it reaches its host through the gateway
address of its bridge, as usual in Docker. Details:
[firewall.md](firewall.md#docker).

### The public node's IP address changed

On the node behind NAT:

```
sudo meshly set peer-endpoint vps 203.0.113.20:51820
```

On the public node, update its own endpoint (used in future invites):

```
sudo meshly set endpoint 203.0.113.20:51820
```

The public node learns the NAT side's address from authenticated packets
itself; nothing else needs to change.

### Large transfers stall or SSH hangs after login (MTU)

Small packets (ping, the TCP handshake) work but larger ones are lost when
the path MTU is smaller than the interface MTU plus about 80 bytes of
WireGuard overhead (PPPoE, some mobile and cloud networks). `doctor` warns
(`mtu`) when a local interface has a smaller MTU. Lower the MTU on both
nodes, for example:

```
sudo meshly set mtu 1380
```

The allowed range is 1280–8920; the default is 1420.

### Configuration file damaged

`doctor` reports `config` as a problem. Copy the latest good revision from
`/var/lib/meshly/history/meshly-<rev>.json` to `/etc/meshly/meshly.json`
(owned by root, mode 0644 or stricter), then run `sudo meshly start`. Without a usable revision,
remove meshly with `meshly reset` and pair the nodes again.

### Removing meshly from a node

```
sudo meshly reset --yes
```

`reset` removes the link (traffic path first, then the firewall table), the
configuration, the key, the runtime state, the configuration history and
the systemd units. Nothing outside meshly's own objects is touched. The
journal (`/var/lib/meshly/journal.jsonl`) and the binary remain; delete them
by hand if you no longer need them:

```
sudo rm -f /usr/local/bin/meshly /usr/local/bin/meshly.prev
sudo rm -rf /var/lib/meshly
```

Run `meshly revoke <peer>` on the other node as well so that it stops trying
to reach this one.
