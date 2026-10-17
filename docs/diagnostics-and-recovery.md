# Diagnostics and recovery

This document explains how to read `meshly status` and `meshly doctor`, what
the journal records, how interrupted operations and safe mode are handled,
and what to do when the link or a service stops working. Architecture
background: [architecture.md](architecture.md). Exit codes of all commands:
[cli.md](cli.md). Firewall details: [firewall.md](firewall.md).

## `meshly status`

`status` shows the saved configuration and the observed kernel state side by
side. Configuration correctness and connectivity are reported separately: a
node can be configured correctly and still have no handshake because the
peer is switched off.

```
Configuration (saved, revision 4, 2026-10-17T19:30:58Z)
  network      homelab  10.100.0.0/24  (id b5cf94172d66)
  this node    vps  10.100.0.1  udp/51820  endpoint 198.51.100.10:51820
  fingerprint  VJW7-OEX7-FGSZ-Y6TN-AID5-LTGJ-YBDE-OJNN
  admin state  up   firewall profile none   2 allow rule(s)
Service
  meshly.service active/enabled, check timer active   (systemd state says nothing about connectivity)
Interface
  meshly0  up, mtu 1420, addresses 10.100.0.1/32, listen udp/51820, key ok
Firewall
  table inet meshly  present, matches config
Peer home
  address 10.100.0.2   fingerprint ECSR-MFJA-MIHL-ML4O-LBKG-YFZP-ETRH-4A7P
  wireguard configured, allowed-ips 10.100.0.2/32, route ok, keepalive 25s
  endpoint 198.51.100.20:51820
  connectivity: last handshake 6s ago, rx 180 B, tx 124 B
  may use here: ping, 22/tcp
Transaction
  none pending; last: allow commit at 2026-10-17T19:30:58Z
Drift
  none: kernel state matches the configuration
```

- **admin state** is `up` after `start`/`init`/`activate` and `down` after
  `meshly stop`.
- **Service** is the systemd state only. `active` means the last start
  succeeded, not that the peer is reachable.
- **Firewall** compares the live `inet meshly` table with the configuration
  (ownership marker hash and the content hash recorded after the last apply).
- **connectivity** is one of `handshake-recent` (within 180 s; WireGuard
  re-keys every 120 s while traffic flows), `handshake-stale`, `no-handshake`
  or `unknown` (not observable: interface down or not running as root).
- **Transaction** shows an interrupted operation, if any, and the last
  operation with its outcome.
- **Drift** lists every step that would be needed to make the kernel match
  the configuration. It is empty in normal operation.

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
| `config` | `/etc/meshly/meshly.json` is valid (or: not initialized). | Restore from `/var/lib/meshly/history/`, or `meshly reset`. |
| `bootstrap` | A join request is waiting for its accept file. | `meshly activate <file.accept>` once the inviting node approved. |
| `keys` | Key files are root-owned `0600` in a `0700` directory and match the public keys in the configuration. | Restore the original keys; new keys need a new trust procedure (`reset`, then `join`). |
| `nftables-ruleset` | The ruleset could not be read. | Check that `nf_tables` is available in the kernel. |
| `firewall-manager` | firewalld or UFW is active; there is no adapter for them. | Disable them and use native nftables, or do not use meshly on this host. |
| `iptables-legacy` | Legacy iptables rules exist (or cannot be inspected). | Migrate them to nftables manually. |
| `firewall-table` | A table `inet meshly` exists that meshly did not create. | Rename or delete it; meshly never takes over foreign objects. |
| `flowtable` | A flowtable offloads traffic of the meshly interface, which would bypass the policy. | Remove the interface from the flowtable devices. |
| `firewall-chain` | A foreign chain is outside the supported profiles (for example an iptables-nft chain that drops). | See [firewall.md](firewall.md). |
| `firewall-integration` | A foreign base chain would drop meshly traffic: integration rule missing, misplaced (after a drop), or profile `none` on a host with a filtering firewall. | Add `meta mark & 0x10000000 == 0x10000000 accept comment "meshly"` before any drop/reject rule in that chain and reload nftables. |
| `firewall-profile` | Summary of the firewall profile (`none` or native `nftables`). | — |
| `docker` | Docker rules were detected. Published container ports are not reachable through the VPN; forwarding and DNAT from the VPN are blocked. | — |
| `netdev` | A netdev chain exists; it runs before meshly and may drop WireGuard transport. | Review that chain. |
| `nftables-reload` | `/etc/nftables.conf` contains `flush ruleset` and nftables.service is enabled. Starting or reloading nftables removes the meshly table until meshly re-applies it. With profile `none` the VPN is unfiltered during that window; with profile `nftables` it is closed. | Prefer `table inet filter; delete table inet filter` over `flush ruleset`. |
| `service` | `meshly.service` installed, enabled and active. | `meshly start`; `journalctl -u meshly` |
| `transaction` | An operation did not finish (problem), or the last one ended in rollback or safe mode (warning). | `meshly recover`, or fix the cause and repeat; `meshly start` re-applies the configuration. |
| `link` | The link is stopped by the administrator. | `meshly start` |
| `drift` | The kernel differs from the configuration; the finding lists the differences. | `meshly start` (or wait for the check timer). |
| `routes` | Routes on the meshly interface that meshly did not create; traffic to them is dropped. | Remove them (`ip route show dev meshly0`). |
| `mtu` | The interface MTU is larger than the smallest outer MTU minus 80 bytes of WireGuard overhead. | `meshly set mtu <n>` on both nodes. |
| `peer` | No peer yet. | `meshly invite` |
| `peer:<name>` | Handshake state of the peer; see [No handshake](#no-handshake). | Depends on the finding. |
| `policy` | Number of packets from the VPN dropped by the default-deny policy since the table was loaded. | If a peer needs a service: `meshly allow <port>/<proto> from <peer>`. |
| `service:<port>/<proto>` | For each allow rule: a service listens on the VPN address or on all addresses (ok), only on another address, or nothing listens. | Bind the service to the VPN address or `0.0.0.0`; start it. |
| `probe:<port>/<proto>` | Result of `--probe` (see below). | Depends on the finding. |

Preflight checks that run before `init`, `start` and `set cidr`, but not in
`doctor`: `interface` (name taken by a foreign interface), `addresses` (VPN
network overlaps local addresses or routes) and `listen-port` (UDP port in
use).

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
records: `invite`, `join`, `upgrade` and `upgrade-rollback`, `reset`,
`restart` and `service-stop`. The journal never contains private keys.

```
$ sudo meshly logs -n 4
2026-10-17 19:30:58  begin        allow          22/tcp from home  (uid=0 user=root)
2026-10-17 19:30:58  commit       allow
2026-10-17 19:30:58  begin        allow          ping from home  (uid=0 user=root)
2026-10-17 19:30:58  commit       allow
```

The journal is `/var/lib/meshly/journal.jsonl` (rotated at 4 MiB to
`journal.jsonl.1`). `meshly reset` keeps it for audit. Output of the systemd
units is in the system journal:

```
journalctl -u meshly -u meshly-check
```

## Interrupted operations: `meshly recover`

If meshly is killed or the machine loses power during an operation, the
journal has a `begin` without a terminal record. The next mutating command,
the next service start (also at boot) and the next check timer run recover
it automatically before doing anything else, and print, for example:

```
meshly: recovered interrupted operation "allow": rolled-back
```

- Operations that grant access (`init`, `approve`, `activate`, `allow`,
  `start`, `set`) are rolled back unless their configuration had already been
  saved, in which case they are completed.
- Operations that reduce access (`deny`, `revoke`, `stop`, `reset`) are
  always completed (`rolled-forward`).

`meshly recover` runs only this step, and is useful after a crash before
looking at anything else. `doctor` reports an unfinished operation as
`transaction`.

## Safe mode

If an operation fails and the rollback (or, for access-reducing operations,
the retry) fails too, meshly enters safe mode and exits with 8:

- the meshly table is replaced by a lockdown version (no peers, no rules: all
  traffic on the interface is dropped);
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
- a per-interface sysctl was changed (such as `forwarding=1`);
- the interface, its address, WireGuard peers or routes were changed outside
  meshly.

It skips the run if another meshly operation holds the lock, and never
starts a link that was stopped (`meshly stop` or `systemctl stop meshly`).
To repair immediately instead of waiting: `sudo meshly start`.

## After an nftables reload or `flush ruleset`

Most `/etc/nftables.conf` files start with `flush ruleset`, which also
removes the meshly table.

- `systemctl reload nftables` and `systemctl restart nftables` reload or
  restart `meshly.service` (`ReloadPropagatedFrom=`, `PartOf=`), which
  re-applies the table.
- `systemctl start nftables` triggers the drop-in
  `nftables.service.d/50-meshly.conf`, which reloads meshly if it is active.
- A manual `nft flush ruleset` or `nft -f` of a file with `flush ruleset` is
  repaired by the check timer within about a minute, or immediately with
  `sudo meshly start` or `sudo systemctl reload meshly`.

Until the table is back, the VPN is open to the peer without filtering with
profile `none`, and closed with profile `nftables` (fail-closed; see
[firewall.md](firewall.md)). To avoid the window, replace `flush ruleset` in
your own configuration with deleting only your own tables, for example
`table inet filter` followed by `delete table inet filter`.

## Runbooks

### No handshake

Run `sudo meshly doctor` on both nodes and look at `peer:<name>`:

1. *No WireGuard UDP packet reached this host on port N* (observed). The
   packets are dropped before the host: open UDP N in the cloud security
   group or provider firewall, or the router's port forwarding. meshly does
   not manage these. Also check that the peer has run `meshly activate`.
2. *UDP packets arrived but no handshake completed* (likely). The packets
   come from a key this node does not know: the peer was reset or a different
   node is sending. Compare the fingerprints in `meshly status` on both
   nodes; if they differ, `revoke` the peer and pair again.
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
configuration, keys, bootstrap and runtime state, the configuration history
and the systemd units. Nothing outside meshly's own objects is touched. The
journal (`/var/lib/meshly/journal.jsonl`) and the binary remain; delete them
by hand if you no longer need them:

```
sudo rm -f /usr/local/bin/meshly /usr/local/bin/meshly.prev
sudo rm -rf /var/lib/meshly
```

Run `meshly revoke <peer>` on the other node as well so that it stops trying
to reach this one.
