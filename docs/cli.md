# CLI reference

`meshly <command> [arguments]`. All commands that change the system require root, and so does `ping`. `status`,
`nodes`, `rules`, `version` and `help` also work without root, with reduced detail. Every changing command takes a lock: a second meshly
operation waits briefly and then fails with exit code 6. `init`, `allow`, `deny`, `revoke`, `start`, `stop` and
`set` accept `--dry-run`, which prints the plan, the rendered nftables table and the config diff, and changes nothing.

`meshly help <command>` prints the same help as below. Secrets are never accepted as arguments and never written to
logs or JSON output. Private keys are never printed; the invite code is printed once, by `meshly invite`.

- [Network setup](#network-setup): `init`, `invite`, `join`
- [Access policy](#access-policy): `allow`, `deny`, `rules`, `revoke`
- [Link lifecycle](#link-lifecycle): `start`, `stop`, `restart`, `set`
- [Information](#information): `status`, `nodes`, `ping`, `doctor`, `logs`, `version`
- [Maintenance](#maintenance): `upgrade`, `reset`, `recover`, `service`
- [Exit codes](#exit-codes)
- [JSON output](#json-output)
- [Files and environment](#files-and-environment)

## Network setup

A network is created on one node with `init`, usually the server whose UDP port is reachable from the internet. Every
other node joins it with a one-time code: run `meshly invite` on the first node and `meshly join` on the new one, once
for each node. The first node is the hub: every node that joined has a tunnel to it and to no other node, so the
nodes that joined do not reach each other. The protocol behind these commands is specified in
[pairing-protocol.md](pairing-protocol.md).

### `meshly init <network> --name <node> [--endpoint IP[:PORT]|auto|none] [options]`

Creates a network on this node and brings up the protected interface. It is usually run on the server whose UDP
port is reachable from the internet. Keys are generated locally.

| Flag | Default | Meaning |
|---|---|---|
| `--name NAME` | (required) | Node name: `a-z`, `0-9`, `-` |
| `--endpoint ADDR` | `auto` | Public address the other nodes connect to: `IP` or `IP:PORT` (numeric; host names are not supported; the port defaults to `--listen-port`), `auto` or `none`. See [Endpoint detection](#endpoint-detection) |
| `--listen-port PORT` | endpoint port or `51820` | Local UDP port |
| `--cidr CIDR` | `10.100.0.0/24` | VPN network: private IPv4, `/16`–`/30`, must not overlap local addresses or routes. It has an address for each node: 254 in a `/24`, 2 in a `/30` |
| `--mtu N` | `1420` | Interface MTU |
| `--interface NAME` | `meshly0` | Interface name |
| `--firewall PROFILE` | `auto` | `auto`, `none` or `nftables`: how a native nftables firewall is integrated; UFW and iptables need nothing. See [firewall.md](firewall.md) |
| `--dry-run` | | Show what would change |

Preflight runs first. If the environment is unsupported (no kernel WireGuard, nftables older than 1.0.6,
firewalld, iptables-legacy rules, a native nftables drop chain without integration, a CIDR conflict or a busy port),
init stops with exit code 3 and changes nothing. UFW and iptables rules need nothing: meshly puts its rule at the
top of their `INPUT` and `OUTPUT` chains (and of `FORWARD` while the node has Docker networks), and init names the
chains. Docker needs nothing either; a forward chain that may drop container traffic is a warning, never a reason
to stop (see [firewall.md](firewall.md#docker)).

init ends with what to do next: `sudo meshly invite` on this node and `sudo meshly join` on the node to add. Without
an endpoint it says that no other node can join until this node has one (`meshly set endpoint IP`).

#### Endpoint detection

With `--endpoint auto` (the default) meshly looks at the interfaces that carry the IPv4 default route and takes their
public IPv4 address, if there is exactly one. Private (RFC 1918), shared (RFC 6598, carrier-grade NAT), loopback and
link-local addresses are skipped. meshly reads only the local network configuration and does not ask any service on the
internet, so it cannot see a public address that the provider maps from outside: AWS, GCP and other clouds with 1:1 NAT
give the server a private address only. In that case, or when there are several public addresses, init reports why and
creates the network without an endpoint; set it with `meshly set endpoint IP`. The endpoint goes into the invite
code, so `invite` needs one; the firewall accepts WireGuard on the listen port with or without it. `join` detects
its own address only with `--endpoint auto`.

### `meshly invite [--ttl DURATION]`

Waits for a new node to join this network. Run it on the node that created the network with `init`; on a node that
joined, it exits with code 5 and names the node to run it on. It needs a public endpoint (exit code 2 otherwise, with
a hint to `meshly set endpoint IP`), a running link (exit code 5 after `meshly stop`, with a hint to `meshly start`)
and a free address in the network (exit code 5; `meshly revoke` a node, or create the network with a larger
`--cidr`). Nodes that joined before keep working while the invite waits.

The new node gets the lowest free address of the network: `10.100.0.2` for the first, `10.100.0.3` for the second,
and so on. The code carries it. An address that `meshly revoke` freed goes to the next node that joins.

| Flag | Default | Meaning |
|---|---|---|
| `--ttl DURATION` | `10m` | How long the code is valid: `1m` to `1h` |

```console
$ sudo meshly invite
Waiting for a node to join network "homelab" until 20:40 UTC (10 minutes). Ctrl+C cancels.
On the new node run `sudo meshly join` and paste this code:

m2atfqa4ikzjwgpbrtj3phaxmxkj7mzkcutbejgrbusyvju73zukbjrppgtl6q4yakmqaaegdk2uxkamwtchm7oqnrrkialyu6jp4zrk7wlzcjm

Node "home" (10.100.0.2) joined. The invite is closed.
```

- **Output.** stdout gets the code, alone on one line, and at the end the `Node … joined` line. The code is `m2`
  followed by lowercase letters and digits, 111 characters for an IPv4 endpoint (130 for IPv6); it is printed once
  and nowhere else. Everything else goes to stderr, including the engine's steps, which the sample leaves out.
- **While it waits**, a temporary WireGuard peer that only the code unlocks and firewall rules that let just the
  joining node's VPN address, through the tunnel, reach TCP port 51820 on this node's VPN address are in place. They
  are never saved in the configuration. Nothing new is reachable, from the internet or by local users: the rules
  drop what comes over loopback too, and the listener answers only the joining node's address. The invite holds
  meshly's lock: other changing commands exit with code 6 (`meshly invite is waiting for a node to join until …; let
  it finish or cancel it with Ctrl+C`), the check timer leaves the temporary state alone, and `status` and `doctor`
  show the open invite.
- **It ends** when a node has joined and confirmed the connection (exit code 0, `Node "home" (10.100.0.2) joined.
  The invite is closed.`), on Ctrl+C, SIGTERM, when the terminal hangs up, for example a closed SSH session, or when
  its output pipe breaks, for example `| tee` killed by the same Ctrl+C (exit code 10; under `nohup` the hang-up is
  ignored; after a broken pipe the cleanup still completes, but writing the final message to the broken pipe can end
  meshly with exit code 141 instead), or when the code expires and no node joined (exit code 13).
- **If the node that joined cannot confirm** within a minute, its membership is undone (`Node "home" did not
  confirm the connection; its membership was undone.`), and the invite waits again while the code is valid. Until
  then the invite counts as open, for `status` and the busy message, even past the code's expiry.
- **Every way out removes the temporary state.** If the process is killed (`kill -9`), `meshly-check.timer` removes
  it within a minute, and `sudo meshly start` at once.

### `meshly join [--name NAME] [--endpoint IP[:PORT]|auto|none] [options]`

Joins the network of the node where `meshly invite` waits. On a terminal it asks `Invite code: `; otherwise it reads
the code from the first line of stdin. **The code is never accepted as an argument** (exit code 2): other users
could see it in the process list, and it would stay in the shell history. Whitespace and letter case in the code
do not matter. A code that a paste broke across lines is read whole: while the input is the start of a code, join
reads the next line too (on a terminal after the prompt `> `), until the code is complete, a blank line or the end
of the input. A first line that cannot become a code is refused at once with exit code 4.

| Flag | Default | Meaning |
|---|---|---|
| `--name NAME` | the host name | Name of this node. The default is the first label of the host name, lowercased, with other characters than `a-z` and `0-9` turned into `-`, at most 32 characters. If that gives no valid name, join asks for `--name` |
| `--endpoint ADDR` | `none` | Public address of this node, if it has one: `IP` or `IP:PORT` (the port defaults to `--listen-port`), `auto` ([detected](#endpoint-detection)) or `none`. Without one, the inviting node learns the address from authenticated packets |
| `--listen-port PORT` | endpoint port, else `51820` or a free port | Local UDP port |
| `--keepalive SECONDS` | `25` | Keepalive towards the inviting node (`0` = off). The inviting node always uses 25 towards this node |
| `--interface NAME`, `--firewall PROFILE` | | As for `init` |

```console
$ sudo meshly join
Invite code: m2atfqa4ikzjwgpbrtj3phaxmxkj7mzkcutbejgrbusyvju73zukbjrppgtl6q4yakmqaaegdk2uxkamwtchm7oqnrrkialyu6jp4zrk7wlzcjm
Connecting to 203.0.113.10:51820...
Joined network "homelab" as "home" (10.100.0.2).
  peer:  vps 10.100.0.1 via 203.0.113.10:51820
Inbound VPN traffic to this node is denied until you run `meshly allow` here.
```

join checks the code and runs the same preflight as `init` (exit code 3) before it contacts the other node. It
then opens a temporary tunnel to it with keys derived from the code, exchanges names, keys and settings, switches to
this node's own keys in one transaction and confirms the connection through the new tunnel. The last three lines go
to stdout; everything else goes to stderr, including the engine's steps, which the sample leaves out.

| Exit code | When | This node |
|---|---|---|
| 4 | The code is damaged or incomplete, from another meshly version, expired, or was made on this node; or the invite was already used by another node | unchanged |
| 5 | This node is already a member of a network, or the name is taken by the inviting node or by a node that joined it (`meshly revoke` that node there first to reuse the name) | unchanged |
| 13 | The inviting node did not answer within 30 seconds: its invite is closed (expired, cancelled or already used), or UDP to its port does not get through | unchanged |
| 7 | The connection through the new tunnel could not be confirmed. Run `sudo meshly join` again while the invite is open | rolled back |
| 10 | Ctrl+C, SIGTERM or a hang-up from the temporary tunnel on (before it, Ctrl+C exits 130 as usual) | unchanged or rolled back |
| 1 | The tunnel works (a WireGuard handshake happened), but the inviting node did not acknowledge the connection. Check `meshly status` on both nodes | configuration kept |

A code is accepted up to 5 minutes past its expiry, in case the two clocks differ. A join shortly after the invite
ended therefore usually gets exit code 13, not 4. If a fresh code is refused as expired too, the clock of the joining
node is wrong; the message says so.

#### Pairing from a script

`invite` writes nothing but the code to stdout before it is done, and `join` reads the code from stdin, so a script
can pass the code over SSH. This one runs as root on the VPS while `meshly invite` waits in the background:

```sh
#!/bin/sh
# Run as root on the vps: pairs it with the node reachable as admin@home.
# sudo on home must not ask for a password: stdin carries the code.
out=$(mktemp)
trap 'rm -f "$out"' EXIT
meshly invite >"$out" &
invite=$!
until [ -s "$out" ]; do                  # the code is the first line of stdout
  kill -0 "$invite" 2>/dev/null || { wait "$invite"; exit; }   # refused, e.g. exit 5
  sleep 1
done
if head -n 1 "$out" | ssh admin@home sudo meshly join --name home; then
  wait "$invite"                         # 0: home joined and confirmed
else
  code=$?
  kill "$invite"; wait "$invite"         # close the invite now, not at expiry
  exit "$code"
fi
```

The code never appears in a command line: it goes from the file through a pipe into the stdin of `ssh`.

## Access policy

Rules are **local**: `allow` on a node opens a port on that node's VPN address, for one peer, for connections that
the peer initiates through the VPN. Nothing is opened on public interfaces. Replies to connections this node
initiates are always allowed.

### `meshly allow <port>/<tcp|udp> from <peer>` · `meshly allow ping from <peer>`

```sh
meshly allow 22/tcp from home
meshly allow 53/udp from home
meshly allow ping from home
```

Running the same `allow` twice is a no-op ("Already allowed"). An unknown peer gives exit code 5. A malformed rule
gives exit code 2.

A port that a Docker container publishes (`-p`, `ports:`) on all addresses or on the VPN address is a port of this
node: `allow` takes the host port, the left number of `-p 9104:8080`. The rule can be added before the container
exists, and survives `docker compose down` and `up` (see [firewall.md](firewall.md#docker)).

### `meshly deny <port>/<tcp|udp> from <peer>` · `meshly deny ping from <peer>`

Removes the rule. Policy is evaluated per packet, so packets of connections that are already established are
dropped as well.

### `meshly rules [--json]`

Lists the rules of this node, each with its meaning in words.

### `meshly revoke <peer> [--yes] [--dry-run]`

Closes all access of the peer first (firewall), then removes it from WireGuard and routing. It asks for
confirmation unless `--yes` is given. The other peers stay connected. On the first node, the address of the revoked
node goes to the next node that joins. A node that revokes the node it joined through is alone; to join again, it
needs `meshly reset` and a new invite.

## Link lifecycle

### `meshly start [--dry-run]`

Brings the link up from the saved configuration and enables `meshly.service`. This also leaves safe mode and
repairs drift.

### `meshly stop [--dry-run]`

Takes the traffic path down first and removes the protective firewall table last. The admin state is saved as
`down`, so the link stays stopped after reboot and the check timer does not revive it.

### `meshly restart`

Tears the link down and brings it up again (via `systemctl restart meshly` when the service is installed). Only
for a running link: a link stopped with `meshly stop` is brought back with `meshly start` (exit code 5 otherwise).

### `meshly set <setting> <value> [--dry-run]`

| Setting | Values | Notes |
|---|---|---|
| `mtu` | `1280`–`8920` | Set the same value on every node |
| `keepalive` | `0`–`3600` seconds | Towards all peers. `0` turns it off (not recommended behind NAT) |
| `endpoint` | `IP`, `IP:PORT`, `auto` or `none` | This node's public address, used in new invites. A bare IP gets the listen port; `auto` [detects](#endpoint-detection) the address and fails if there is not exactly one |
| `peer-endpoint` | `<peer> IP`, `<peer> IP:PORT` or `<peer> none` | Where to reach the peer, e.g. after the VPS changed its IP. A bare IP keeps the current port (or gets `51820`) |
| `cidr` | `CIDR` | VPN network; only before a peer joined |

## Information

### `meshly status [--json]`

Shows the saved configuration, the service state, the interface, the firewall table, each peer (handshake age,
traffic counters, endpoint, the rules it may use), interrupted operations and drift between configuration and
kernel. The systemd state is shown separately and says nothing about connectivity. Without root, kernel and key
details are omitted. While `meshly invite` waits, status shows `Invite open until …` instead of the drift, and the
firewall table as `present, with the open invite's temporary rules`. Under the firewall table, `iptables chains`
names the iptables chains that carry meshly's rule and whether it is first, and on a node with Docker networks
`docker networks` lists them and `forward chains` names the forward chains that may drop container traffic (see
[diagnostics-and-recovery.md](diagnostics-and-recovery.md#meshly-status)).

### `meshly nodes [--json]`

Lists the nodes of the network, this one first:

```
Network homelab  10.100.0.0/24

NODE              VPN ADDRESS   PUBLIC ADDRESS       CONNECTION                  MAY USE THIS NODE
vps (this node)   10.100.0.1    203.0.113.10:51820   -                           -
home              10.100.0.2    198.51.100.7:51820   online, last seen 36s ago   ping, 22/tcp

Check the link to home: sudo meshly ping home
```

The connection comes from the last WireGuard handshake. `online` means a handshake within the last 3 minutes. A
working link keeps handshaking every 2 minutes, because keepalive (25 seconds by default) keeps it in use. `offline`
means only an older handshake. When keepalive is off (`meshly set keepalive 0`), an unused link looks the same, so
it shows `idle or offline`. `never connected` means no handshake at all. `link stopped` means `meshly stop` was run
on this node. Without root the connection is `unknown`. The public address of a peer is where its packets last came
from, or the configured endpoint before that. `MAY USE THIS NODE` lists the allow rules of the peer on this node. Under
the table, meshly prints the next step for each peer: `ping` it, find out why it is not connected, or allow it a
service. The first node lists every node of the network; a node that joined lists itself and the first node, because
it knows no other.

### `meshly ping [<node>] [-c N] [--json]`

Sends `N` (default 4, `--count` too) ICMP echo requests to another node through the VPN, from this node's VPN
address, one per second, and waits up to 2 seconds for each reply. `<node>` is a name or a VPN address. Without it,
meshly pings the only other node; with several, it asks for one (exit code 2). Ctrl+C stops early and still prints the summary. Needs root, because it sends ICMP
from a raw socket.

```
PING home (10.100.0.2) from vps (10.100.0.1) through meshly0
reply from home: seq=1 time=11.0 ms
...
--- home: 4 sent, 4 received, 0% loss, time min/avg/max 11.0/12.5/14.0 ms
```

A node answers only if it allows ping: `meshly allow ping from vps` on home. When no reply comes, meshly checks the
handshake after the pings and says which of two cases it is (exit code 13):

- a recent handshake: the link works, so most likely home does not allow ping from vps. The message names the
  command to run on home.
- no recent handshake: the nodes have no connection. See `meshly doctor`.

Exit code 0 means at least one reply. A local failure, such as a missing VPN address, exits 1 at once.

### `meshly doctor [--json] [--probe <port>/<tcp|udp>] [--peer NAME]`

Runs every check and prints one line per finding: `✓` ok, `·` info, `!` warning, `✗` problem. Each finding has
a certainty: `observed` (a measured fact), `likely` or `possible` (inferred), and a fix where one is known.
`--probe` connects from this node's VPN address to a service on the peer; with several peers, `--peer` names it (exit
code 2 without it). For TCP it tells apart "connected",
"refused" (allowed, nothing listens), "timed out with a recent handshake" (the peer's policy does not allow the
port) and "timed out without a handshake" (peer down or unreachable). For UDP, silence is inconclusive. It opens
nothing locally. Check ids and runbooks are in
[diagnostics-and-recovery.md](diagnostics-and-recovery.md).

### `meshly logs [-n N] [--json]`

Shows the operation journal: who (uid, sudo user) did what, begin/commit/rollback/recovery/safe-mode events, and
audit records such as an invite opened and closed.
`-n` must be ≥ 1 (default 30). Service output is in `journalctl -u meshly -u meshly-check -u meshly-watch`.

### `meshly version [--short] [--json]`

`--short` prints only the version (used by `install.sh` and `upgrade` to check a downloaded binary).

## Maintenance

### `meshly upgrade [--check] [--version X.Y.Z] [--force] [--yes]`

The upgrade runs these steps:

1. Download `SHA256SUMS` and `SHA256SUMS.sig` of the latest (or the given) release from
   `github.com/nikitakiselev/meshly`.
2. Verify the Ed25519 signature with the release key compiled into the running binary.
3. Download the binary for this architecture and check its SHA-256.
4. Run the new binary to check that it reports the expected version.
5. Replace the executable atomically, keeping the previous one as `<exe>.prev`.
6. Reinstall the units. If `meshly.service` was running before replacement, restart it and verify it is active.
   If it fails, restore the previous binary and restart and verify it even if the new unit is now failed.
   Code 7 means the previous version is running again; a failed restoration returns an error. An intentionally
   stopped service remains stopped.

`--check` only reports whether a newer release exists. Downgrades are refused unless `--force` is given (exit code
5). The version is taken only from the signed `SHA256SUMS`, so an old signed release cannot be replayed as a new
one. A release that fails the signature or checksum verification is refused with exit code 1, and the binary stays
unchanged.

### `meshly reset [--yes]`

Stops the link and removes the configuration, keys, runtime state, configuration history and units from this node.
The binary and the operation journal stay. If `/etc/iptables/rules.v4` or `rules.v6` still contains meshly's iptables
rule (saved with `netfilter-persistent save`), `reset` warns: run `sudo netfilter-persistent save` again.
With a missing or unreadable configuration, owned WireGuard interfaces are discovered by their ownership markers,
including custom names. Their traffic paths close before the shared firewall is removed. A failure keeps firewall
protection and reports failure; foreign interfaces remain untouched.

### `meshly recover`

Finishes or rolls back an operation interrupted by a crash or power loss. Every command does this first, so this
command is rarely needed by hand.
Safe mode leaves the transaction pending until recovery saves and applies its intended configuration. A pending
access-removing operation completes before drift repair can restore any older configuration.

### `meshly service start|stop|reload|check|install|watch`

Entry points for `meshly.service`, `meshly-check.service` and `meshly-watch.service`. They are not meant to be run
by hand. `install` rewrites the unit files for the current binary path. `watch` runs until it is stopped: it follows
interface and nftables changes and runs the same check as `check` a few seconds after each (see
[diagnostics-and-recovery.md](diagnostics-and-recovery.md#drift-and-the-check-timer)).

## Exit codes

Exit codes are stable and safe to use in scripts.

| Code | Name | Meaning |
|---|---|---|
| 0 | ok | Success; for `doctor`: no problems |
| 1 | error | Unexpected error |
| 2 | usage | Invalid command line |
| 3 | preflight | Unsupported or unprepared environment. **Nothing was changed** |
| 4 | invalid-code | Invite code rejected: damaged or incomplete, from another meshly version, expired, made on this node, or already used. Nothing was changed |
| 5 | conflict | Ownership, address or state conflict (e.g. unknown peer, the name is taken, an invite on a node that joined or in a full network). Nothing was changed |
| 6 | busy | Another meshly operation holds the lock, for example a waiting `meshly invite` |
| 7 | rolled-back | Apply failed and the previous configuration is active again (also: upgrade rolled back; `join` rolled back because the new tunnel could not be confirmed) |
| 8 | safe-mode | Apply and rollback failed: the VPN interface was removed and VPN access is closed |
| 9 | not-initialized | meshly is not initialized on this node |
| 10 | declined | Confirmation missing (no terminal and no `--yes`) or answered "no"; Ctrl+C, SIGTERM or a hang-up of the terminal during `invite` or `join`. Ctrl+C before they change anything (while waiting for the lock, during the preflight or at the `Invite code:` prompt) ends them as usual, with 130 |
| 11 | warnings | `doctor`: warnings only |
| 12 | problems | `doctor`: at least one problem |
| 13 | unreachable | The other node did not answer: `join` got no answer from the inviting node (nothing was changed), the invite expired before a node joined, or `ping` got no reply |

## JSON output

`status`, `nodes`, `ping`, `doctor`, `rules` and `logs` accept `--json`, and each document carries a `schema` field. Within a schema
version, fields are only added, never renamed or removed; a breaking change gets a new version. `version --json`
prints `{"version", "commit", "go", "os", "arch"}`.

| Command | Schema |
|---|---|
| `status --json` | `meshly.status/v1` |
| `nodes --json` | `meshly.nodes/v1` |
| `ping --json` | `meshly.ping/v1` |
| `doctor --json` | `meshly.doctor/v1` |
| `rules --json` | `meshly.rules/v1` |
| `logs --json` | `meshly.logs/v1` |

An abridged `meshly.status/v1` example:

```json
{
  "schema": "meshly.status/v1",
  "initialized": true,
  "privileged": true,
  "operation_in_progress": false,
  "config": {
    "revision": 4, "admin_state": "up", "network_name": "homelab", "cidr": "10.100.0.0/24",
    "name": "vps", "address": "10.100.0.1", "listen_port": 51820, "endpoint": "203.0.113.10:51820",
    "wg_public_key": "bWcWhZaUNdCDGVVlpXq8o/ep9g9jtumd2jC7Zsju9C4=", "interface": "meshly0", "mtu": 1420,
    "firewall_profile": "none",
    "rules": [{"peer": "home", "proto": "tcp", "port": 22, "rule": "allow 22/tcp from home", "meaning": "…"}]
  },
  "service": {"systemd": true, "installed": true, "active": "active", "enabled": "enabled", "check_timer_active": "active"},
  "interface": {"name": "meshly0", "exists": true, "owned": true, "up": true, "public_key_matches_config": true},
  "firewall": {"profile": "none", "table_present": true, "owned": true, "matches_config": true, "modified_outside_meshly": false},
  "peers": [{
    "name": "home", "address": "10.100.0.2", "wg_public_key": "Z4YzTt5wXZdSfsyoVJhIk0Q8KYaqf3moKZi95pr9DmA=",
    "in_wireguard": true, "allowed_ips_ok": true, "route_ok": true,
    "handshake_age_seconds": 6, "rx_bytes": 180, "tx_bytes": 124,
    "connectivity": "handshake-recent", "services_it_may_use_here": ["ping", "22/tcp"]
  }],
  "transaction": {"incomplete": false, "last_op": "allow", "last_event": "commit"},
  "drift": []
}
```

`config.wg_public_key` and `peers[].wg_public_key` are the WireGuard public keys; compare them across two nodes to
check that each knows the other's key. On a host with UFW, iptables rules or Docker, `firewall.iptables_chains`
lists the chains that carry meshly's rule (`chain`, `meshly_rule_present`, `meshly_rule_first`). On a node with
Docker networks, `firewall.docker_networks` lists them, for example `["br-3f1c2a9b7d01", "docker0"]`, and
`firewall.forward_findings` the forward chains that may drop container traffic, for example `["inet filter forward"]`
(`meshly doctor` has the fix); without them the fields are absent. `peers[].connectivity` is one of `handshake-recent`, `handshake-stale`,
`no-handshake` or `unknown`.

While `meshly invite` waits, the document has `"invite": {"expires_at": "2026-10-18T20:40:00Z"}` and
`operation_in_progress` is `true`. `drift` stays empty, because the drift check is skipped: the invite's temporary
peer and firewall rule are not part of the saved configuration, so `firewall.matches_config` is `false` meanwhile.
Without an open invite there is no `invite` field. The code is never in the document.

A `meshly.nodes/v1` document has `network`, `cidr` and `nodes[]`, this node first. Each node has:

- `name`, `this_node`, `vpn_address` and `public_address`;
- `connection`: one of `this-node`, `online`, `offline`, `idle`, `never-connected`, `link-stopped` or `unknown`;
- `last_seen` and `last_seen_seconds_ago`;
- `may_use_here`, for example `["ping", "22/tcp"]`.

A `meshly.ping/v1` document has:

- `node`, `address`, `from` and `from_address`;
- `sent` and `received`;
- `packets[]`, each with `seq`, `reply` and `rtt_ms`;
- `min_ms`, `avg_ms` and `max_ms`, when a reply came;
- `diagnosis`, when none came. Then the exit code is 13.

A `meshly.doctor/v1` document has `findings[]`, each with `id`, `status` (`ok`, `info`, `warn`, `fail`),
`certainty`, `detail` and `fix`, plus a `summary`.

## Files and environment

| Path | Mode | Contents |
|---|---|---|
| `/etc/meshly/meshly.json` | `0644` | Configuration (no secrets) |
| `/etc/meshly/keys/` | `0700` | `wireguard.key` (`0600`) |
| `/var/lib/meshly/` | `0700` | `journal.jsonl`, `runtime.json` (applied table hash, learned peer endpoints), `history/` |
| `/run/meshly/` | `0700` | Operation lock; `invite.json` (`0600`) while `meshly invite` waits, holding only its expiry |
| `/etc/systemd/system/meshly*.{service,timer}` | `0644` | Units installed by meshly |
| `/etc/systemd/system/{nftables,netfilter-persistent,docker}.service.d/50-meshly.conf` | `0644` | Drop-ins that re-apply meshly after these services start |

meshly reads no configuration from the environment. Under `sudo`, `SUDO_USER` is recorded in the journal.
`install.sh` honours `MESHLY_VERSION` and `MESHLY_BASE_URL` (a mirror of the GitHub releases).
