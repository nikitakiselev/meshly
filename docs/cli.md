# CLI reference

`meshly <command> [arguments]`. All commands that change the system require root. `status`, `rules`, `version`
and `help` also work without root, with reduced detail. Every changing command takes a lock: a second meshly
operation waits briefly and then fails with exit code 6. `init`, `allow`, `deny`, `revoke`, `start`, `stop` and
`set` accept `--dry-run`, which prints the plan, the rendered nftables table and the config diff, and changes nothing.

`meshly help <command>` prints the same help as below. Secrets are never accepted as arguments and never written to
logs or JSON output. Private keys are never printed; the invite code is printed once, by `meshly invite`.

- [Network setup](#network-setup): `init`, `invite`, `join`
- [Access policy](#access-policy): `allow`, `deny`, `rules`, `revoke`
- [Link lifecycle](#link-lifecycle): `start`, `stop`, `restart`, `set`
- [Information](#information): `status`, `doctor`, `logs`, `version`
- [Maintenance](#maintenance): `upgrade`, `reset`, `recover`, `service`
- [Exit codes](#exit-codes)
- [JSON output](#json-output)
- [Files and environment](#files-and-environment)

## Network setup

The second node joins with a one-time code: run `meshly invite` on the node with the public endpoint and
`meshly join` on the other one. The protocol behind these commands is specified in
[pairing-protocol.md](pairing-protocol.md).

### `meshly init <network> --name <node> [--endpoint IP[:PORT]|auto|none] [options]`

Creates a network on this node and brings up the protected interface. It is usually run on the server whose UDP
port is reachable from the internet. Keys are generated locally.

| Flag | Default | Meaning |
|---|---|---|
| `--name NAME` | (required) | Node name: `a-z`, `0-9`, `-` |
| `--endpoint ADDR` | `auto` | Public address the other node connects to: `IP` or `IP:PORT` (numeric; host names are not supported; the port defaults to `--listen-port`), `auto` or `none`. See [Endpoint detection](#endpoint-detection) |
| `--listen-port PORT` | endpoint port or `51820` | Local UDP port |
| `--cidr CIDR` | `10.100.0.0/24` | VPN network: private IPv4, `/16`–`/30`, must not overlap local addresses or routes |
| `--mtu N` | `1420` | Interface MTU |
| `--interface NAME` | `meshly0` | Interface name |
| `--firewall PROFILE` | `auto` | `auto`, `none` or `nftables`; see [firewall.md](firewall.md) |
| `--dry-run` | | Show what would change |

Preflight runs first. If the environment is unsupported (no kernel WireGuard, nftables older than 1.0.6, ufw,
firewalld, iptables-legacy rules, a foreign drop chain without integration, a CIDR conflict or a busy port), init
stops with exit code 3 and changes nothing.

init ends with what to do next: `sudo meshly invite` on this node and `sudo meshly join` on the other. Without an
endpoint it says that no other node can join until this node has one (`meshly set endpoint IP`).

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

Waits for the second node to join this network. Run it on the node the other one reaches over UDP: it needs a
public endpoint (exit code 2 otherwise, with a hint to `meshly set endpoint IP`), a running link (exit code 5 after
`meshly stop`, with a hint to `meshly start`) and no peer yet (exit code 5; `meshly revoke` the old one first).

| Flag | Default | Meaning |
|---|---|---|
| `--ttl DURATION` | `10m` | How long the code is valid: `1m` to `1h` |

```console
$ sudo meshly invite
Waiting for a node to join network "homelab" until 20:40 UTC (10 minutes). Ctrl+C cancels.
On the other node run `sudo meshly join` and paste this code:

m1atfqa4ikzjwg2zywqwljinoqqmmvkznfpk6kh55j6yhwhnxjtxndbo3gzdxpilqkmqaaagdk2uxkasjvuxzmxu2ljlylk2tq5xtgw2omnywbs

Node "home" (10.100.0.2) joined. The invite is closed.
```

- **Output.** stdout gets the code, alone on one line, and at the end the `Node … joined` line. The code is `m1`
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
Invite code: m1atfqa4ikzjwg2zywqwljinoqqmmvkznfpk6kh55j6yhwhnxjtxndbo3gzdxpilqkmqaaagdk2uxkasjvuxzmxu2ljlylk2tq5xtgw2omnywbs
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
| 5 | This node is already a member of a network, or the name is taken (it is the inviting node's) | unchanged |
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

### `meshly deny <port>/<tcp|udp> from <peer>` · `meshly deny ping from <peer>`

Removes the rule. Policy is evaluated per packet, so packets of connections that are already established are
dropped as well.

### `meshly rules [--json]`

Lists the rules of this node, each with its meaning in words.

### `meshly revoke <peer> [--yes] [--dry-run]`

Closes all access of the peer first (firewall), then removes it from WireGuard and routing. It asks for
confirmation unless `--yes` is given. After a revoke, the network can accept a new peer through a new invite.

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
| `mtu` | `1280`–`8920` | Set the same value on both nodes |
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
firewall table as `present, with the open invite's temporary rules`.

### `meshly doctor [--json] [--probe <port>/<tcp|udp>] [--peer NAME]`

Runs every check and prints one line per finding: `✓` ok, `·` info, `!` warning, `✗` problem. Each finding has
a certainty: `observed` (a measured fact), `likely` or `possible` (inferred), and a fix where one is known.
`--probe` connects from this node's VPN address to a service on the peer. For TCP it tells apart "connected",
"refused" (allowed, nothing listens), "timed out with a recent handshake" (the peer's policy does not allow the
port) and "timed out without a handshake" (peer down or unreachable). For UDP, silence is inconclusive. It opens
nothing locally. Check ids and runbooks are in
[diagnostics-and-recovery.md](diagnostics-and-recovery.md).

### `meshly logs [-n N] [--json]`

Shows the operation journal: who (uid, sudo user) did what, begin/commit/rollback/recovery/safe-mode events, and
audit records such as an invite opened and closed.
`-n` must be ≥ 1 (default 30). Service output is in `journalctl -u meshly -u meshly-check`.

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
6. Reinstall the units and restart `meshly.service`. If the service does not come back, the previous binary is
   restored and restarted, and the command exits with code 7.

`--check` only reports whether a newer release exists. Downgrades are refused unless `--force` is given (exit code
5). The version is taken only from the signed `SHA256SUMS`, so an old signed release cannot be replayed as a new
one. A release that fails the signature or checksum verification is refused with exit code 1, and the binary stays
unchanged.

### `meshly reset [--yes]`

Stops the link and removes the configuration, keys, runtime state, configuration history and units from this node.
The binary and the operation journal stay.

### `meshly recover`

Finishes or rolls back an operation interrupted by a crash or power loss. Every command does this first, so this
command is rarely needed by hand.

### `meshly service start|stop|reload|check|install`

Entry points for `meshly.service` and `meshly-check.service`. They are not meant to be run by hand. `install`
rewrites the unit files for the current binary path.

## Exit codes

Exit codes are stable and safe to use in scripts.

| Code | Name | Meaning |
|---|---|---|
| 0 | ok | Success; for `doctor`: no problems |
| 1 | error | Unexpected error |
| 2 | usage | Invalid command line |
| 3 | preflight | Unsupported or unprepared environment. **Nothing was changed** |
| 4 | invalid-code | Invite code rejected: damaged or incomplete, from another meshly version, expired, made on this node, or already used. Nothing was changed |
| 5 | conflict | Ownership, address or state conflict (e.g. unknown peer, a peer already exists, the name is taken). Nothing was changed |
| 6 | busy | Another meshly operation holds the lock, for example a waiting `meshly invite` |
| 7 | rolled-back | Apply failed and the previous configuration is active again (also: upgrade rolled back; `join` rolled back because the new tunnel could not be confirmed) |
| 8 | safe-mode | Apply and rollback failed: the VPN interface was removed and VPN access is closed |
| 9 | not-initialized | meshly is not initialized on this node |
| 10 | declined | Confirmation missing (no terminal and no `--yes`) or answered "no"; Ctrl+C, SIGTERM or a hang-up of the terminal during `invite` or `join`. Ctrl+C before they change anything (while waiting for the lock, during the preflight or at the `Invite code:` prompt) ends them as usual, with 130 |
| 11 | warnings | `doctor`: warnings only |
| 12 | problems | `doctor`: at least one problem |
| 13 | unreachable | The other node did not come: `join` got no answer from the inviting node (nothing was changed), or the invite expired before a node joined |

## JSON output

`status`, `doctor`, `rules` and `logs` accept `--json`, and each document carries a `schema` field. Within a schema
version, fields are only added, never renamed or removed; a breaking change gets a new version. `version --json`
prints `{"version", "commit", "go", "os", "arch"}`.

| Command | Schema |
|---|---|
| `status --json` | `meshly.status/v1` |
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

`config.wg_public_key` and `peers[].wg_public_key` are the WireGuard public keys; compare them across the two nodes
to check that each knows the other's key. `peers[].connectivity` is one of `handshake-recent`, `handshake-stale`,
`no-handshake` or `unknown`.

While `meshly invite` waits, the document has `"invite": {"expires_at": "2026-10-18T20:40:00Z"}` and
`operation_in_progress` is `true`. `drift` stays empty, because the drift check is skipped: the invite's temporary
peer and firewall rule are not part of the saved configuration, so `firewall.matches_config` is `false` meanwhile.
Without an open invite there is no `invite` field. The code is never in the document.

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

meshly reads no configuration from the environment. Under `sudo`, `SUDO_USER` is recorded in the journal.
`install.sh` honours `MESHLY_VERSION` and `MESHLY_BASE_URL` (a mirror of the GitHub releases).
