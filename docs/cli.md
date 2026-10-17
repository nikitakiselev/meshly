# CLI reference

`meshly <command> [arguments]`. All commands that change the system require root. `status`, `rules`, `version`
and `help` also work without root, with reduced detail. Every changing command takes a lock: a second meshly
operation waits briefly and then fails with exit code 6. `init`, `join`, `approve`, `activate`, `allow`, `deny`,
`revoke`, `start`, `stop` and `set` accept `--dry-run`, which prints the plan, the rendered nftables table and the
config diff, and changes nothing.

`meshly help <command>` prints the same help as below. Secrets are never accepted as arguments, never printed and
never written to JSON output.

- [Network setup](#network-setup): `init`, `invite`, `join`, `approve`, `activate`
- [Access policy](#access-policy): `allow`, `deny`, `rules`, `revoke`
- [Link lifecycle](#link-lifecycle): `start`, `stop`, `restart`, `set`
- [Information](#information): `status`, `doctor`, `logs`, `version`
- [Maintenance](#maintenance): `upgrade`, `reset`, `recover`, `service`
- [Exit codes](#exit-codes)
- [JSON output](#json-output)
- [Files and environment](#files-and-environment)

## Network setup

The protocol behind these commands is specified in [bootstrap-protocol.md](bootstrap-protocol.md).

### `meshly init <network> --name <node> [--endpoint IP:PORT] [options]`

Creates a network on this node and brings up the protected interface. It is usually run on the server whose UDP
port is reachable from the internet. Keys are generated locally.

| Flag | Default | Meaning |
|---|---|---|
| `--name NAME` | (required) | Node name: `a-z`, `0-9`, `-` |
| `--endpoint IP:PORT` | none | Public UDP endpoint the other node connects to. Numeric only; host names are not supported |
| `--listen-port PORT` | endpoint port or `51820` | Local UDP port |
| `--cidr CIDR` | `10.100.0.0/24` | VPN network: private IPv4, `/16`–`/30`, must not overlap local addresses or routes |
| `--mtu N` | `1420` | Interface MTU |
| `--interface NAME` | `meshly0` | Interface name |
| `--firewall PROFILE` | `auto` | `auto`, `none` or `nftables`; see [firewall.md](firewall.md) |
| `--dry-run` | | Show what would change |

Preflight runs first. If the environment is unsupported (no kernel WireGuard, nftables older than 1.0.6, ufw,
firewalld, iptables-legacy rules, a foreign drop chain without integration, a CIDR conflict or a busy port), init
stops with exit code 3 and changes nothing.

### `meshly invite [--out FILE] [--ttl DURATION] [--new] [--force]`

Creates a one-time invite for the second node. It is valid for 1 hour by default (`--ttl` accepts `1m` to `24h`).
Running it again returns the same unused invite. `--new` cancels it and creates a fresh one. The file defaults to
`peer.invite`, `-` writes to stdout, and the file mode is `0600`: whoever holds the file can submit a join request
until it expires. Under `sudo`, output files belong to the invoking user, so you can `scp` them without root.

### `meshly join <invite-file> --name <node> [options]`

Verifies the invite, shows the inviter's fingerprint and asks you to confirm it by typing `yes`. It then generates
this node's keys and writes a signed join request. Nothing is trusted or changed in the network configuration yet.

| Flag | Default | Meaning |
|---|---|---|
| `--name NAME` | (required) | Name of this node |
| `--out FILE` | `<name>.request` | Request file (`-` = stdout) |
| `--expect-fingerprint FP` | | Inviter fingerprint. **Required when stdin is not a terminal** |
| `--endpoint IP:PORT` | none | Public endpoint of this node, if it has one |
| `--listen-port PORT` | `51820` or a free port | Local UDP port |
| `--keepalive SECONDS` | `25` | Keepalive towards the inviter. The inviter always uses 25 towards this node |
| `--interface NAME`, `--firewall PROFILE` | | As for `init` |
| `--force` | | Replace an existing `--out` file that has different content |

`<invite-file>` may be `-` to read from stdin. Input files must be regular files (symlinks and FIFOs are refused)
of at most 64 KiB.

### `meshly approve <request-file> [--out FILE] [--expect-fingerprint FP] [--force] [--dry-run]`

Shows the candidate's name, fingerprint, keys, assigned address and request id, and asks for an explicit `yes`.
In non-interactive use, `--expect-fingerprint` is mandatory. On approval, the peer is added to WireGuard with one
allowed IP (`/32`) and no service is opened. The command then writes `<name>.accept`. Running it again with the
same request rewrites the same accept file until the request expires.

### `meshly activate <accept-file> [--dry-run]`

Activates the membership on the joining node. Only the accept that answers this node's own pending request is
accepted. On success the link comes up, autostart is enabled, and inbound VPN traffic stays denied until
`meshly allow`.

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
| `endpoint` | `IP:PORT` or `none` | This node's public endpoint (used in new invites) |
| `peer-endpoint` | `<peer> IP:PORT` or `<peer> none` | Where to reach the peer, e.g. after the VPS changed its IP |
| `cidr` | `CIDR` | VPN network; only before a peer joined |

## Information

### `meshly status [--json]`

Shows the saved configuration, the service state, the interface, the firewall table, each peer (handshake age,
traffic counters, endpoint, the rules it may use), interrupted operations and drift between configuration and
kernel. The systemd state is shown separately and says nothing about connectivity. Without root, kernel and key
details are omitted.

### `meshly doctor [--json] [--probe <port>/<tcp|udp>] [--peer NAME]`

Runs every check and prints one line per finding: `✓` ok, `·` info, `!` warning, `✗` problem. Each finding has
a certainty: `observed` (a measured fact), `likely` or `possible` (inferred), and a fix where one is known.
`--probe` connects from this node's VPN address to a service on the peer. For TCP it tells apart "connected",
"refused" (allowed, nothing listens), "timed out with a recent handshake" (the peer's policy does not allow the
port) and "timed out without a handshake" (peer down or unreachable). For UDP, silence is inconclusive. It opens
nothing locally. Check ids and runbooks are in
[diagnostics-and-recovery.md](diagnostics-and-recovery.md).

### `meshly logs [-n N] [--json]`

Shows the operation journal: who (uid, sudo user) did what, begin/commit/rollback/recovery/safe-mode events.
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

`--check` only reports whether a newer release exists. Downgrades are refused unless `--force` is given. The
version is taken only from the signed `SHA256SUMS`, so an old signed release cannot be replayed as a new one.

### `meshly reset [--yes]`

Stops the link and removes the configuration, keys, bootstrap state and units from this node. The binary and the
operation journal stay.

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
| 4 | invalid-file | Bootstrap file rejected: signature, binding, expiry, replay or schema |
| 5 | conflict | Ownership, address or state conflict (e.g. unknown peer, existing output file). Nothing was changed |
| 6 | busy | Another meshly operation holds the lock |
| 7 | rolled-back | Apply failed and the previous configuration is active again (also: upgrade rolled back) |
| 8 | safe-mode | Apply and rollback failed: the VPN interface was removed and VPN access is closed |
| 9 | not-initialized | meshly is not initialized on this node |
| 10 | declined | Confirmation missing (no terminal and no `--yes`/`--expect-fingerprint`) or answered "no" |
| 11 | warnings | `doctor`: warnings only |
| 12 | problems | `doctor`: at least one problem |

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
    "name": "vps", "address": "10.100.0.1", "listen_port": 51820, "interface": "meshly0", "mtu": 1420,
    "firewall_profile": "none",
    "rules": [{"peer": "home", "proto": "tcp", "port": 22, "rule": "allow 22/tcp from home", "meaning": "…"}]
  },
  "service": {"systemd": true, "installed": true, "active": "active", "enabled": "enabled", "check_timer_active": "active"},
  "interface": {"name": "meshly0", "exists": true, "owned": true, "up": true, "public_key_matches_config": true},
  "firewall": {"profile": "none", "table_present": true, "owned": true, "matches_config": true, "modified_outside_meshly": false},
  "peers": [{
    "name": "home", "address": "10.100.0.2", "in_wireguard": true, "allowed_ips_ok": true, "route_ok": true,
    "handshake_age_seconds": 6, "rx_bytes": 180, "tx_bytes": 124,
    "connectivity": "handshake-recent", "services_it_may_use_here": ["ping", "22/tcp"]
  }],
  "transaction": {"incomplete": false, "last_op": "allow", "last_event": "commit"},
  "drift": []
}
```

`peers[].connectivity` is one of `handshake-recent`, `handshake-stale`, `no-handshake` or `unknown`. A
`meshly.doctor/v1` document has `findings[]`, each with `id`, `status` (`ok`, `info`, `warn`, `fail`),
`certainty`, `detail` and `fix`, plus a `summary`.

## Files and environment

| Path | Mode | Contents |
|---|---|---|
| `/etc/meshly/meshly.json` | `0644` | Configuration (no secrets) |
| `/etc/meshly/keys/` | `0700` | `wireguard.key`, `identity.key` (`0600`) |
| `/var/lib/meshly/` | `0700` | `journal.jsonl`, `bootstrap.json`, `runtime.json` (applied table hash, learned peer endpoints), `history/` |
| `/run/meshly/` | `0700` | Operation lock |
| `/etc/systemd/system/meshly*.{service,timer}` | `0644` | Units installed by meshly |

meshly reads no configuration from the environment. Under `sudo`, `SUDO_UID`/`SUDO_GID` decide who owns the
bootstrap files it writes, and `SUDO_USER` is recorded in the journal. `install.sh` honours `MESHLY_VERSION` and
`MESHLY_BASE_URL` (a mirror of the GitHub releases).
