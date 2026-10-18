# Architecture and decisions

meshly is a single static Go binary that turns a small declarative
configuration (`/etc/meshly/meshly.json`) into kernel state on one Linux host:
a WireGuard interface, its address and host routes, a few per-interface
sysctls, and one nftables table. Every change runs as a journaled transaction
that either completes, rolls back, or closes the VPN path (safe mode). This
document describes how that works and why it was built that way. Related
documents: [pairing protocol](pairing-protocol.md),
[threat model](threat-model.md), [firewall](firewall.md),
[CLI reference](cli.md), [diagnostics and recovery](diagnostics-and-recovery.md),
[testing](testing.md).

## Scope

- Exactly two nodes per network in this version (`model.MaxPeers = 1`):
  typically a VPS with a reachable UDP port and a home server behind NAT.
- IPv4 inside the VPN (default `10.100.0.0/24`, each node a `/32`).
- Kernel WireGuard, nftables ≥ 1.0.6, systemd. Target distributions:
  Debian 12 and Ubuntu 24.04 on amd64 and arm64 (what was actually tested
  where is listed in [testing.md](testing.md)).
- meshly controls only what a peer may reach on *this* node through the
  VPN. It does not manage cloud firewalls, routers, or the host's public
  firewall.

## Package layout

| Path | Responsibility |
|---|---|
| `cmd/meshly` | `main`: builds the application and calls `cli.App.Main`. |
| `internal/cli` | Command parsing, user output, exit codes; wires preflight → engine → systemd. |
| `internal/model` | Configuration types, validation, rule parsing, address allocation, CIDR conflict detection. |
| `internal/store` | Files on disk: atomic fsync'ed writes, ownership/permission checks, config history, keys, runtime state, the marker of an open invite. |
| `internal/journal` | Append-only JSONL transaction log; also the audit trail shown by `meshly logs`. |
| `internal/lock` | `flock(2)` serialisation of mutating operations. |
| `internal/engine` | Observe → plan → apply → verify; transactions, recovery, safe mode, drift detection, temporary overlays. |
| `internal/engine/enginetest` | In-memory fake kernel (links, WireGuard, nft) for unit tests. |
| `internal/netstack` | Interface, address, routes and per-interface sysctls over rtnetlink. |
| `internal/wg` | WireGuard configuration over generic netlink (wgctrl). |
| `internal/nft` | Renders the meshly table, runs `nft`, parses `nft -j list ruleset`, analyses foreign chains. |
| `internal/preflight` | Capability and compatibility checks before any change. |
| `internal/diag` | `meshly status` and `meshly doctor` reports. |
| `internal/pairing` | The invite code (format, temporary keys derived from it) and the messages `invite` and `join` exchange. |
| `internal/systemd` | Unit files embedded in the binary; `systemctl` control. |
| `internal/upgrade` | Release download, signature and hash verification, binary replacement. |
| `internal/fault` | Fault injection points (compiled to no-ops in release builds). |
| `internal/version` | Version and commit injected at build time. |
| `tools/release` | Release key generation and signing of `SHA256SUMS`. |
| `test/integration` | Docker-based multi-node lab (build tag `integration`). |

## Data on disk

All managed paths must be real directories/files (symlinks are refused),
owned by root, and no more permissive than listed. Every write goes to a
temporary file in the same directory, is fsync'ed, renamed over the target,
and the directory is fsync'ed.

| Path | Mode | Content |
|---|---|---|
| `/etc/meshly/` | 0755 | |
| `/etc/meshly/meshly.json` | 0644 | Desired configuration: network, this node, peer, rules, admin state, revision. Public data only. |
| `/etc/meshly/keys/` | 0700 | |
| `/etc/meshly/keys/wireguard.key` | 0600 | WireGuard private key. |
| `/var/lib/meshly/` | 0700 | |
| `/var/lib/meshly/journal.jsonl` | 0600 | Transaction journal. Rotated at 4 MiB to `journal.jsonl.1` (one previous generation), never while an operation is open. |
| `/var/lib/meshly/history/meshly-<rev>.json` | 0600 | Copy of each saved configuration revision; the newest 20 are kept. |
| `/var/lib/meshly/runtime.json` | 0600 | Non-authoritative runtime state: hash of the meshly table as read back after the last apply, and `peer_endpoints` (endpoint hints, see below). |
| `/run/meshly/lock` | 0600 | Operation lock (`/run/meshly` is 0700). |
| `/run/meshly/invite.json` | 0600 | Marker of an open `meshly invite`: only its expiry, never the code. Removed when the invite ends; a marker left by a killed invite is removed by the next command that takes the lock. `/run` is emptied at boot. |
| `/usr/local/bin/meshly` (+ `.prev`) | 0755 | Binary, installed by `install.sh`; `.prev` is kept by `meshly upgrade`. |

Private keys are read only when needed, wiped from memory afterwards, never
passed in argv, never printed (`Keys.String()` returns `[redacted keys]`),
and never included in status, doctor or the journal. The invite code and the
temporary keys derived from it live only in the memory of `invite` and
`join` and are wiped when they end; the code is printed once, by
`meshly invite`, and never saved or journaled.

## Kernel state and how it is applied

meshly never runs a shell and never executes user-supplied commands.

- **Interface, addresses, routes, sysctls**: rtnetlink via
  `vishvananda/netlink`. Ownership is explicit: the interface must be of type
  `wireguard` with the alias `meshly:<network-id>`, and routes carry the
  routing protocol number 109. Objects without these markers are never
  modified or removed; a name clash is reported as a conflict (exit 5).
  Sysctls are per-interface only (`forwarding=0`, `rp_filter=1`, no
  redirects or source routing, `disable_ipv6=1`); no global sysctl is
  changed.
- **WireGuard**: generic netlink via `wgctrl`. The private key travels only
  over netlink. Each peer gets exactly its `/32` as allowed IP.
- **nftables**: the fixed binary `/usr/sbin/nft` with fixed argument vectors
  (`--version`, `-c -f -`, `-f -`, `-j list ruleset`), the ruleset on stdin,
  and a minimal environment. Every value in the rendered table is typed and
  validated (interface names, `netip` addresses, ports), so no free-form
  string reaches the ruleset. A change is first checked with `nft -c`, then
  applied as one transaction:

  ```
  table inet meshly
  delete table inet meshly
  table inet meshly { ... }
  ```

  The first rule of `guard_pre` carries the ownership marker
  `meshly:v1 net=<network-id> hash=<policy-hash>`. After applying, meshly
  reads the table back, checks the marker hash, and records a normalised hash
  of the live table in `runtime.json`; a different live hash later means the
  table was modified outside meshly and is repaired. See
  [firewall.md](firewall.md) for the chains and the packet path.
- **systemd**: `/usr/bin/systemctl` with fixed argument vectors.

## Engine: plan, transaction, verify

`engine.DesiredFrom` derives the desired kernel state from a configuration
(nothing at all for a missing configuration or admin state `down`).
`Observe` reads the current state, and `Plan` produces an ordered list of
steps, each with a name (used by the journal and by fault injection) and a
human description (printed while applying and by `--dry-run`).

Ordering invariants:

- Bring-up: `firewall.apply` → `link.create` (down) → `link.alias` /
  `link.mtu` → `link.sysctl` → `link.address` → `wireguard.configure` →
  `link.up` → `routes.sync`. Protection exists before any traffic path.
- Tear-down: `link.down` → `link.delete` (with its peers and routes) →
  `firewall.remove`. The traffic path goes first, the protective table last.

Only the steps needed for the difference are planned, so repeating a command
is a no-op ("kernel state already matches").

`Engine.Execute` runs one operation:

1. Validate the target configuration (revision = base + 1); plan. If neither
   the configuration nor the kernel would change, return without journaling.
2. Append a fsync'ed `begin` record with the operation, audit arguments,
   actor (uid, `SUDO_USER`), recovery direction, base revision, interface,
   plan, and the complete target configuration.
3. For **forward** operations, save the target configuration first
   (write-ahead).
4. Run the steps.
5. **Verify**: observe again; the plan must now be empty. Verification is
   local. It deliberately does not include connectivity to the peer: a
   correct node may have no handshake because the peer is switched off.
6. For **backward** operations, save the target configuration now.
7. Append `commit`.

Recovery directions:

- **Backward** (operations that grant or restore access: `init`, `invite`
  (adding the joining node), `join`, `allow`, `start`, `restart`, `set`,
  service start/reload, check-repair). On failure the engine reconciles back
  to the base configuration and re-saves it, recording `rolled-back`
  (exit 7).
- **Forward** (operations that reduce access: `deny`, `revoke`, `stop`,
  `reset`, `invite-undo` and `join-undo`, which remove a joined node that
  did not confirm the connection). On failure the engine retries reconciling
  to the target and records `commit` with "completed after retry". An
  interruption must never re-open access that the administrator removed.

If the rollback or retry also fails, the engine enters **safe mode**,
records `safe-mode` and exits with 8: it applies a lockdown table (same
guards, no peers and no allow rules, so everything on the interface is
dropped), but only if no foreign table with the same name exists, then
deletes the interface (falling back to removing all peers). Nothing else is
touched and the saved configuration is kept. `meshly start` re-applies it.

Ownership conflicts (a foreign interface or table with meshly's name) are
never "repaired": the operation stops with exit 5 and nothing is changed.

### Temporary overlays

Pairing needs kernel state that belongs to no saved configuration: the
temporary peer and firewall rule of an open invite, and the joining node's
temporary tunnel. An `engine.Overlay` adds an extra WireGuard peer (with a
preshared key), extra `allow_in` entries, or a replacement private key on
top of a configuration. `ApplyOverlay` reconciles to the configuration plus
the overlay and verifies it; on failure it restores the plain
configuration. An overlay is never saved, journaled or printed, and an
operation that carries one (`Op.Overlay`) rolls back and recovers without
it. Removing an overlay is a plain reconcile to the saved configuration (or
to none, on a node that has not joined yet), so anything that re-applies the
configuration (the check timer, `meshly start`, a reboot) also removes a
leftover one.

### Recovery of interrupted operations

An operation whose `begin` has no terminal record (`commit`, `rolled-back`,
`safe-mode`, `recovered`) was interrupted, for example by a crash or power
loss. Every mutating command takes the lock and then calls
`Engine.Recover` before doing anything else, and so do `meshly service start`
(boot) and the check timer:

- the saved configuration equals the journaled target → the operation had
  committed its configuration: reconcile the kernel to it (`completed`, or
  `rolled-forward` for forward operations);
- forward operation not yet saved → save the target, reconcile
  (`rolled-forward`);
- backward operation not saved → reconcile to the saved (base) configuration
  (`rolled-back`).

If reconciling fails, recovery enters safe mode. The result is journaled as
`recovered` with the mode. `meshly recover` runs only this step.

### Locking

Mutating commands take an exclusive `flock` on `/run/meshly/lock`, waiting
up to 30 seconds, otherwise exit 6. Read-only commands (`status`, `doctor`,
`rules`, `logs`) take no lock; `status` reports `operation_in_progress` from
a non-blocking probe. The check timer never waits: if the lock is held it
does nothing. `upgrade` holds the lock while replacing the binary.
`invite` holds it for its whole wait, so the check timer cannot "repair"
the invite's temporary state away; other changing commands then exit 6 with
a message that names the open invite and its expiry.

## systemd integration

The unit files are embedded in the binary and rendered with the resolved
executable path and interface name. `init`, `join`, `start` and an
`invite` that a node joined install them (only rewriting files whose
content differs), enable and start them;
`meshly service install` rewrites them (used by `upgrade`); `reset` stops,
disables and removes them.

- `meshly.service`: `Type=oneshot`, `RemainAfterExit=yes`, running
  `meshly service start|reload|stop`. `After=nftables.service` because the
  system ruleset usually starts with `flush ruleset`. `PartOf=` and
  `ReloadPropagatedFrom=nftables.service`, so restarting or reloading the
  system firewall restarts or reloads meshly, which re-applies its table.
  `ConditionPathExists=/etc/meshly/meshly.json`.
- `nftables.service.d/50-meshly.conf`: `ExecStartPost=-/usr/bin/systemctl
  --no-block try-reload-or-restart meshly.service`, which covers *starting*
  nftables (not covered by `PartOf`/`ReloadPropagatedFrom`). It does
  nothing when meshly is not active.
- `meshly-check.timer` (2 min after boot, then every minute) runs
  `meshly-check.service` → `meshly service check`: it records learned peer
  endpoints, computes drift, and repairs it in a journaled `check-repair`
  transaction (for example a deleted or modified meshly table, a changed
  sysctl, or the temporary peer of an invite that was killed).
  `Requisite=meshly.service` means the check never starts the link when the
  service is stopped.
- `systemctl stop meshly` tears the link down without changing the
  configuration; `meshly stop` additionally saves admin state `down`, so the
  link stays down across reboots until `meshly start`.
- `/etc/systemd/network/10-meshly-unmanaged.network` and
  `/etc/NetworkManager/conf.d/meshly.conf` (each only if that directory
  exists) tell systemd-networkd and NetworkManager to leave the interface
  alone.
- Hardening of both services: `CapabilityBoundingSet=CAP_NET_ADMIN`,
  `NoNewPrivileges`, `ProtectSystem=strict` with write access only to the
  meshly directories, `ProtectHome`, `PrivateTmp`, `PrivateDevices`,
  `ProtectKernelModules`, `ProtectControlGroups`, `ProtectClock`,
  `ProtectHostname`, `RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET
  AF_INET6`, `RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`,
  `LockPersonality`, `MemoryDenyWriteExecute`, `SystemCallArchitectures=native`.
  `ProtectKernelTunables` stays off because per-interface sysctls are
  written.

## Pairing

The second node joins with a one-time code. `meshly invite`, on the node
with the public endpoint, prints the code, holds the lock and waits (10
minutes by default, at most 1 hour). `meshly join`, on the other node, reads
the code from a prompt or stdin, never from its arguments.

The code carries the inviting node's endpoint and WireGuard public key, the
network CIDR, the expiry and a 128-bit secret. Both nodes derive a temporary
WireGuard key and a preshared key from the secret and build a temporary
tunnel with them (overlays, see above) through the WireGuard port that is
already open. Inside it the joining node sends its name and WireGuard public
key over TCP to the inviting node's VPN address and receives the network's
settings and its address. Each node then commits the other as its peer in a
journaled transaction (`invite` and `join`), the joining node switches to its
own key and confirms the connection through the real tunnel, and the invite
closes. If the confirmation does not come, both sides undo the join
(`invite-undo`, `join-undo`). Every way out of `invite` removes its temporary
state. Details: [pairing-protocol.md](pairing-protocol.md).

## Upgrade

`meshly upgrade` downloads from `github.com/nikitakiselev/meshly/releases`:

1. `SHA256SUMS` and `SHA256SUMS.sig` (size-bounded, HTTPS only). The
   signature is Ed25519 over `"meshly-release/1" || 0x00 || SHA256SUMS` and
   is verified with the public key compiled into the running binary (builds
   without a key refuse to upgrade).
2. The version is taken only from the signed `SHA256SUMS`, which must list
   exactly one version. An older version is refused unless `--force` is
   given, so a replayed old release cannot be installed silently.
3. The binary for this architecture is downloaded and its SHA-256 is checked
   against the signed list.
4. The new binary is written next to the current one, must run and report the
   expected `version --short`, and then replaces the executable by rename.
   The previous binary is kept as `<exe>.prev`. This happens under the
   operation lock.
5. The new binary rewrites the unit files (`meshly service install`). If
   `meshly.service` was active it is restarted and must become active within
   30 seconds. Otherwise the previous binary is restored from `.prev`, the
   service is restarted again, and the command exits with 7.

`install.sh` performs the same signature and hash verification with
`openssl` and `sha256sum` before the first installation. It embeds the
release public key; it is itself fetched over HTTPS, which is the trust
anchor of a first installation.

## Decisions

Each entry: context, decision, consequences.

### D1. One owned nftables table, replaced atomically

- **Context.** Editing a host's existing firewall (rules in other tables,
  `iptables` chains) is fragile and makes uninstalling unsafe.
- **Decision.** meshly owns exactly one table, `inet meshly`, marked by a
  comment rule, and always replaces it as a whole in one nft transaction. It
  never modifies, flushes or deletes other tables, and never uses
  `flush ruleset`. A table with the same name but without the marker is a
  conflict.
- **Consequences.** Packets see either the old or the new policy, never a
  partial one. Removing meshly removes only its own objects. A host
  firewall that drops traffic in its own base chains needs one integration
  rule, added by the administrator (D3).

### D2. Per-packet policy instead of an "established" shortcut

- **Context.** The common `ct state established,related accept` at the top of
  an input chain lets existing connections survive the removal of the rule
  that admitted them.
- **Decision.** For traffic arriving from the VPN, original-direction packets
  are always matched against the `allow_in` set (peer address, protocol,
  port). Only replies to connections *this* node initiated are accepted by
  conntrack state. In the output path, replies of inbound flows are allowed
  only while the same tuple is in `allow_in`.
- **Consequences.** `deny` and `revoke` stop established connections at once
  (tested with a live TCP stream). The cost is one set lookup per packet.

### D3. fwmark integration rule for hosts with their own nftables firewall

- **Context.** An `accept` in one nftables base chain does not stop
  evaluation in other base chains on the same hook. A host firewall with
  `policy drop` therefore drops VPN traffic that meshly accepted.
- **Decision.** Packets accepted by meshly are marked with bit `0x10000000`
  (the bit is cleared first on every packet, so it cannot be pre-set by
  another component). The administrator adds one rule to their own chains,
  before any drop or reject:
  `meta mark & 0x10000000 == 0x10000000 accept comment "meshly"`.
  Profile `auto` picks `nftables` when a foreign chain needs or has this
  rule, otherwise `none`. meshly detects a missing or misplaced rule and
  prints the exact fix.
- **Consequences.** Fail-closed: without the meshly table nothing is marked,
  so the host policy drops what meshly had opened. meshly still edits
  nothing outside its table. Ports that the host firewall itself opens on
  all interfaces remain reachable for the peer in that state, as for any
  internet host (see [firewall.md](firewall.md)).

### D4. Refuse unsupported firewall setups before any change

- **Context.** UFW, firewalld, legacy iptables rules and iptables-nft chains
  that drop traffic manage rules that meshly cannot safely integrate with.
- **Decision.** Preflight detects them (UFW config, firewalld pid file / unit
  state / tables, `ip_tables_names` with rules, iptables-managed base chains)
  and stops with exit 3 and an actionable message, before anything is
  changed, including with `--dry-run`. Operations that only reduce access are
  never blocked; they print a warning instead.
- **Consequences.** meshly does not run on such hosts until the
  administrator switches to native nftables. No automatic firewall
  migration.

### D5. IPv4 only inside the VPN

- **Context.** Two nodes need two addresses. Dual-stack policy, router
  advertisements and link-local addresses would double the policy surface.
- **Decision.** VPN addresses and rules are IPv4. IPv6 on the meshly
  interface is disabled by sysctl and dropped by the table. The outer
  WireGuard endpoint may be an IPv6 address as far as validation is
  concerned.
- **Consequences.** Smaller and easier to verify policy; no IPv6 services
  through the VPN. IPv6 outer transport is not covered by tests
  ([testing.md](testing.md)).

### D6. Keepalive on both sides and learned endpoint hints

- **Context.** The node behind NAT has no stable endpoint. After the public
  node restarted, it had no endpoint for its peer and waited for the peer's
  next handshake; this took 15–40 seconds in the lab.
- **Decision.** Persistent keepalive (25 s) is configured on both sides.
  Endpoints learned from authenticated WireGuard packets (handshake within
  the last 10 minutes) are saved as hints in `runtime.json`
  (`peer_endpoints`) when the link goes down and on every check. When
  configuring a peer without a configured endpoint, an IPv4 hint is used.
- **Consequences.** After a restart the node re-initiates the session itself;
  in the lab, reconnection became immediate. Hints are not authoritative:
  WireGuard roaming still updates the endpoint from authenticated packets. An
  idle link sends one small packet every 25 s in each direction.

### D7. Pairing through the WireGuard port, without a server

- **Context.** A coordination service is an extra component to run, secure
  and trust. A pairing service of meshly's own that listens on the internet,
  even for a few minutes, would be new attack surface. The administrator
  should not have to look up or type addresses, ports or keys.
- **Decision.** The inviting node prints a one-time code with everything the
  joining node needs: endpoint, WireGuard public key, CIDR, expiry and a
  128-bit secret. Keys derived from the secret open a temporary WireGuard
  tunnel to the WireGuard port that is already open, and the two nodes
  exchange keys and settings inside it, over TCP on the inviting node's VPN
  address. The code is the only thing the administrator copies, from one
  terminal to the other.
- **Consequences.** No server, no third party, and nothing new reachable
  from the internet, even while the invite waits. Pairing needs the same UDP
  path as the link itself, so a blocked port shows up at `join` (exit 13)
  rather than later. The code is a bearer secret: whoever uses it first while
  the invite is open joins, and the channel it is copied over is a trust
  boundary ([threat model](threat-model.md)). It is long (111 characters for
  an IPv4 endpoint) because it carries a 32-byte key.

### D8. `start`/`stop`/`restart` and `upgrade` from GitHub releases

These deviate from the original specification and were requested by the
project owner.

- **Context.** The specification named the lifecycle commands `up`/`down` and
  assumed a package manager for updates.
- **Decision.** The lifecycle commands are `start`, `stop` and `restart`, as
  for Linux services. Updates come from signed GitHub releases through
  `meshly upgrade`. The first installation uses `install.sh`; there are no
  distribution packages.
- **Consequences.** The update channel is the GitHub repository plus the
  release key (see the [threat model](threat-model.md)). Updates are
  explicit; there is no automatic update.

### D9. No PostUp/PostDown and no arbitrary commands

- **Context.** Hook commands in VPN configurations (as in `wg-quick`) are a
  common way to run attacker-influenced strings as root and to bypass policy.
- **Decision.** The configuration has no hook or command fields. External
  programs (`nft`, `systemctl`, the new binary during upgrade) are run by
  absolute path with fixed argument vectors and a minimal environment. User
  data never reaches a shell.
- **Consequences.** Customisation happens outside meshly (for example with
  systemd drop-ins for other services), not through meshly's configuration.

### D10. Reproducible, signed release builds

- **Context.** A binary should be checkable against its source by anyone.
- **Decision.** Release builds use `CGO_ENABLED=0`, `-trimpath`, an empty
  build ID and fixed `-ldflags`. `SHA256SUMS` is signed with an Ed25519 key
  kept offline (never in the repository; only `release-key.pub` is
  committed). The `Verify release` workflow rebuilds each published release
  from its tag and compares checksums.
- **Consequences.** The same toolchain version produces identical binaries on
  different hosts. Signing is a manual step on the maintainer's machine
  (`scripts/release.sh`).

### D11. Direction-aware transactions

- **Context.** "Undo on failure" is wrong for access-reducing operations: a
  crash during `revoke` must not restore the revoked peer.
- **Decision.** Each operation declares a recovery direction: backward for
  operations that grant access, forward for operations that reduce it (see
  [Engine](#engine-plan-transaction-verify)). If neither works, safe mode
  closes the VPN path.
- **Consequences.** After any interruption, an access-granting change is
  either fully in effect or not at all, an access-reducing change is always
  completed, or the node is in safe mode with the VPN path closed.
