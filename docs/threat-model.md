# Threat model

This document describes what meshly protects, against whom, how, and where
its protection ends. Each claim names the mechanism and the test that checks
it. **Integration** tests run real kernels, real WireGuard and real
nftables, with every node in its own privileged container and network
namespace (`test/integration`, see [testing](testing.md)). **Unit** tests
run against an in-memory fake kernel or recorded nft output. A claim
without a test is marked *not verified*.

Related: [architecture](architecture.md), [firewall](firewall.md),
[bootstrap protocol](bootstrap-protocol.md),
[diagnostics and recovery](diagnostics-and-recovery.md), [CLI](cli.md).

## Scope

meshly connects exactly two Linux nodes:

- usually a VPS with a public UDP endpoint;
- and a server behind NAT.

They are connected over kernel WireGuard, and meshly manages the interface,
address, routes, per-interface sysctls, one nftables table (`inet meshly`)
and its systemd units. The VPN gives each node access only to the services
the *other* node explicitly allows. It is not a site-to-site VPN: there is no
LAN access and no forwarding in either direction.

## Assets

| Asset | Where | Why it matters |
|---|---|---|
| WireGuard private key | `/etc/meshly/keys/wireguard.key` (0600, dir 0700) | impersonation of the node inside the tunnel |
| Identity private key (Ed25519) | `/etc/meshly/keys/identity.key` | signing invites and accepts, i.e. admitting a peer |
| Policy (allow rules, peer, addresses) | `/etc/meshly/meshly.json`, kernel `inet meshly` table | decides what the peer can reach |
| Services on each node | local sockets, often bound to `0.0.0.0` | the thing being protected |
| LAN behind each node | e.g. the home network | must never be reachable through the VPN |
| Bootstrap and transaction state | `/var/lib/meshly/` (0700) | one-time invites, replay protection, recovery |
| The meshly binary and release key | `/usr/local/bin/meshly`, compiled-in public key | code that runs as root |

## Trust boundaries

1. **Internet path** between the nodes. Untrusted. WireGuard protects it.
2. **The administrators' file channel** (scp/ssh) for the bootstrap files.
   meshly assumes it exists. It does not authenticate the files by itself:
   the fingerprint comparison does.
3. **The peer node.** It is authenticated, but only as trusted as the policy
   says. A compromised peer is an explicit attacker model.
4. **Other interfaces of each node**: the public interface and the LAN.
   They must not be able to reach the VPN address or pose as the peer.
5. **Root on each node.** Fully trusted for that node. meshly cannot protect
   a node from its own root.
6. **The release channel**: GitHub Releases and any mirror. Untrusted for
   integrity, because the signature check provides integrity.

## Attacker models

### 1. Network attacker on the internet path

**Can:** observe, drop, delay, replay and inject UDP between the endpoints.
Scan the public addresses.

**meshly guarantees:**

- Confidentiality, integrity and replay protection of tunnel traffic come
  from kernel WireGuard. meshly configures the keys and adds no transport
  crypto of its own.
- The WireGuard port does not answer unauthenticated packets. The endpoint
  of a peer without a configured `endpoint` is learned only from
  authenticated packets.
- The VPN address is reachable only through the meshly interface.
  `guard_pre` drops packets for the local VPN address that arrive on any
  other interface (except `lo`), and packets with a source inside the VPN
  CIDR from other interfaces. *Integration:* `TestPolicy` (an attacker
  with a route to `10.100.0.0/24` via the VPS cannot reach an allowed
  service).

**Not protected:**

- denial of service (the path can be cut);
- traffic analysis: endpoints, volume, timing;
- an attacker who controls the file channel *and* whose substituted
  fingerprint the admin accepts without comparing (see 4).

### 2. Attacker on the LAN of either node

**Can:** send arbitrary packets to the node's LAN address, spoof VPN
addresses, try to use the node as a router into the VPN.

**meshly guarantees:**

- Packets from the LAN with a VPN source address or for the VPN address are
  dropped in `guard_pre`. *Integration:* `TestCompromisedPeerContained`
  (a LAN host with `10.100.0.1` configured and a route to `10.100.0.2`
  cannot reach the allowed service).
- No forwarding into the VPN:
  - `guard_fwd` (forward hook, priority -300) drops everything with
    `oifname` set to the meshly interface;
  - the interface has `forwarding=0`, strict `rp_filter`, no redirects, no
    source routing and IPv6 disabled.

  *Unit only:* `TestRenderPolicyShape` checks that the rule is rendered.
  No integration test routes a LAN host's traffic into the VPN through the
  node.

**Not protected:** services of the node itself on its LAN address. They are
the host firewall's business, not meshly's.

### 3. Compromised peer (root on the other node)

**Can:** do anything on that node: remove its own meshly table, widen its
WireGuard allowed IPs and routes, add addresses, send any packet into the
tunnel.

**meshly guarantees on the attacked node** (all enforced locally, so the
peer's configuration does not matter):

- **Only explicitly allowed services.** `from_vpn` accepts a new flow only if
  `(peer address, protocol, port)` is in `allow_in`, or for ping in
  `allow_ping`. Everything else hits `default deny`. *Integration:*
  `TestPolicy` (exact port, protocol and direction; the reverse direction
  stays closed), `TestCompromisedPeerContained` (an unlisted port stays
  closed after the compromise).
- **Policy per packet, not per connection.** Removing a rule also cuts
  established flows. *Integration:* `TestDenyStopsEstablishedFlow`.
- **No source spoofing.** WireGuard cryptokey routing on the attacked node
  accepts only the peer's `/32`, and `from_vpn` requires `ip saddr` in
  `@peers`. *Integration:* `TestCompromisedPeerContained` (a source
  address `10.100.0.9` is not accepted).
- **No LAN access and no forwarding**, even if the attacked node forwards for
  other reasons, as a Docker host does:
  - `guard_fwd` drops all forwarding from the interface;
  - `forwarding=0` on the interface;
  - cryptokey routing.

  *Integration:* `TestCompromisedPeerContained` (LAN host unreachable
  directly and via the LAN address, also after the `forwarding` sysctl is
  turned on behind meshly's back; the drop counters increase; the drift is
  reported by `status` and repaired by `service check`).
- **No DNAT or redirect bypass.** Decisions are taken at priority -180,
  before DNAT (-100), against the original destination. `guard_in` then
  drops anything from the VPN whose destination was rewritten or whose
  conntrack entry has `dnat` status. *Integration:*
  `TestCompromisedPeerContained`, using a Docker-style `dnat to <LAN host>`
  and a local `redirect`, both on ports with an allow rule.
- **Revoke ends all access.** Rules are removed first, then the key and the
  route. *Integration:* `TestPolicy`.

**Not protected:**

- attacks on the allowed services themselves (application vulnerabilities,
  credential guessing);
- DoS of the tunnel;
- the attacker learning the node's public endpoint and VPN address;
- outbound access: allow rules are per node, not per user, so on the
  attacked node any local process can still open connections to the
  services the *compromised* peer allows.

### 4. Attacker who obtains or substitutes a bootstrap file

**Can:** read or replace an invite, join request or accept while it is in
transit or lying around in a shared directory.

**meshly guarantees** (details in [bootstrap-protocol.md](bootstrap-protocol.md)):

- **Substitution is detected by the fingerprint comparison.** `join` and
  `approve` stop without an interactive `yes` or a matching
  `--expect-fingerprint`. The fingerprint covers both public keys.
  *Integration:* `TestBootstrapTrust` (a wrong inviter fingerprint gives
  exit 10; a missing flag or another candidate's fingerprint at approve
  gives exit 10).
- **Modification breaks the signature.** *Integration:*
  `TestBootstrapTrust` (a tampered invite, request or accept gives exit 4,
  and no keys are generated for a rejected invite). *Unit:*
  `TestTamperingDetected`, `TestSignatureDomainSeparation`, `TestStrictJSON`,
  `FuzzOpen`.
- **A stolen invite** lets the thief create a join request, which still
  needs the inviting admin's explicit, fingerprint-checked approval. Invites
  are one-time and expire (default 1 h, max 24 h). *Integration:*
  `TestBootstrapTrust` (a second candidate on the same invite is refused
  with "one-time", also after the first peer was revoked), `TestInviteExpiry`.
- **A stolen accept** is useless elsewhere. It activates only the node whose
  pending request and private keys it was issued for. *Integration:*
  `TestBootstrapTrust` (the accept used on another candidate gives exit 4).
- **The files contain no secrets.** *Integration:* `TestBootstrapTrust`
  checks that private keys do not appear in the invite, the accept, the
  saved state, `status`, `doctor`, `logs` (also `--json`) or process
  arguments.

**Not protected:**

- an admin who approves without comparing the fingerprint;
- a thief whose request reaches the admin first and is approved without
  comparison: then the thief becomes the peer. This is the residual risk of
  file-based bootstrap; the fingerprint step exists to remove it.

### 5. Local unprivileged user on a node

**Can:** run `meshly`, read world-readable files, create files and symlinks
in shared directories such as `/tmp`.

**meshly guarantees:**

- **Changing commands require root** and exit 3 otherwise. `status` runs
  without root with reduced detail. *Unit:* `TestExitCodes` (exit 3 for
  `start` as a non-root user).
- **Secrets are unreadable to the user:**
  - keys are `0600` root in a `0700` directory;
  - state in `/var/lib/meshly` is `0700`/`0600`;
  - the lock is in `/run/meshly` (`0700`).

  *Integration:* `TestBootstrapTrust` (key and directory modes).
- **No secret in `argv`.** WireGuard is configured through netlink
  (`wgctrl`) and nft scripts are passed on stdin; no shell is ever
  involved. *Integration:* `TestBootstrapTrust` checks `ps` output once
  (a spot check, not a proof).
- **Managed files cannot be swapped.** meshly refuses to load them if they
  are symlinks, not regular files, owned by another user or group- or
  world-writable. *Unit:* `internal/store` tests (`fs_test.go`,
  `keys_test.go`, `config_test.go`, `bootstrap_test.go`).
- **Planted links do not redirect file I/O.** Bootstrap input files are
  opened with `O_NOFOLLOW`, regular files only, and a FIFO does not block.
  Output files are created with `O_EXCL|O_NOFOLLOW`; a symlink or directory
  planted at the output path is refused even with `--force`. *Unit:*
  `TestReadUntrusted`, `TestWriteOutputRefusesNonRegular`.

**Not protected:**

- users with `sudo` or root;
- local processes using the tunnel: any local user can connect to the
  services the peer allows for this node. Rules are per node, not per
  user or process.

### 6. Malicious release, mirror or network during install/upgrade

**Can:** serve modified binaries, `SHA256SUMS`, signatures or an older
release.

**meshly guarantees:**

- **`meshly upgrade` verifies before installing.** It checks the Ed25519
  signature over `"meshly-release/1" || 0x00 || SHA256SUMS` with the
  public key compiled into the running binary, then the SHA-256 of the
  binary.
  - The version is taken only from the signed `SHA256SUMS`, which must list
    exactly one version.
  - Downgrades are refused unless `--force` is given (exit 5).
  - URLs must be HTTPS; plain HTTP is allowed only for loopback, for tests.
  - The new binary must run and report the expected version before it
    atomically replaces the old one. The previous binary is kept as
    `<exe>.prev`.

  *Integration:* `TestInstallUpgradeUninstall` (upgrade, repeated upgrade,
  downgrade refused, forged `SHA256SUMS` refused with exit 4, binary
  unchanged after a refusal).
- **`install.sh` performs the same checks** with `openssl` and `sha256sum`
  before anything is written to `/usr/local/bin`. *Integration:*
  `TestInstallUpgradeUninstall` (a tampered `SHA256SUMS` and a tampered
  binary are refused; the installed binary stays unchanged).
- **The private release key never reaches CI.** It is kept offline by the
  maintainer (`tools/release`, `scripts/release.sh`). Builds are
  reproducible, and `.github/workflows/release-verify.yml` rebuilds each
  published release from its tag and compares it with the signed
  `SHA256SUMS`.

**Not protected:**

- **First install is trust on first use.** `install.sh` carries the public
  key and is fetched over HTTPS from GitHub; whoever can change that file
  (GitHub account, TLS interception with a trusted CA) can change the key.
  Users can compare the key with `release-key.pub` in the repository.
- **A stolen release key**, or a compromised maintainer account together
  with the key.
- **Freeze attacks.** A mirror can withhold new releases; meshly only
  refuses older ones.
- **Automatic rollback after a failed restart is not verified.**
  `upgrade` restores `<exe>.prev` if `meshly.service` does not come back
  after the upgrade; this path is not covered by an integration test.

### 7. Misconfigured or changing foreign firewall, Docker

**Can:** the host's own nftables/iptables rules, UFW, firewalld, Docker or
an admin's `nft flush ruleset` can interfere with meshly's table.

**meshly guarantees:**

- **Detection before any change.** The live ruleset is analysed before
  anything is touched. Unsupported setups (UFW, firewalld, legacy iptables
  rules, iptables-nft chains that would drop meshly traffic, flowtables that
  offload the interface) stop the command with exit 3. `--dry-run` reports
  the same. *Integration:* `TestUnsupportedFirewalls` checks that foreign
  state is unchanged after the refusal. Note that UFW and firewalld are
  simulated by their config and pid files, not by the real daemons. *Unit:*
  `TestAnalyzeFixtures` over rulesets recorded from nft 1.0.6 and 1.0.9.
- **Native nftables profile.** A host firewall with `policy drop` must
  contain the one integration rule
  `meta mark & 0x10000000 == 0x10000000 accept`. A missing or misplaced rule
  is refused with the exact rule to add. The host firewall is never
  modified. *Integration:* `TestNativeNftablesProfile`.
- **Fail closed.** In profile `nftables`, only packets that meshly has
  accepted and marked pass the host firewall. If the meshly table
  disappears, nothing is marked, and everything meshly opened is closed
  again. If the integration rule disappears, access-opening commands are
  refused, while access-reducing commands still run with a warning.
  *Integration:* `TestNativeNftablesProfile`.
- **No foreign object is modified.** meshly changes only its own table, in
  one atomic `nft -f` transaction, and never runs `flush ruleset`.
  *Integration:* `TestForeignStatePreserved` (foreign tables, routes,
  interfaces and public SSH unchanged over the whole lifecycle including
  `reset`). *Unit:* fake-kernel assertions in `TestFlowAndSecrets`.
- **Docker.** Published ports are not reachable through the VPN, and DNAT
  from the VPN is dropped (see 3). This is verified with Docker-style nft
  rules (`TestCompromisedPeerContained`), *not with a running Docker
  daemon*.
- **Restoration after external changes:**
  - `nftables.service` reloads propagate to meshly (`ReloadPropagatedFrom`),
    so the table is re-applied;
  - after a start or restart of `nftables.service`, a drop-in re-applies
    the table;
  - a timer runs `meshly service check` every minute and re-applies a
    missing or modified table;
  - `doctor` reports when `/etc/nftables.conf` contains `flush ruleset`.

  *Integration:* `TestSystemdLifecycle/nftables-reload` (reload and restart
  of `nftables.service`; table and service are back within 15 s),
  `TestSystemdLifecycle/check-timer`.

**Not protected:**

- **Exposure window while the meshly table is missing.** For example,
  between an external `nft flush ruleset` and the re-application by the
  service or the timer (up to about one minute).
  - In profile `none`, there is no host firewall, so the peer can reach
    every service listening on the VPN address or `0.0.0.0`.
  - In profile `nftables`, the peer can reach what the host firewall itself
    accepts on all interfaces, such as `tcp/22`, exactly like any internet
    host.

  The window is not measured by the tests; only the restoration is. See
  [firewall.md](firewall.md).
- **Cloud firewalls and security groups.** meshly does not manage them. The
  WireGuard UDP port must be opened there by the admin.
- **Rules in hooks that run before meshly.** For example, `netdev` ingress
  chains are reported as warnings, not prevented.
- **Firewall managers without an adapter.** UFW and firewalld must be
  disabled to use meshly.

## Failures and interrupted operations

meshly's own failures must never leave more access than the configuration
grants. Changes run as journaled transactions:

- access-opening changes are rolled back on failure;
- access-reducing changes are completed on recovery;
- if a rollback itself fails, safe mode replaces the table with a lockdown
  table and removes the interface.

*Integration:* `TestFaultsInit`, `TestFaultsAllow` (including safe mode),
`TestFaultsReduce`, `TestFaultActivate`, which inject errors and crashes
(immediate process exit without cleanup) at each step, and `TestSystemdLifecycle/recovery-at-boot`.
Concurrent commands are serialised by a lock (`TestConcurrentOperations`).
The fault-injection points exist only in builds with the
`meshly_faultinject` tag. Details:
[diagnostics-and-recovery.md](diagnostics-and-recovery.md).

## Out of scope

- **Root compromise of a node.** That node, its keys and its policy are lost.
  The other node remains protected as described in model 3.
- **Kernel or WireGuard implementation bugs, and side channels.**
- **The journal is not tamper-evident.** `meshly logs` is an audit aid
  against mistakes; root can rewrite it.
- **More than two nodes, IPv6 inside the tunnel, and per-user policies.**
  They are not supported in this version.
- **Time.** Validity checks use the local clocks, with 5 minutes of
  tolerated skew for creation times. An attacker who controls a node's
  clock controls that node's notion of expiry.

## Test environment caveat

Integration tests run in privileged containers with their own network
namespaces on a real Linux kernel. They do not run in full virtual machines.
"Reboot" is a container restart, which recreates the network namespace (the
interface and all nftables tables are gone) and boots systemd again; the
kernel itself is not rebooted.
