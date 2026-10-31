# Threat model

This document describes what meshly protects, against whom, how, and where
its protection ends. Each claim names the mechanism and the test that checks
it. **Integration** tests run real kernels, real WireGuard and real
nftables, with every node in its own privileged container and network
namespace (`test/integration`, see [testing](testing.md)). **Unit** tests
run against an in-memory fake kernel or recorded nft output. A claim
without a test is marked *not verified*.

Related: [architecture](architecture.md), [firewall](firewall.md),
[pairing protocol](pairing-protocol.md),
[diagnostics and recovery](diagnostics-and-recovery.md), [CLI](cli.md).

## Scope

meshly connects Linux nodes as a hub and spokes:

- the hub, usually a VPS with a public UDP endpoint, which created the
  network;
- the nodes that joined it, for example servers behind NAT. Each of them
  has a tunnel to the hub alone.

They are connected over kernel WireGuard, and meshly manages the interface,
address, routes, per-interface sysctls, one nftables table (`inet meshly`)
and its systemd units, and on a node with Docker networks one policy routing
rule and its routing table. The VPN gives each node access only to the
services that the node at the other end of its tunnel explicitly allows. The
nodes that joined do not reach each other: the hub does not forward between
them. It is not a site-to-site VPN:
there is no LAN access. The only forwarding is between the tunnel and the
node's own Docker networks, because meshly treats a container like a program
on the node: from the peer to a port that Docker publishes on the node and
the peer is allowed, and from containers to the peer, which sees them as the
node. Nothing else is forwarded in either direction.

## Assets

| Asset | Where | Why it matters |
|---|---|---|
| WireGuard private key | `/etc/meshly/keys/wireguard.key` (0600, dir 0700) | impersonation of the node inside the tunnel |
| Policy (allow rules, peer, addresses) | `/etc/meshly/meshly.json`, kernel `inet meshly` table | decides what the peer can reach |
| Services on each node | local sockets, often bound to `0.0.0.0`, and container ports that Docker publishes | the thing being protected |
| LAN behind each node | e.g. the home network | must never be reachable through the VPN |
| Invite code | printed by `meshly invite`, valid once and for 10 minutes by default; then on screens, in clipboards, in whatever it is pasted into | whoever uses it first while the invite is open becomes a node of the network, a peer of the hub |
| Transaction state | `/var/lib/meshly/` (0700) | recovery |
| The meshly binary and release key | `/usr/local/bin/meshly`, compiled-in public key | code that runs as root |

## Trust boundaries

1. **Internet path** between the nodes. Untrusted. WireGuard protects it.
2. **The way the invite code travels** from the inviting node's terminal to
   the joining node's prompt, usually copied by one administrator. meshly
   assumes it stays private while the invite is open. It cannot tell who
   pastes the code: the code is a bearer secret.
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
- An open invite exposes nothing new. Pairing runs inside a temporary
  WireGuard tunnel through the same UDP port, and its TCP listener is bound
  to the VPN address. *Integration:* `TestPairingNothingExposed` (the only
  new socket is on the VPN address; the public address does not accept the
  pairing port; a host with a route to the VPN address through the VPS is
  dropped by `guard_pre`).
- A packet for an address of the VPN network never leaves unencrypted
  through another interface while the link is up. The whole network is
  routed into the meshly interface, where `to_vpn` drops what is not for a
  peer, such as a node that joined the same hub. *Integration:*
  `TestHubAndSpokes` (a connection from one node that joined to another
  fails, and the counter of the first node's drop grows). *Unit:*
  `TestRoutesCoverTheNetwork`.

**Not protected:**

- packets for VPN addresses while the link is stopped or in safe mode: the
  interface is gone with its routes, so they follow the host's routing
  table, like packets for any other address;
- denial of service (the path can be cut);
- traffic analysis: endpoints, volume, timing;
- an attacker who reads or replaces the invite code on its way between the
  terminals (see 4).

### 2. Attacker on the LAN of either node

**Can:** send arbitrary packets to the node's LAN address, spoof VPN
addresses, try to use the node as a router into the VPN.

**meshly guarantees:**

- Packets from the LAN with a VPN source address or for the VPN address are
  dropped in `guard_pre`. *Integration:* `TestCompromisedPeerContained`
  (a LAN host with `10.100.0.1` configured and a route to `10.100.0.2`
  cannot reach the allowed service).
- No forwarding into the VPN from the LAN, or from any interface but the
  node's Docker networks:
  - `guard_fwd` (forward hook, priority -300) drops everything with
    `oifname` set to the meshly interface, except connections from a Docker
    bridge to a peer and the replies of published container ports;
  - on a node with Docker networks, `guard_post` drops, after NAT, anything
    that would leave through the interface with another source than the
    node's VPN address.

  Besides, on a node with Docker networks and `rp_filter` on (Ubuntu's
  default), the kernel is expected to drop packets from the LAN to the
  tunnel even before the forward hook: it looks up their reverse path in
  meshly's routing table 109, which has no route to the LAN (see
  [firewall.md](firewall.md#policy-routing-table-109)). That is kernel
  behaviour, not a guarantee of meshly, and no test checks it.

  *Integration:* `TestDockerHostContained/lan-into-vpn` (a LAN host routes
  the peer's VPN address through a Docker host that forwards, with
  `rp_filter` off so that `guard_fwd` alone decides: nothing reaches the
  peer, over TCP or UDP, and the drop counter grows). *Unit:*
  `TestRenderPolicyShape` checks that the rule is rendered. On a node
  without Docker networks, no integration test routes a LAN host's traffic
  into the VPN through the node.

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
  `allow_ping`. Everything else hits `default deny`. A port that Docker
  publishes is a service of the node like any other: closed until `allow`.
  A container port that is not published stays closed even with an allow
  rule, and so does a port published on `127.0.0.1` only. *Integration:*
  `TestPolicy` (exact port, protocol and direction; the reverse direction
  stays closed), `TestCompromisedPeerContained` (an unlisted port stays
  closed after the compromise), `TestDockerPublishedPort`
  (`closed-without-allow`, `allowed`, `unpublished-port`, `localhost-only`).
- **Policy per packet, not per connection.** Removing a rule also cuts
  established flows, those to a published container port too: `from_vpn`
  drops the peer's packets, and `guard_post` drops the container's replies.
  *Integration:* `TestDenyStopsEstablishedFlow`,
  `TestDockerPublishedPort/deny-stops-established-flow` (a TCP stream into
  a container) and `TestDockerPublishedPort/udp` (a UDP flow) for the
  peer's packets; `TestDockerPublishedPort/deny-stops-container-replies`
  for the container's: a container that keeps sending over TCP and UDP on
  a flow the peer opened reaches the peer no more after `deny`, and the
  counter of `guard_post` grows.
- **No source spoofing.** WireGuard cryptokey routing on the attacked node
  accepts only the peer's `/32`, and `from_vpn` requires `ip saddr` in
  `@peers`. *Integration:* `TestCompromisedPeerContained` (a source
  address `10.100.0.9` is not accepted).
- **No LAN access, and forwarding only to published container ports**,
  even if the attacked node forwards for other reasons, as a Docker host
  does:
  - `from_vpn` accepts only packets for the node's own VPN address, so the
    peer cannot address a LAN host or a container directly;
  - `guard_fwd` forwards from the interface only connections whose original
    destination is the node's VPN address and that Docker's DNAT sent into
    a Docker network, and the replies to connections that containers
    started; it drops all other forwarding from the interface;
  - without Docker networks, `forwarding=0` on the interface; with them,
    policy routing: whatever comes from the interface is routed with table
    109, which knows only the Docker networks, so the LAN has no route from
    the tunnel, also while the meshly table is missing;
  - cryptokey routing.

  *Integration:* `TestCompromisedPeerContained`, on a node without Docker
  (LAN host unreachable directly and via the LAN address, also after the
  `forwarding` sysctl is turned on behind meshly's back; the drop counters
  increase; the drift is reported by `status` and repaired by `service
  check`). `TestDockerHostContained`, on a Docker host that already
  forwarded before Docker started, so that the `FORWARD` policy stays
  `ACCEPT` and only meshly keeps the tunnel apart from the LAN; the hostile
  peer also routes the node's Docker network into the tunnel: the LAN host
  is unreachable (`lan`), container addresses and an allowed but
  unpublished port stay closed (`containers`), policy routing refuses the
  LAN with the meshly table deleted (`without-table`), and there is exactly
  one routing rule (`one-routing-rule`). `TestDockerPublishedPort/container-address`:
  a peer that routes a container's address into the tunnel is dropped by
  `from_vpn`. For the container addresses, Docker's own guard (its raw
  `PREROUTING` rules) is removed first. Each check makes sure that meshly
  drops: the counter of a meshly rule grows, or the route lookup fails.
- **No DNAT or redirect bypass.** Decisions are taken at priority -180,
  before DNAT (-100), against the original destination. `guard_in` then
  drops anything from the VPN whose destination was rewritten or whose
  conntrack entry has `dnat` status. A DNAT to another host is forwarded
  traffic: without Docker networks `guard_fwd` drops it; with them, policy
  routing refuses every destination outside the Docker networks before the
  forward hook, and `guard_fwd` forwards only into a Docker network and only
  for the node's VPN address. *Integration:*
  `TestCompromisedPeerContained`, using a Docker-style `dnat to <LAN host>`
  and a local `redirect`, both on ports with an allow rule.
  `TestDockerHostContained`, with a foreign `dnat to <LAN host>` on an
  allowed port: refused by routing, it never reaches the forward hook
  (`lan`); without the routing rule, `guard_fwd` drops it and the check
  restores the rule (`lan-without-routing-rule`); a local `redirect` on an
  allowed port is dropped by `guard_in` (`local-redirect`).
- **Revoke ends all access.** Rules are removed first, then the key and the
  route. The other peers stay connected. *Integration:* `TestPolicy`,
  `TestHubAndSpokes`.
- **No path to other nodes through the hub.** A compromised node that
  joined has no key or route for the other nodes that joined, and if it
  sends packets for them into its tunnel anyway, the hub's `from_vpn`
  accepts only packets for the hub's own VPN address and drops them before
  routing, also when the hub forwards IPv4. Each node that joined admits only
  the hub's address (`@peers`, cryptokey routing). *Integration:*
  `TestHubAndSpokes` (root on home routes office's address into its tunnel,
  the vps forwards IPv4: nothing reaches office, and the counter of the
  vps's drop grows).

**Not protected:**

- attacks on the allowed services themselves (application vulnerabilities,
  credential guessing);
- DoS of the tunnel;
- the attacker learning the node's public endpoint and VPN address;
- outbound access: allow rules are per node, not per user, so on the
  attacked node any local process, and any container on its Docker
  networks, can still open connections to the services the *compromised*
  peer allows;
- a compromised hub: it is the peer of every node that joined, so it
  reaches on each of them what that node allows the hub, and nothing more.
  The nodes that joined are protected from it as from any peer, and no
  node reaches another without it.

### 4. Attacker who obtains or substitutes an invite code

**Can:** read the code while it is shown or copied (a shared screen, a chat,
a clipboard, terminal scrollback, a recorded session), or hand the
administrator of the joining node a code of their own.

**meshly guarantees** (details in [pairing-protocol.md](pairing-protocol.md)):

- **Without the code there is nothing to talk to.** The invite's temporary
  WireGuard peer is the public key of a key derived from the code's 128-bit
  secret, with a preshared key derived from it too. A handshake without
  them gets no answer, and the temporary peer reaches only TCP 51820 on the
  inviting node's VPN address. *Integration:* `TestPairingNothingExposed`
  (nothing new is reachable from outside the tunnel), `TestPairingRefusals`
  (the code of a closed invite gets no answer). *Unit:*
  `TestOverlayPeerAndAllow` (the temporary peer, its preshared key and its
  single allow entry, and their removal).
- **Not from the inviting node either.** Its own processes reach the VPN
  address over loopback, so the pairing port has two more layers. The
  invite's firewall rule drops every packet for the port that does not
  arrive through the tunnel from the joining node's address, loopback
  included, and the listener closes every connection from another source
  without an answer. A process on the inviting node, even one of root's,
  gets no connection. *Integration:* `TestPairingClosedToLocalUsers`
  (refused as `nobody` and as root while the rule's counter grows; with the
  rule deleted, the listener still does not answer). *CLI:*
  `TestInviteIgnoresForeignSource`. *Unit:* `TestRenderExclusive` (the rule
  exists only with the invite's temporary state).
- **A code works once, for a short time.** Once a node has joined, the
  invite answers a second `hello` with `used` (exit 4), and once the invite
  has closed, a second `join` gets no answer at all (exit 13). The invite
  ends at its expiry (10 minutes by default, at most 1 hour), and the
  joining node refuses a code more than 5 minutes past it (exit 4).
  *Integration:* `TestPairingRefusals` (used code, expired invite, expired
  code; nothing changes on the refused node). *CLI:* `TestJoinCodeUsed`,
  `TestInviteSessionAnswers`, `TestInviteCancelAndExpiry`.
- **A code cannot take the place of a node.** The joining node gets an
  address that no node of the network has, and the invite refuses a name or
  a WireGuard key of a node of the network. A node that joined before
  cannot use the invite: WireGuard drops what it sends with the joining
  node's address. *CLI:* `TestInviteSessionAnswers`,
  `TestJoinNameOfAnotherNode`, `TestInviteAddsNode`.
- **The joining node talks only to the inviting node of the code.** The code
  carries that node's WireGuard public key, so nobody else can answer
  through the temporary tunnel, and the `welcome` must match the code (CIDR,
  addresses, key, endpoint) or `join` stops (exit 1).
- **A damaged code is refused before anything changes.** A checksum catches
  typos and truncated pastes (exit 4). It is not a signature. *Unit:*
  `TestParseCodeErrors`, `FuzzParseCode`. *CLI:* `TestJoinCodeInput`.
  *Integration:* `TestPairingRefusals` (no interface, table, configuration
  or key is left after the refusal).
- **A hostile party in the exchange gains nothing from malformed input.**
  Messages are parsed strictly and validated with the configuration's own
  validators on both sides; a malformed message closes the connection, and a
  `reject` text is limited to printable ASCII. *Unit:* `TestHostilePeer`,
  `TestMessageSizeBoundary`, `FuzzReadRequest`.
- **No temporary access is left behind.** Every way out of `invite`
  removes the temporary peer, its preshared key and its allow rule; after
  `kill -9`, `meshly-check.timer` does it within a minute. *Integration:*
  `TestPairingCleanup`, `TestPairing`. *CLI:* `TestPairFlow`.
- **The code is kept out of everything else.** `join` refuses it as an
  argument (exit 2), and neither the code nor the keys derived from it are
  saved, journaled or shown by `status`, `doctor` or `logs`. A code that a
  paste broke across lines is read whole, so no part of it is left over for
  the shell and its history. *Integration:* `TestPairing` (process list,
  journal, `status`, `doctor` and `logs`, also `--json`),
  `TestPairingRefusals`. *CLI:* `TestJoinCodeWrapped`.

**Not protected:**

- **A stolen code used first.** Whoever joins with the code while the invite
  is open becomes the peer. It reaches nothing until `meshly allow` on the
  inviting node, the invite prints the name it joined with, and the real
  node's `join` then fails (exit 13). Remove the intruder with `sudo meshly
  revoke <name>`, then invite again.
- **A substituted code.** The joining node then pairs with whoever made the
  code. Nothing on the joining node is reachable until `meshly allow` there,
  but what it sends to the peer's VPN address goes to that party. `join`
  prints the endpoint it connects to and the peer it joined, so the
  administrator can check the address before using the link.
- **The code where it was copied to.** Scrollback, clipboard history, chat
  logs keep it; it is a credential until the invite closes and useless
  after that.
- **A freed address.** `revoke` frees the node's VPN address, and the next
  node that joins gets it. meshly's own rules name nodes and go with the
  revoked node, but a service that trusts a VPN address in its own
  configuration, such as an allowlist, then trusts the new node: update it
  after a revoke.

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
  - the lock and the marker of an open invite are in `/run/meshly`
    (`0700`).

  *Integration:* `TestPairing` (key and directory modes).
- **No secret in `argv`.** WireGuard is configured through netlink
  (`wgctrl`), nft scripts are passed on stdin, and `join` reads the invite
  code from a prompt or stdin and refuses it as an argument (exit 2); no
  shell is ever involved. *Integration:* `TestPairing` checks `ps` output
  while an invite waits (a spot check, not a proof), `TestPairingRefusals`
  the refusal.
- **Managed files cannot be swapped.** meshly refuses to load them if they
  are symlinks, not regular files, owned by another user or group- or
  world-writable, and a FIFO planted at their path does not block it.
  *Unit:* `internal/store` tests (`fs_test.go`, `keys_test.go`,
  `config_test.go`, `invite_test.go`).
- **No way into an open invite.** The pairing port listens on the VPN
  address, which a local process reaches over loopback. The invite's
  firewall rule admits it only from the joining node's address through the
  tunnel, and the listener answers no other source, so a local user can
  neither join without the code nor take the peer slot. It can still take
  TCP port 51820 on the VPN address before the invite starts; `invite` then
  fails at once with "address already in use" instead of waiting, so the
  block is loud, not silent. *Integration:* `TestPairingClosedToLocalUsers`. *CLI:*
  `TestInviteIgnoresForeignSource`.

**Not protected:**

- users with `sudo` or root;
- local processes using the tunnel: any local user can connect to the
  services the peer allows for this node, and so can every container on
  the node's Docker networks. Rules are per node, not per user, process or
  container.

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
  downgrade refused, forged `SHA256SUMS` refused with exit 1, binary
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
- **Failed upgrades restore the running service.** Running intent is captured
  before replacement; rollback restarts the restored binary even after the
  new unit fails, and verifies it becomes active before reporting success.
  An intentionally stopped service stays stopped. *Integration:*
  `TestUpgradeRollbackRestoresRunningService` checks the restored binary version,
  active unit and allowed TCP traffic after a signed release fails to start.

**Not protected:**

- **First install is trust on first use.** `install.sh` carries the public
  key and is fetched over HTTPS from GitHub; whoever can change that file
  (GitHub account, TLS interception with a trusted CA) can change the key.
  Users can compare the key with `release-key.pub` in the repository.
- **A stolen release key**, or a compromised maintainer account together
  with the key.
- **Freeze attacks.** A mirror can withhold new releases; meshly only
  refuses older ones.

### 7. Misconfigured or changing foreign firewall, Docker

**Can:** the host's own nftables/iptables rules, UFW, firewalld, Docker or
an admin's `nft flush ruleset` can interfere with meshly's table.

**meshly guarantees:**

- **Detection before any change.** The live ruleset is analysed before
  anything is touched. Unsupported setups (firewalld, legacy iptables rules,
  iptables-nft chains outside `filter INPUT`/`OUTPUT` that would drop meshly
  traffic, flowtables that offload the interface) stop the command with exit
  3. `--dry-run` reports the same. *Integration:* `TestUnsupportedFirewalls`
  checks that foreign state is unchanged after the refusal. Note that
  firewalld is simulated by its pid file, not by the real daemon. *Unit:*
  `TestAnalyzeFixtures` over rulesets recorded from nft 1.0.6 and 1.0.9
  (UFW and fail2ban also from 1.1.3), `TestAnalyzeDockerCE` over rulesets
  of a real Docker CE 29.9.1 on nft 1.0.6, 1.0.9 and 1.1.3 (on 1.0.9 also
  with UFW and with Docker's nftables firewall backend).
- **UFW and iptables.** meshly keeps one rule at the top of the iptables
  `filter` chains `INPUT` and `OUTPUT` (and `ip filter FORWARD` on a node
  with Docker networks); it accepts only packets that carry
  meshly's mark, which meshly sets only on packets its own policy accepted
  and clears on every other packet. UFW's and the administrator's rules
  still decide everything else, and a port they open to the internet stays
  closed to the peer through the VPN. Without the rule (after
  `iptables-restore`, until the check repairs it) the VPN fails closed.
  *Integration:* `TestUFW` (Debian 12 and Ubuntu 24.04, real UFW on both
  nodes), `TestIptablesHost`, `TestSystemdUFW` (reboot).
- **Ban lists hold.** A rule that drops sources listed in a named set
  without a range of VPN addresses (fail2ban, sshguard, CrowdSec) is left
  alone and needs no integration, so its bans apply to traffic through the
  VPN too: a peer that fails SSH logins through the tunnel is banned like
  any other host. A ban that hits a peer is a warning, never a refusal, so
  it cannot keep meshly from starting. With fail2ban's iptables actions its
  jumps come after meshly's rule, and its bans do not reach traffic meshly
  accepted. *Integration:* `TestFail2ban` (Debian 12 and Ubuntu 24.04, real
  fail2ban on both nodes), `TestFail2banIptables`. *Unit:* `TestBanLists`.
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
- **Docker: a container is a program on the node.** A port that Docker
  publishes on all addresses or on the VPN address opens to the peer only
  with `meshly allow`, and closes with `deny`; a container connects to the
  peer like a program on the node, to what the peer allows the node. The
  LAN, container addresses and ports without `allow` stay closed (see 2
  and 3). The tests run a real Docker daemon on Debian 12 and Ubuntu 24.04:
  a port published on all addresses is closed until `allow`, open after
  it, and closed again by `deny`, for an established TCP stream and a UDP
  flow too; a port published on the VPN address is closed until `allow` and
  open after it; a port published on `127.0.0.1` stays closed.
  *Integration:* `TestDockerPublishedPort`,
  `TestDockerClient`, `TestDockerHostContained`, and with Docker's own
  firewall rules changing: `TestDockerNetworkLifecycle` (a new network works
  within seconds, a removed one is gone, and with the last one forwarding
  and routing go), `TestDockerAfterMeshly` (Docker started after meshly,
  restarted, and after a reboot), `TestDockerUFW`,
  `TestDockerNftablesBackend` (Docker's nftables firewall backend).
- **Containers leave the tunnel only as the node.** Everything sent into
  the tunnel has the node's VPN address as its source: meshly translates
  the source of container traffic itself (`nat_out`), and `guard_post`
  drops any other source after NAT. The peer never sees a container's
  address. *Integration:* `TestDockerClient/allowed` (vps sees home's VPN
  address in conntrack, never a container's),
  `TestDockerHostContained/container-source` (with meshly's SNAT and
  Docker's masquerade removed, nothing reaches vps from a container, and
  `guard_post`'s counter grows).
- **Problems on the containers' path never block the tunnel.** A chain on
  the forward hook that may drop container traffic (a native nftables
  chain, a drop in another iptables table) is a warning with the fix, never
  a refusal, in both profiles; Docker's own chains of its nftables backend
  are information. The forward hook is analysed only on a node with Docker
  networks. *Integration:* `TestDockerNativeForwardChain` (with a native
  forward chain `policy drop`, the tunnel between the hosts works and
  `doctor` prints the rule to add). *Unit:* `TestEvaluateFirewallForward`.
- **Nothing changes without Docker networks.** The table, the sysctls and
  the routing of a node without Docker networks are the same as before
  Docker support: no `docker_ifs`, no forwarding rules, `forwarding=0`, no
  routing rule. *Unit:* `TestRenderWithoutDockerUnchanged`,
  `TestMarkerRoundTripRealNft` (the table rendered without Docker networks
  has the hash of the table captured from real nft before),
  `TestForwardingDriftWithoutDocker`. *Integration:*
  `TestDockerNetworkLifecycle/docker-gone` (when the last bridge goes, so do
  forwarding, the routing rule, the rule in `FORWARD` and `docker_ifs`).
- **Restoration after external changes:**
  - `nftables.service` reloads propagate to meshly (`ReloadPropagatedFrom`),
    so the table is re-applied;
  - after a start or restart of `nftables.service`, a drop-in re-applies
    the table;
  - after a start or restart of `docker.service`, a drop-in re-applies
    meshly, which puts its rule back at the top of `FORWARD`;
  - `meshly-watch.service` runs the check seconds after the network
    interfaces or nftables change, which applies a new Docker network and
    puts meshly's rule back at the top of `FORWARD` after Docker moved it;
  - a timer runs `meshly service check` every minute and re-applies a
    missing or modified table;
  - `doctor` reports when `/etc/nftables.conf` contains `flush ruleset`.

  *Integration:* `TestSystemdLifecycle/nftables-reload` (reload and restart
  of `nftables.service`; table and service are back within 15 s),
  `TestSystemdLifecycle/check-timer`, `TestDockerNetworkLifecycle` and
  `TestDockerAfterMeshly` (within 10 s each).

**Not protected:**

- **Exposure window while the meshly table is missing.** For example,
  between an external `nft flush ruleset` and the re-application by the
  service or the timer (up to about one minute).
  - In profile `none`, there is no host firewall, so the peer can reach
    every service listening on the VPN address or `0.0.0.0`.
  - In profile `nftables`, the peer can reach what the host firewall itself
    accepts on all interfaces, such as `tcp/22`, exactly like any internet
    host.
  - On a node with Docker networks, in either profile, the peer can also
    reach the ports that Docker publishes on all addresses or on the VPN
    address, without `allow`, unless a forward chain of the host firewall
    drops them: Docker's own rules let them through, as they let the former
    through from the internet. This is the same class as the host services
    on `0.0.0.0` in profile `none`. The LAN stays closed: policy routing
    does not depend on the table (`TestDockerHostContained/without-table`).
    Container addresses do have a route then. When only `table inet meshly`
    is deleted, Docker's own rules keep them closed (the tested Docker drops
    packets for a container that arrive on another interface, in its raw
    `PREROUTING` rules; `without-table` deletes only the meshly table).
  - `nft flush ruleset` also removes Docker's rules, which are in nftables
    on the hosts meshly supports (iptables-nft or Docker's nftables
    backend), and so does a start, reload or restart of `nftables.service`
    whose config begins with `flush ruleset`. Until meshly re-applies its
    table, a peer that routes a Docker subnet into the tunnel reaches every
    port of every container on it by the container's address, published or
    not. The window is near zero when `nftables.service` flushes and usually
    seconds after a manual flush; no test covers it.

  `meshly-watch.service` usually re-applies the table within seconds of the
  change. The window is not measured by the tests; only the restoration is.
  See [firewall.md](firewall.md).
- **Docker turning on forwarding, before meshly follows it.** Docker
  writes `net.ipv4.ip_forward=1` whenever it turns forwarding on: at its
  first start after each boot, unless forwarding is already on (on a host
  that does not set it at boot, that is every boot). The write turns
  `forwarding` on for every interface, the meshly interface included, which
  already exists then. Until the drop-in for `docker.service` or
  `meshly-watch.service` applies the new Docker networks (about 1 to 5
  seconds), there is no routing rule, so the second layer is missing.
  `guard_fwd` in table `inet meshly` keeps dropping all forwarding from and
  into the interface meanwhile, since the table has no Docker network yet.
  The window is not measured by the tests.
- **Cloud firewalls and security groups.** meshly does not manage them. The
  WireGuard UDP port must be opened there by the admin.
- **Rules in hooks that run before meshly.** For example, `netdev` ingress
  chains are reported as warnings, not prevented, and so are forward chains
  at priority -300 or lower on a node with Docker networks.
- **Firewall managers without an adapter.** firewalld must be disabled to
  use meshly. UFW and iptables must use the default `iptables-nft` backend.
- **meshly's mark set outside meshly.** While table `inet meshly` exists,
  its chains clear the bit before any filter chain sees a packet. While it
  is absent (deleted, until the check restores it), a local process with
  `CAP_NET_ADMIN` that sets the bit with `SO_MARK` passes the integration
  rule in `OUTPUT`; such a process can change the firewall anyway. The
  administrator's own `MARK` rules in `mangle` run after meshly's chains and
  must not set the bit.
- **Saved iptables rules.** `netfilter-persistent save` writes meshly's rule
  into `/etc/iptables/rules.v4` and `rules.v6`. While meshly runs (or is
  stopped) this is harmless: meshly replaces or removes the restored copy at
  boot. After `meshly reset` it would come back at every boot; `reset` warns
  and says to save the rules again.

## Failures and interrupted operations

meshly's own failures must never leave more access than the configuration
grants. Changes run as journaled transactions:

- access-opening changes are rolled back on failure;
- access-reducing changes are completed on recovery;
- if a rollback itself fails, safe mode replaces the table with a lockdown
  table and removes the interface.
- safe mode keeps incomplete intent in the journal. If persisting a deny,
  revoke or stop fails, recovery keeps the VPN closed until the intended
  target can be saved and applied. Pending access-granting transactions
  restore their journaled base, even after the target was saved;
- without readable configuration, reset and service stop discover every
  owned WireGuard interface by its validated alias and close those paths
  before removing shared firewall protection. Foreign objects stay untouched.

*Integration:* `TestFaultsInit`, `TestFaultsAllow` (including safe mode),
`TestFaultsReduce`, `TestFaultJoin`, which inject errors and crashes
(immediate process exit without cleanup) at each step, and `TestSystemdLifecycle/recovery-at-boot`.
`TestIssue1CleanupWithoutConfig` checks custom interface cleanup after missing
and corrupt configuration with allowed and denied TCP probes and foreign objects.
`TestIssue2ForwardPersistenceFailure` and `TestIssue2BackwardBasePersistenceFailure`
check real TCP traffic stays closed across blocked configuration writes and repeated
recovery. Unit tests also cover superseded historical safe-mode records and failure
to append a commit, including completion without Docker networks.
Concurrent commands are serialised by a lock (`TestConcurrentOperations`).
The fault-injection points exist only in builds with the
`meshly_faultinject` tag. Details:
[diagnostics-and-recovery.md](diagnostics-and-recovery.md).

## Out of scope

- **Root compromise of a node.** That node, its keys and its policy are lost.
  The other nodes remain protected as described in model 3.
- **Kernel or WireGuard implementation bugs, and side channels.**
- **The journal is not tamper-evident.** `meshly logs` is an audit aid
  against mistakes; root can rewrite it.
- **Connections between nodes that joined (full mesh), IPv6 inside the
  tunnel, and per-user policies.** They are not supported in this version.
- **Time.** An invite ends at its expiry by the inviting node's clock; the
  joining node refuses the code more than 5 minutes past the expiry by its
  own clock, to allow for clocks that differ. An attacker who controls a
  node's clock controls that node's notion of expiry.

## Test environment caveat

Integration tests run in privileged containers with their own network
namespaces on a real Linux kernel. They do not run in full virtual machines.
"Reboot" is a container restart, which recreates the network namespace (the
interface and all nftables tables are gone) and boots systemd again; the
kernel itself is not rebooted. The Docker tests run Docker CE inside these
containers, with the `vfs` storage driver.
