# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until 1.0.0, minor versions may change the CLI and the
on-disk formats.

## [Unreleased]

### Fixed

- In a container (LXC on Proxmox, for example) without kernel WireGuard, preflight says to load the module on the
  host (`modprobe wireguard` there, and `/etc/modules-load.d/wireguard.conf` to load it at boot). It advised to
  install a kernel or to run `modprobe`, which a container cannot do.

## [0.0.6] - 2026-10-19

### Added

- A network has more than two nodes, around the node that created it (hub and spokes). `meshly invite` on that node
  adds one node per invite while the nodes already there keep working:
  - The new node gets the lowest free address of the network (`10.100.0.3`, then `10.100.0.4`); an address freed by
    `meshly revoke` goes to the next node that joins.
  - Every node that joined has one peer, the first node, and reaches there only what `meshly allow … from <node>`
    opens to it. The nodes that joined do not reach each other, also not through the first node.
  - `meshly invite` on a node that joined names the node to run it on, and in a network without a free address it
    stops with exit 5 before printing a code. A name that another node uses is refused at `join` with exit 5, and the
    invite waits on.
  See [hub and spokes](docs/architecture.md#d13-hub-and-spokes).

### Changed

- Invite codes start with `m2` (pairing protocol `meshly-pair/2`): the code carries the address of the joining node.
  The inviting and the joining node both need this version; a code of 0.0.5 or earlier is refused with
  `made by another meshly version`. Nodes that joined before keep working without an upgrade.
- The whole VPN network is routed into `meshly0`: a packet for a VPN address that is not a peer meets meshly's drop
  there and never leaves unencrypted through the default route. `meshly upgrade` adds the route when it restarts the
  service.
- `meshly doctor --probe` needs `--peer <name>` when the node has more than one peer.
- Messages and help name the new node or the other nodes instead of the second node.

## [0.0.5] - 2026-10-19

### Added

- `meshly-watch.service` applies a new or removed Docker network within seconds, for example after `docker compose up`
  or `down`, without a command. It follows interface and nftables changes and runs the same check as the timer; the
  check timer stays as a backstop. It starts and stops with `meshly.service`, also after `meshly upgrade`. A drop-in
  for `docker.service` re-applies meshly after Docker starts.
- `meshly status` lists the Docker networks (`docker networks`; `firewall.docker_networks` in `--json`) and the
  forward chains that may drop container traffic (`forward chains`; `firewall.forward_findings`), and `meshly logs`
  shows which networks appeared or went (`Docker networks changed: +br-…`).

### Changed

- Docker containers work through the VPN like programs on the server, with nothing to configure in Docker or compose:
  - A port published with `-p` or `ports:` on all addresses or on the VPN address opens to the peer with
    `meshly allow <host port>/<proto> from <peer>`. `deny` and `revoke` close it, established connections included.
  - Containers on Docker's bridge networks reach the other node, to the ports it allows, and appear there as this
    node's VPN address.
  - The LAN behind the node, container addresses and ports without `meshly allow` stay closed. The LAN stays closed
    also while the meshly table is missing: policy routing sends everything forwarded from the tunnel to a table that
    knows only the Docker networks. Ports that Docker publishes on all addresses or on the VPN address are open to
    the peer meanwhile, as the former are to the internet. `nft flush ruleset` also removes Docker's rules, and then
    every container port is open to the peer by container address until meshly re-applies its table, usually within
    seconds (see the [threat model](docs/threat-model.md)).
  - meshly's rule also goes to the top of the iptables `FORWARD` chain. A forward chain of the host firewall that may
    drop container traffic is a warning in `doctor` with the fix, and `status` names it; it is never a reason to
    refuse.
  - A problem on the containers' path never takes the tunnel between the hosts down. A Docker bridge that is set down
    is left out until it is up again, and a subnet that two Docker networks share is routed to the first of them by
    name. Routes of another program in routing table 109 turn container support off, with a warning and the fix.
    Any other failure while applying the Docker networks applies the configuration without them, with a warning and
    `completed without the Docker networks: …` in `meshly logs`; meshly retries every minute.
  - On a node without Docker networks nothing changes. See [docs/firewall.md](docs/firewall.md#docker).

### Fixed

- Reads of interfaces, addresses, routes and policy rules are retried when the kernel reports that they changed
  during the read (containers or virtual machines starting). `init`, `join`, `status` and the check could fail with
  `results may be incomplete or inconsistent` before.
- A verdict map in a foreign nftables chain (`iifname vmap @jumps`, `vmap { … : jump … }`) no longer counts as a rule
  that may drop meshly traffic by itself: meshly follows its jumps as it does a rule's own and finds a drop only
  where there is one. With Docker's nftables firewall backend, `init` stopped with exit 3 over Docker's NAT chains,
  with a fix for `/etc/nftables.conf` that did not apply.

## [0.0.4] - 2026-10-18

### Added

- `meshly nodes` lists the nodes of the network:
  - their VPN and public addresses;
  - whether each is connected: online, offline or never connected, with the time it was last seen;
  - what it may use on this node;
  - the next step for each node.
- `meshly ping [<node>] [-c N]` pings the other node through the tunnel from this node's VPN address. When no reply
  comes, it says why, with exit code 13: either the nodes have no connection, or the link works and the other node
  does not allow ping. In the second case it names the command to run there. Both commands accept `--json`
  (`meshly.nodes/v1` and `meshly.ping/v1`).

## [0.0.3] - 2026-10-18

### Fixed

- `upgrade` failed with `open lock /run/meshly/lock: no such file or directory` on a node where meshly had not run
  since the last boot, for example before `init`. It now creates `/run/meshly` itself. On 0.0.1 and 0.0.2, update
  with `install.sh` once, or run `sudo mkdir -p /run/meshly` before `meshly upgrade`.

## [0.0.2] - 2026-10-18

### Fixed

- fail2ban (with its nftables actions, the default on Ubuntu 24.04) no longer stops `init`, `invite` and `join`
  with exit 3 and an impossible fix for `/etc/nftables.conf`. A rule that drops addresses listed in a named set
  (fail2ban, sshguard, CrowdSec, your own blocklists) is a ban list: it needs no integration, and its bans apply to
  traffic through meshly too. Until a peer is known, rules on the peer's address are checked against the VPN
  network. A ban that hits a peer's address or endpoint is a warning with the command that lifts it
  (`fail2ban-client unban`), never a refusal, so it cannot keep meshly from starting.
- `install.sh` names `invite` and `join` with a code in its next steps, not an invite file.
- Release builds no longer depend on untracked files in the checkout (`-buildvcs=false`), and the release check
  downloads the release outside the checkout.

## [0.0.1] - 2026-10-18

First public release.

### Added

- Point-to-point network of two Linux nodes over kernel WireGuard: `init` creates it, `invite` prints a one-time
  code and waits, and `join` on the other node takes the code and pairs the two nodes through the WireGuard port,
  with no server and nothing new reachable from the internet or by local users. The code works once, expires after
  10 minutes by default (`--ttl`, at most 1 hour) and is read from a prompt or stdin, never from the command line,
  also when a paste broke it across lines. The joining node is named after its host name unless `--name` is given.
- Endpoint detection: `init` takes the public IPv4 address of the interface with the default route, so
  `meshly init homelab --name vps` needs no address; `join --endpoint auto` does the same for the joining node.
  Endpoints accept a bare IP, with the listen port (by default 51820).
- Default-deny policy in a single atomically replaced nftables table `inet meshly`: `allow`, `deny`, `rules`,
  `revoke`. Per-packet decisions (deny cuts established flows), no forwarding, no LAN access, no IPv6 inside the
  VPN, DNAT/redirect from the tunnel refused, spoofing protection.
- Firewall profiles `none` and `nftables` (integration through a packet mark), automatic selection, and refusal of
  firewalld, iptables-legacy rules and non-integrable chains before any change.
- UFW and iptables (`iptables-nft`) hosts work without configuration: meshly keeps its integration rule at the top
  of the `filter` chains `INPUT` and `OUTPUT` (IPv4 and IPv6), repairs it after `iptables-restore` and removes it on
  `stop` and `reset`; `status` shows each chain.
- Transactions with an operation journal, verification, rollback, forward recovery for operations that remove
  access, and safe mode; `recover` for interrupted operations.
- Lifecycle commands `start`, `stop`, `restart`, `set` (mtu, keepalive, endpoint, peer-endpoint, cidr), `reset`.
- systemd integration: `meshly.service`, `meshly-check.timer` (drift repair), nftables and netfilter-persistent
  drop-ins, networkd and NetworkManager unmanaged files, unit hardening.
- Diagnostics: `status` and `doctor` with `--json` (schemas `meshly.status/v1`, `meshly.doctor/v1`), `doctor --probe`,
  `logs`, stable exit codes.
- Signed self-upgrade from GitHub releases (`upgrade`), `install.sh` with signature verification, reproducible
  release builds for linux/amd64 and linux/arm64.

[Unreleased]: https://github.com/nikitakiselev/meshly/compare/v0.0.6...HEAD
[0.0.6]: https://github.com/nikitakiselev/meshly/compare/v0.0.5...v0.0.6
[0.0.5]: https://github.com/nikitakiselev/meshly/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/nikitakiselev/meshly/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/nikitakiselev/meshly/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/nikitakiselev/meshly/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/nikitakiselev/meshly/releases/tag/v0.0.1
