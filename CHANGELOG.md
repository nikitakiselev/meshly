# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until 1.0.0, minor versions may change the CLI and the
on-disk formats.

## [Unreleased]

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

[Unreleased]: https://github.com/nikitakiselev/meshly/compare/v0.0.3...HEAD
[0.0.3]: https://github.com/nikitakiselev/meshly/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/nikitakiselev/meshly/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/nikitakiselev/meshly/releases/tag/v0.0.1
