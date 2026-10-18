# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until 1.0.0, minor versions may change the CLI and the
on-disk formats.

## [Unreleased]

## [0.0.1] - 2026-10-17

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
  ufw, firewalld, iptables-legacy rules and non-integrable chains before any change.
- Transactions with an operation journal, verification, rollback, forward recovery for operations that remove
  access, and safe mode; `recover` for interrupted operations.
- Lifecycle commands `start`, `stop`, `restart`, `set` (mtu, keepalive, endpoint, peer-endpoint, cidr), `reset`.
- systemd integration: `meshly.service`, `meshly-check.timer` (drift repair), nftables drop-in, networkd and
  NetworkManager unmanaged files, unit hardening.
- Diagnostics: `status` and `doctor` with `--json` (schemas `meshly.status/v1`, `meshly.doctor/v1`), `doctor --probe`,
  `logs`, stable exit codes.
- Signed self-upgrade from GitHub releases (`upgrade`), `install.sh` with signature verification, reproducible
  release builds for linux/amd64 and linux/arm64.

[Unreleased]: https://github.com/nikitakiselev/meshly/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/nikitakiselev/meshly/releases/tag/v0.0.1
