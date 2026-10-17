# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until 1.0.0, minor versions may change the CLI and the
on-disk formats.

## [Unreleased]

## [0.0.1] - 2026-10-17

First public release.

### Added

- Point-to-point network of two Linux nodes over kernel WireGuard: `init`, `invite`, `join`, `approve`, `activate`.
  Bootstrap files are signed (Ed25519), one-time, time-limited and bound to each other; fingerprints are confirmed
  interactively or with `--expect-fingerprint`.
- Endpoint detection: `init` takes the public IPv4 address of the interface with the default route, so
  `meshly init homelab --name vps` needs no address; `join` does the same when the inviter has no endpoint. Endpoints
  accept a bare IP, with the listen port (by default 51820).
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
