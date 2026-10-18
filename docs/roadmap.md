# Roadmap

meshly 0.0.x is deliberately narrow: two nodes, IPv4 inside the tunnel, nftables only. This page lists what is
planned, roughly in order. Nothing here is a commitment to a date. Suggestions are welcome in
[issues](https://github.com/nikitakiselev/meshly/issues).

## Next

- **Real VM tests.** Run the integration suite in full virtual machines (real reboots, real `systemd-networkd` and
  NetworkManager, a real firewalld) in addition to containers. See [testing.md](testing.md#not-verified).
- **Upgrade rollback test.** An integration test where the new binary fails to start and `meshly upgrade` must
  restore the previous one.
- **Safe-mode backoff.** The check timer retries a failed configuration every minute; retries should back off and
  be visible in `status`.
- **Key rotation.** `meshly rotate-keys` for the WireGuard key, coordinated with the peer, without pairing again.
- **Packaging of the release key.** Publish the release public key in more places (website, keyserver-style
  transparency) and document key rollover.

## Later

- **More than two nodes.** Hub-and-spoke first (one public node, several nodes behind NAT), with per-peer rules.
  This needs invites that add a node to an existing network and policy sets keyed by peer.
- **Host names in endpoints.** Resolve DNS names for `--endpoint` / `set peer-endpoint`, with re-resolution when
  the handshake goes stale.
- **IPv6.** IPv6 transport endpoints are accepted today but not yet covered by integration tests; IPv6 *inside* the tunnel is blocked. Dual-stack VPN
  addressing would need a second policy family.
- **Firewall adapters.** firewalld (zones/policies) and ufw adapters, so those hosts are supported instead of
  refused.
- **Distribution packages.** `.deb` packages with the same signing key, as an alternative to `install.sh`.
- **Metrics.** A textfile collector output for node_exporter (handshake age, bytes, denied packets).

## Not planned

- A coordination server or any cloud component. The nodes pair directly, with a one-time code, through the
  WireGuard port.
- Running arbitrary user commands (`PostUp`/`PostDown`-style hooks).
- Managing cloud provider firewalls or security groups.
