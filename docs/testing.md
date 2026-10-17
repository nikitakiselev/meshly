# Testing

meshly is tested in four layers: unit tests with an in-memory fake kernel,
fuzz tests of every parser that reads untrusted input, fault injection
inside real transactions, and integration tests with real packets between
Linux network namespaces. This document lists what each layer covers, how to
run it, and, at the end, what has **not** been verified. Background:
[architecture.md](architecture.md), [threat-model.md](threat-model.md),
[firewall.md](firewall.md).

## Quick reference

| Command | What it runs | Needs |
|---|---|---|
| `make vet` | `gofmt`, `go vet` for Linux, with and without `meshly_faultinject` | Go |
| `make test` | `go test ./...` | Go |
| `make fuzz` | each fuzz target for `FUZZTIME` (default 30s) | Go |
| `make integration` | `go test -tags integration ./test/integration/...` | Linux kernel with WireGuard and nf_tables, Docker, Go |
| `make dist` | reproducible release build for amd64 and arm64 | Go, `release-key.pub` |

## Unit tests

`go test ./...` runs on any OS with Go. Tests that need Linux-only code
(`internal/cli/flow_linux_test.go`) are built only on Linux.

| Package | Covers |
|---|---|
| `internal/model` | Validation of every configuration field (names, interface names, CIDRs, addresses, endpoints incl. IPv6 notation, ports, MTU, keepalive, mark, keys), rule parsing, address allocation, conflicts with local prefixes. |
| `internal/store` | Directory and file modes and ownership, refusal of symlinks and non-regular files, atomic writes, bounded reads of untrusted files, config history pruning, keys (never printed, wiped), runtime and bootstrap state. |
| `internal/journal` | Append/read, torn and corrupt lines after a crash, incomplete operation detection, rotation (never with an open operation). |
| `internal/bootstrap` | Round trip of invite → request → accept, tampering of every part, signature domain separation, strict JSON (unknown, duplicate or non-canonical keys), validity periods and clock skew, accept pinned to the inviter, fingerprints. |
| `internal/nft` | Deterministic rendering and policy hash, rule shapes (default deny, no forwarding, DNAT refusal, IPv4 only, no `established` shortcut inbound), lockdown table, rejection of unsafe input, ownership marker round trip, analysis of foreign rulesets. |
| `internal/engine` | Bring-up order (firewall first), tear-down order (traffic path first), idempotency, ownership conflicts, backward rollback (also after the config was saved), forward completion, safe mode when rollback fails, recovery in both directions, drift, endpoint hints. Uses `internal/engine/enginetest`. |
| `internal/preflight` | UFW/firewalld/legacy iptables detection, local port parsing and listen port selection, conflict checks, profile selection and firewall evaluation. |
| `internal/systemd` | Unit rendering (unsafe executable paths refused), installation incl. networkd/NetworkManager files and the nftables drop-in, uninstall, exact `systemctl` argument vectors, state parsing. |
| `internal/upgrade` | Release key parsing, signed message format, signature verification, `SHA256SUMS` parsing (single version), version comparison, download over a local test server with tampered files, URL policy (HTTPS only, loopback for tests), binary install and rollback. |
| `internal/cli` (Linux) | Full two-node flow (`init` → `invite` → `join` → `approve` → `activate` → `allow`/`deny`/`revoke`) on two fake kernels, absence of private keys in all output and copied files, exit codes (including 7 rolled back and 8 safe mode, and leaving safe mode with `start`), rejection of invalid bootstrap files. |

`internal/nft/testdata/nft-1.0.6` and `nft-1.0.9` hold `nft -j list ruleset`
output captured from real nftables 1.0.6 (Debian 12) and 1.0.9
(Ubuntu 24.04): empty ruleset, host firewalls with and without the
integration rule, a misplaced rule, compatible accept rules, named sets,
Docker, iptables-nft, UFW, firewalld, flowtable/netdev, and meshly's own
table.

To run the Linux-only CLI tests from macOS, build the test binary and run it
in a Linux container:

```
GOOS=linux GOARCH=arm64 go test -c -o bin/cli.test ./internal/cli
docker run --rm -v "$PWD/bin:/t" debian:12 /t/cli.test -test.v
```

## Fuzzing

`make fuzz` (set `FUZZTIME`, e.g. `make fuzz FUZZTIME=5m`) runs:

| Target | Input |
|---|---|
| `internal/bootstrap` `FuzzOpen` | bootstrap envelopes (invite, request, accept files) |
| `internal/model` `FuzzParseRule` | `allow`/`deny` arguments |
| `internal/model` `FuzzParseEndpoint` | `IP:PORT` endpoints |
| `internal/model` `FuzzParseCIDR` | VPN network CIDRs |
| `internal/nft` `FuzzParseRuleset` | `nft -j list ruleset` JSON, seeded with the fixtures; analysis must not panic |
| `internal/store` `FuzzDecodeConfig` | `meshly.json` |

## Fault injection

Binaries built with `-tags meshly_faultinject` read
`MESHLY_FAULT="<point>=<error|crash>[,...]"`. `error` makes the point return
an error; `crash` exits the process immediately with status 137 and no
cleanup, which stands in for `kill -9` or power loss. Release builds compile
every point to a no-op and ignore the variable.

| Point | Location |
|---|---|
| `tx:after-begin` | after the `begin` record was written |
| `step:<name>` | before each plan step (`firewall.apply`, `link.create`, `link.sysctl`, `link.address`, `wireguard.configure`, `link.up`, `routes.sync`, `link.down`, `link.delete`, `firewall.remove`, …) |
| `tx:before-verify` | after all steps |
| `tx:before-save` | before saving the configuration (backward operations only) |
| `tx:before-commit` | before the `commit` record |
| `tx:rollback` | at the start of rollback or retry (used to force safe mode) |

The same build reads `MESHLY_TEST_RELEASE_URL` so that upgrade tests can use
a local release server. The integration tests use this build.

## Integration tests

`make integration` builds a fault-injection binary, a test file server and
the container images, then runs each test in its own lab. Every node is a
privileged Docker container with its **own network namespace**; meshly never
runs on the host's network stack. Containers and networks carry the label
`meshly-it=1` and are removed afterwards (set `MESHLY_IT_KEEP=1` to keep the
containers of a failed test). `MESHLY_IT_DISTROS=deb12,u2404` selects the
distributions (default: both).

Topology of each lab:

```mermaid
flowchart TB
    subgraph wan["wan 198.51.100.0/24"]
        vps["vps .10"]
        attacker["attacker .66"]
    end
    natgw["natgw .2<br/>masquerade"]
    subgraph lan["lan 192.168.77.0/24"]
        home["home .10"]
        lanhost["lanhost .20"]
    end
    wan --- natgw --- lan
```

Images: `node.Dockerfile` on Debian 12 and Ubuntu 24.04 (nftables,
iptables, iproute2, wireguard-tools, conntrack, netcat), and
`systemd.Dockerfile` on Debian 12 with systemd as PID 1. A container
restart stands in for a reboot: the network namespace, interface and all
nftables tables are recreated empty, and systemd boots again.

| Test | What it shows with real packets |
|---|---|
| `TestPolicy` (Debian 12 and Ubuntu 24.04) | Handshake through NAT; nothing is reachable in either direction before `allow`; `allow` opens exactly one port, protocol and direction (TCP and UDP; ping needs its own rule); an outside host routing to the VPN address over the public network gets nothing; `revoke` closes all access and removes the peer's key, route and rules. |
| `TestDenyStopsEstablishedFlow` | A running TCP stream (ESTABLISHED in conntrack) receives no further data after `deny`; new connections fail. |
| `TestCompromisedPeerContained` | With root on the VPS turned hostile (meshly table removed, WireGuard allowed-ips and routes widened): no access to the home LAN, to home's LAN address, to ports without a rule, with a spoofed VPN source address (from the VPN and from the LAN), or through Docker-style DNAT and redirect; forwarding stays blocked even after `forwarding=1` is set on the interface, and the check repairs that sysctl. |
| `TestForeignStatePreserved` | Foreign nftables tables, routes, interfaces and public SSH are byte-for-byte unchanged across `init`, `allow`, `set mtu`, `stop`, `start`, `revoke` and `reset`; `reset` leaves no meshly objects. |
| `TestNATAndIdle` | With 30 s UDP conntrack timeouts on the NAT gateway, the link works after 70 s idle, and again after all NAT mappings are flushed. |
| `TestIdempotency` | Repeating `init`, `invite` (same invite), `activate` and `allow` leaves the kernel state (interface, routes, WireGuard, nftables) exactly as before. |
| `TestConcurrentOperations` | Parallel commands are serialised by the lock; `status` works while they run. |
| `TestBootstrapTrust` | Modified invites, requests and accepts are rejected (exit 4); a wrong expected fingerprint stops `join`/`approve` (exit 10); invites are one-time; an accept activates only the node whose request it answers; private keys never appear in output or in copied files. |
| `TestInviteExpiry` | Expired invites are refused. |
| `TestFaultsInit` | `init` with `error` and `crash` at every point leaves either nothing or the complete, verified configuration after recovery. |
| `TestFaultsAllow` | An interrupted `allow` is either fully in effect (config and packets) or not at all; with a failing rollback, safe mode removes the interface, the lockdown table admits no peer, and `start` restores the link without the failed rule. |
| `TestFaultsReduce` | Interrupted `deny`, `stop` and `revoke` are completed by recovery; access is closed afterwards in every case. |
| `TestFaultActivate` | A crash during `activate` is rolled back and `activate` can be repeated. |
| `TestUnsupportedFirewalls` | UFW, firewalld, legacy iptables rules and an iptables-nft drop chain each stop `init` and `init --dry-run` with exit 3 and a message naming the cause, with no change to the host. |
| `TestNativeNftablesProfile` | A host firewall with `policy drop`: refused without the integration rule and with a misplaced one; works with it; the application port stays closed publicly and public SSH stays open; SSH is not reachable through the VPN without a rule; deleting the meshly table closes what meshly opened (fail-closed) until the check repairs it; with the integration rule removed, `allow` is refused, `deny`/`revoke` still work, and `doctor` exits 12 with the rule to add. |
| `TestSystemdLifecycle` | Units enabled and active after pairing; after a reboot the link and an allowed service come back, with the firewall table installed before the interface; `systemctl stop/start/restart meshly` leave the configuration unchanged; `meshly stop` survives a reboot; an operation crashed before a reboot is recovered at boot and does not take effect; `nftables.service` start, reload and restart with `flush ruleset` keep the meshly table and the service reachable; the check timer is scheduled, and `meshly-check.service` restores a deleted table; after safe mode, `meshly-check.service` brings the link back from the saved configuration without the failed change. |
| `TestInstallUpgradeUninstall` | `install.sh` installs from a local release tree and refuses a tampered `SHA256SUMS` or binary; `upgrade --check`, `upgrade` (needs `--yes` non-interactively), `.prev` kept, repeated upgrade is a no-op; the service is reachable after the upgrade; a downgrade needs `--force` (exit 5); a modified `SHA256SUMS` (signature mismatch) is refused (exit 4) without changing the binary; `reset` removes units, kernel objects and state without touching foreign state. |

A full run takes about 7 minutes on an Apple-silicon laptop with OrbStack.

## Continuous integration

`.github/workflows/ci.yml` runs on pushes to `main` and on pull requests:

- `lint`: `gofmt`, `go mod tidy -diff`, `go vet` (plain, `meshly_faultinject`,
  `integration`), `shellcheck scripts/*.sh`;
- `test`: `go test -race ./...` and the fault-injection build, on
  `ubuntu-24.04` (amd64) and `ubuntu-24.04-arm` (arm64);
- `fuzz`: every fuzz target for 15 s;
- `build`: `make dist` for both architectures, uploaded as an artifact;
- `integration`: `make integration` on `ubuntu-24.04` after loading the
  `wireguard` and `nf_tables` modules.

`.github/workflows/release-verify.yml` runs when a release is published (or
manually for a tag). It verifies the Ed25519 signature of `SHA256SUMS` with
`release-key.pub` from the repository, using `openssl` as `install.sh` does,
checks the released files against `SHA256SUMS`, rebuilds the release from the
tag and requires identical checksums.

## Reproducible builds

Release builds use `CGO_ENABLED=0`, `-trimpath`, `-buildid=` and fixed
`-ldflags`, with the Go version from `go.mod`. While preparing 0.0.1, `make
dist VERSION=0.0.1` was run on macOS (arm64) and in a `golang:1.27.2` Linux
container, and the two `SHA256SUMS` files were identical. To check a release
yourself:

```
git checkout v0.0.1
make dist VERSION=0.0.1 COMMIT=$(git rev-parse --short=12 HEAD)
gh release download v0.0.1 --dir released
diff released/SHA256SUMS dist/SHA256SUMS
```

## Not verified

The following is not covered by the tests above. Treat these areas with more
care, and please report results from real systems.

- **Containers, not virtual machines.** All integration nodes share one host
  kernel (OrbStack's Linux kernel locally, the runner's kernel in CI). Network
  namespaces give each node its own interfaces, routes, conntrack and
  nftables, but kernel versions and module loading are not varied.
- **No real reboot.** A container restart recreates the network namespace and
  boots systemd, but no kernel, initramfs or real boot ordering with
  networkd/NetworkManager and cloud-init is involved.
- **firewalld and UFW are simulated.** Detection is tested with firewalld's pid
  file and UFW's `ENABLED=yes`, and with captured rulesets in unit tests. Real
  firewalld and UFW were not installed.
- **NetworkManager and systemd-networkd** are not running in the test images;
  only the installation of the "unmanaged" files is unit-tested.
- **Upgrade rollback after a failed service start** (restore `.prev`, restart,
  exit 7) is not integration-tested. Binary installation and rollback are
  unit-tested; the restart path is not.
- **Automatic firing of the check timer.** The test checks that the timer is
  scheduled and starts `meshly-check.service` by hand.
- **Distribution coverage.** Only Debian 12 (nftables 1.0.6) and Ubuntu 24.04
  (nftables 1.0.9). `TestPolicy` runs on both; all other integration tests,
  including all systemd tests, run on Debian 12 only.
- **Architecture coverage.** The integration suite was run locally on arm64.
  amd64 is covered only by the CI workflow.
- **IPv6 transport.** Validation accepts IPv6 endpoints (`[2001:db8::1]:51820`),
  but no test runs WireGuard over IPv6. Learned endpoint hints are used only
  for IPv4. IPv6 inside the VPN is not supported by design.
- **Real networks.** One Linux masquerading NAT with short timeouts; no
  carrier-grade or symmetric NAT, no real cloud firewalls or security groups,
  no path-MTU problems.
- **Docker** is simulated with equivalent nftables DNAT/redirect rules and a
  captured Docker ruleset; a real Docker daemon on a meshly host was not
  tested.
- **install.sh over GitHub.** Tests serve the release tree over local HTTP
  (`MESHLY_BASE_URL`); downloads from github.com over HTTPS are not part of
  the suite.
- **Long-term behaviour and performance** (days of uptime, throughput, CPU
  cost of the per-packet policy) were not measured.
