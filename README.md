<div align="center">

# meshly

**A private, default-deny WireGuard link between two Linux servers: one command per step, nothing open by accident.**

[![CI](https://github.com/nikitakiselev/meshly/actions/workflows/ci.yml/badge.svg)](https://github.com/nikitakiselev/meshly/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/nikitakiselev/meshly?sort=semver)](https://github.com/nikitakiselev/meshly/releases)
[![License](https://img.shields.io/github/license/nikitakiselev/meshly)](LICENSE)
[![Go](https://img.shields.io/github/go-mod/go-version/nikitakiselev/meshly)](go.mod)

**English** · [Русский](README.ru.md)

</div>

meshly connects a server with a public IP (for example a VPS) and a server
behind NAT (for example a home server) over kernel WireGuard. It owns the
whole lifecycle: keys, interface, addresses, routes, nftables policy and the
systemd service. Nothing is reachable through the tunnel until you allow it
explicitly, port by port and peer by peer.

```text
 home server (behind NAT)                                VPS (public IP)
 ┌───────────────────────┐   WireGuard, UDP 51820    ┌───────────────────────┐
 │ meshly0  10.100.0.2   │ ◄────────────────────────►│ meshly0  10.100.0.1   │
 │ allow 9100/tcp from vps│                           │ allow 22/tcp from home│
 └───────────────────────┘                           └───────────────────────┘
   LAN, Docker networks and the public interfaces are never exposed to the peer
```

> [!NOTE]
> meshly is at an early stage (0.0.x). The CLI and the on-disk formats may still change between minor
> versions. Read the [threat model](docs/threat-model.md) and [what is not verified yet](docs/testing.md#not-verified)
> before you depend on it.

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Install](#install)
- [Quick start](#quick-start)
- [Everyday use](#everyday-use)
- [How it works](#how-it-works)
- [Security](#security)
- [Documentation](#documentation)
- [FAQ](#faq)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Default deny.** A peer can reach only the ports you list with `meshly allow`. A rule applies only to traffic
  coming in through the tunnel, in one direction (peer → this node). `meshly deny` also cuts connections that are
  already established.
- **No accidental exposure.** No forwarding into or out of the tunnel, no access to the LAN, and no IPv6 inside the
  VPN. Docker port publishing (DNAT) cannot be used to bypass the policy. Spoofed sources are dropped.
- **Secure bootstrap without a server.** Setup goes invite → join → approve → activate. The four files are one-time,
  time-limited and signed with Ed25519. Each side confirms the other's fingerprint by eye, and no secret passes
  through command-line arguments.
- **Safe changes.** Every change is a journaled transaction with verification and rollback. If a failure leaves the
  tunnel in an unknown state, meshly closes it (*safe mode*) rather than leaving it open. An operation interrupted by
  a crash or power loss is finished or rolled back on the next start.
- **Respects your firewall.** meshly owns one nftables table, `inet meshly`, replaces it atomically and never touches
  anything else. Unsupported setups (ufw, firewalld, iptables-legacy rules, foreign drop chains without integration)
  are detected *before* any change.
- **Survives the real world.** NAT and idle timeouts (keepalive on both sides), VPS restarts (instant re-handshake
  from learned endpoints), reboots, `systemctl restart nftables` and `flush ruleset`. A one-minute integrity check
  repairs drift.
- **Diagnosable.** `meshly status` and `meshly doctor` print human-readable reports, or stable JSON with `--json`.
  Exit codes are stable, and every finding says whether it was observed or inferred.
- **Signed self-upgrade.** `meshly upgrade` installs the latest GitHub release after checking an Ed25519 signature and
  SHA-256. It restarts the service and rolls back if the new version does not start. Release builds are
  reproducible.

## Requirements

| | |
|---|---|
| OS | Linux with systemd. Tested on **Debian 12** and **Ubuntu 24.04** |
| Architecture | `amd64`, `arm64` |
| Kernel | WireGuard in the kernel (built-in or module; any 5.6+ distribution kernel) |
| Firewall | nftables ≥ 1.0.6 (`/usr/sbin/nft`) on its own, or no firewall. Not supported: ufw, firewalld, iptables-legacy rules |
| Network | One node needs a public UDP port (default `51820`) that the other node can reach |
| Tools | `curl` or `wget`, `openssl`, `sha256sum` (installer only) |

meshly runs as root (`sudo`). It installs no packages and changes no global sysctl. It does not manage cloud
firewalls or security groups.

## Install

Run on **both** servers:

```sh
curl -fsSL https://github.com/nikitakiselev/meshly/releases/latest/download/install.sh | sudo sh
```

The installer downloads the binary for your architecture and verifies the Ed25519 signature of `SHA256SUMS` with
the release key built into the script. It then checks the binary's SHA-256 and installs it as
`/usr/local/bin/meshly`. It makes no other change: the network, firewall and systemd setup is done later by
`meshly init`, `meshly join` and `meshly activate`.

<details>
<summary>Install a specific version, inspect the installer first, or verify by hand</summary>

```sh
# a specific version
curl -fsSL https://github.com/nikitakiselev/meshly/releases/latest/download/install.sh | sudo MESHLY_VERSION=0.0.1 sh

# read the script before running it
curl -fsSLO https://github.com/nikitakiselev/meshly/releases/latest/download/install.sh
less install.sh && sudo sh install.sh
```

Manual verification uses the public key from [`release-key.pub`](release-key.pub):

```sh
V=0.0.1; A=amd64   # or arm64
base=https://github.com/nikitakiselev/meshly/releases/download/v$V
curl -fsSLO $base/SHA256SUMS -O $base/SHA256SUMS.sig -O $base/meshly-$V-linux-$A
printf '%s\n' '-----BEGIN PUBLIC KEY-----' "MCowBQYDK2VwAyEA$(curl -fsSL https://raw.githubusercontent.com/nikitakiselev/meshly/main/release-key.pub)" '-----END PUBLIC KEY-----' > meshly-release.pem
{ printf 'meshly-release/1\000'; cat SHA256SUMS; } > msg
openssl base64 -d -A -in SHA256SUMS.sig -out sig
openssl pkeyutl -verify -pubin -inkey meshly-release.pem -rawin -in msg -sigfile sig
sha256sum --ignore-missing -c SHA256SUMS
sudo install -m 0755 meshly-$V-linux-$A /usr/local/bin/meshly
```

Every release is also rebuilt from the tagged source by the
[Verify release](.github/workflows/release-verify.yml) workflow, which checks that the published binaries match.
</details>

## Quick start

The example uses two servers:

- **vps**: public IP `203.0.113.10`. Allow inbound **UDP 51820** in your cloud firewall.
- **home**: behind NAT, can reach the VPS (for example over SSH).

meshly passes trust through small files. Copy them over a channel you already trust, such as `scp` to a host whose
SSH key you have verified. All copies below are run on **home**, because it can reach the VPS.

**1. On vps:** create the network and an invite.

```console
admin@vps:~$ sudo meshly init homelab --name vps --endpoint 203.0.113.10:51820
Network "homelab" created.
  this node:    vps  10.100.0.1 on meshly0
  firewall:     profile none; all inbound VPN traffic is denied until `meshly allow`
  fingerprint:  VJW7-OEX7-FGSZ-Y6TN-AID5-LTGJ-YBDE-OJNN

admin@vps:~$ sudo meshly invite --out home.invite
Invite written to home.invite (one-time, expires 2026-10-17T20:30:33Z).
  fingerprint:  VJW7-OEX7-FGSZ-Y6TN-AID5-LTGJ-YBDE-OJNN   <- the joining admin must see exactly this
```

**2. On home:** fetch the invite, join, and send the request back.

```console
admin@home:~$ scp admin@203.0.113.10:home.invite .
admin@home:~$ sudo meshly join home.invite --name home
Invite from node "vps" for network "homelab":
  inviter fingerprint: VJW7-OEX7-FGSZ-Y6TN-AID5-LTGJ-YBDE-OJNN
Does this fingerprint match the one printed by `meshly invite` on vps? Type 'yes' to continue: yes

Join request written to home.request. Nothing is trusted yet.
  your fingerprint: ECSR-MFJA-MIHL-ML4O-LBKG-YFZP-ETRH-4A7P   <- the admin of vps must see exactly this at approve

admin@home:~$ scp home.request admin@203.0.113.10:
```

**3. On vps:** approve the new node.

```console
admin@vps:~$ sudo meshly approve home.request
Join request from node "home":
  fingerprint:     ECSR-MFJA-MIHL-ML4O-LBKG-YFZP-ETRH-4A7P
Compare the fingerprint with the one printed by `meshly join` on home. Approve this node? Type 'yes' to approve: yes
Node "home" approved; its key is on meshly0 with allowed IP 10.100.0.2/32 only.
Accept written to home.accept.
```

**4. On home:** activate.

```console
admin@home:~$ scp admin@203.0.113.10:home.accept .
admin@home:~$ sudo meshly activate home.accept
Membership in network "homelab" is active.
  this node:  home 10.100.0.2
  peer:       vps 10.100.0.1 via 203.0.113.10:51820
```

**5. Allow what each side needs.** Rules are per node: a rule opens a port on the node where you run it.

```sh
admin@vps:~$  sudo meshly allow 22/tcp from home     # home may SSH to vps at 10.100.0.1
admin@home:~$ sudo meshly allow 9100/tcp from vps    # vps may scrape node_exporter on home at 10.100.0.2
admin@home:~$ sudo meshly allow ping from vps
```

**6. Check.**

```sh
sudo meshly status     # configuration, interface, handshake, traffic, rules, drift
sudo meshly doctor     # every check with a verdict; exit 0 = no problems
```

The link starts at boot via `meshly.service`. For scripts and automation, the non-interactive forms are
`meshly join … --expect-fingerprint FP` and `meshly approve … --expect-fingerprint FP`.

## Everyday use

| Task | Command |
|---|---|
| Open a service to the peer | `sudo meshly allow 5432/tcp from home` |
| Close it (cuts established connections too) | `sudo meshly deny 5432/tcp from home` |
| List rules | `sudo meshly rules` |
| Health and diagnostics | `sudo meshly status`, `sudo meshly doctor`, `sudo meshly doctor --probe 22/tcp` |
| Stop or start the link (stop survives reboot) | `sudo meshly stop`, `sudo meshly start`, `sudo meshly restart` |
| VPS changed its IP | `sudo meshly set peer-endpoint vps 198.51.100.7:51820` (on home) |
| Path with a smaller MTU | `sudo meshly set mtu 1380` (on both nodes) |
| Who changed what | `sudo meshly logs` |
| Upgrade to the latest release | `sudo meshly upgrade` (`--check` to only look) |
| Remove the peer | `sudo meshly revoke home` |
| Remove meshly from a node | `sudo meshly reset` |

Every command that changes something supports `--dry-run`. Run `meshly help <command>` for details. The full
reference, including exit codes and JSON schemas, is in [docs/cli.md](docs/cli.md).

## How it works

- **Kernel WireGuard** is configured over netlink. There is no `wg-quick`, no shell and no `PostUp`/`PostDown`
  hooks: meshly runs no user-supplied commands.
- **One nftables table**, `inet meshly`, holds the entire policy. It is replaced atomically and carries an ownership
  marker. Foreign tables are only read, to detect conflicts. With a native nftables ruleset that drops by default,
  you add one integration rule to your chain, and `meshly doctor` prints it for you
  ([firewall profiles](docs/firewall.md)).
- **Transactions**: each change is a plan of steps that is journaled, applied, verified and then committed. Failure
  rolls back, and an unknown state ends in safe mode (the tunnel closed). [Architecture](docs/architecture.md).
- **systemd**: `meshly.service` (oneshot) brings the link up at boot after the system firewall. `meshly-check.timer`
  re-applies the policy if something removed it. A drop-in re-applies it after `nftables.service` starts.

## Security

- Private keys are generated on the node, stored with mode `0600` under `/etc/meshly/keys`, and never printed,
  logged or put in JSON output.
- Bootstrap files are signed with Ed25519 and bound to each other, so they can be neither replayed nor reused.
  The fingerprints are what you compare by eye ([protocol](docs/bootstrap-protocol.md)).
- Releases are signed with an offline Ed25519 key. `install.sh` and `meshly upgrade` both verify the signature.
- The guarantees, and what is out of scope, are in the [threat model](docs/threat-model.md).

**Report vulnerabilities privately:** see [SECURITY.md](SECURITY.md). Do not open public issues for them.

## Documentation

| Document | Contents |
|---|---|
| [docs/cli.md](docs/cli.md) | Every command, flag, exit code and JSON output |
| [docs/architecture.md](docs/architecture.md) | Components, on-disk state, transactions, systemd, upgrade; design decisions |
| [docs/bootstrap-protocol.md](docs/bootstrap-protocol.md) | Invite / join / approve / activate specification |
| [docs/firewall.md](docs/firewall.md) | Packet path, the `inet meshly` table, supported firewall profiles, Docker |
| [docs/threat-model.md](docs/threat-model.md) | Assets, attackers, guarantees and non-goals |
| [docs/diagnostics-and-recovery.md](docs/diagnostics-and-recovery.md) | Reading `status` and `doctor`; runbooks; recovery and safe mode |
| [docs/testing.md](docs/testing.md) | Unit, fuzz and integration tests; what is and is not verified |
| [docs/roadmap.md](docs/roadmap.md) | Planned work |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

## FAQ

**Why not just `wg-quick`?** `wg-quick` sets up a tunnel. It does not decide what may cross it, it does not stop
Docker or forwarding from leaking your LAN, and it cannot roll back a half-applied change. meshly does all three.

**Can I connect more than two servers?** Not yet. A network has exactly two nodes in 0.0.x. See the
[roadmap](docs/roadmap.md).

**Does it work with ufw or firewalld?** No. meshly detects them and refuses to change anything, because it cannot
guarantee its policy alongside them. Native nftables, or no firewall at all, is supported.

**Are my Docker containers reachable through the VPN?** No. Published ports work through DNAT, and meshly drops
DNAT and forwarding for tunnel traffic. To expose a container service, publish it on the host and allow that port.
The [firewall docs](docs/firewall.md#docker) explain the details.

**What happens if the VPS reboots?** The home node re-handshakes as soon as the VPS is back. Both sides send
keepalives, and meshly remembers the last authenticated endpoint.

**How do I uninstall?** Run `sudo meshly reset` (removes the interface, firewall table, configuration, keys and
units), then `sudo rm /usr/local/bin/meshly`.

## Contributing

Bug reports, ideas and pull requests are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) for the development
setup (unit, fuzz and integration tests run locally in Docker) and the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

[Apache License 2.0](LICENSE).
