# Security policy

meshly manages network access between servers, so security reports are taken seriously and handled with
priority.

## Supported versions

| Version | Supported |
|---|---|
| Latest 0.0.x release | Yes |
| Older releases | No. Upgrade with `sudo meshly upgrade` |

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a vulnerability.**

Report it privately through GitHub:
[**Report a vulnerability**](https://github.com/nikitakiselev/meshly/security/advisories/new). Only the maintainers
can see the report.

Please include:

- the meshly version (`meshly version`), the distribution and the kernel version;
- what an attacker can do, and from which position (internet path, LAN, the peer, a local user, …; see the
  [threat model](docs/threat-model.md));
- steps to reproduce, ideally as a script for network namespaces or containers;
- `meshly status --json` and `meshly doctor --json` output if relevant. These outputs contain no private keys, but
  review them for addresses you do not want to share.

What to expect:

- an acknowledgement within 3 working days;
- an assessment and a planned fix date within 10 working days;
- a fixed release, a GitHub security advisory and credit in the changelog (unless you prefer to stay anonymous).

Please give us a reasonable time to release a fix before you disclose the issue publicly. 90 days is the default.

## Scope

In scope: anything that breaks a guarantee stated in [docs/threat-model.md](docs/threat-model.md). Examples:

- access through the tunnel to a port without an allow rule;
- reaching the LAN or another host through a node;
- joining a network without its invite code, or with a code that was already used or has expired;
- reaching anything on a node, other than the pairing exchange, through an open invite;
- leaking private keys or an invite code;
- installing a release that is not signed by the release key.

Out of scope: the non-goals listed in the threat model, such as a compromised root account on a node, the GitHub
account or the release key, and cloud firewalls.

## Release signing key

Releases are signed with an offline Ed25519 key. The public key is in [`release-key.pub`](release-key.pub) and is
embedded in `install.sh` and in every meshly binary:

```text
7gHr+V3cOgzQ5U42S737a9o1XOgXuIkB0imB2U/faxY=
```

The signature covers `meshly-release/1`, a zero byte and then the content of `SHA256SUMS`. The README shows how to
verify it by hand.
