# Pairing protocol (`meshly-pair/1`)

This document specifies how the second node joins a network. The node with
a public endpoint (the **inviter**, for example a VPS) runs `meshly invite`,
which prints a one-time code and waits. The other node (the **joiner**, for
example a home server) runs `meshly join` and is given the code. The two
nodes then exchange everything they need through the WireGuard UDP port that
is already open, inside a temporary WireGuard tunnel that only the code
unlocks. There is no server, nothing to copy but the code, and nothing new
is reachable from the internet, even while the invite waits.

The implementation is in `internal/pairing` (the code, key derivation and
messages), `internal/cli/cmd_invite.go` and `internal/cli/cmd_join.go` (the
two sides), and `internal/engine` (temporary state on top of the saved
configuration).

See also: [architecture](architecture.md), [threat model](threat-model.md),
[firewall](firewall.md), [CLI reference and exit codes](cli.md),
[testing](testing.md).

## Overview

The addresses are those of the default network `10.100.0.0/24`: the
inviter is `10.100.0.1`, the joiner `10.100.0.2`.

```mermaid
sequenceDiagram
    autonumber
    participant A as Inviter (vps)
    participant B as Joiner (home)
    Note over A: meshly invite
    A->>A: secret S; temporary key K_t and preshared key from S
    A->>A: temporary peer K_t for 10.100.0.2/32,<br/>allow tcp/51820 from 10.100.0.2,<br/>listen on 10.100.0.1:51820
    A-->>B: invite code (copied by the administrator)
    Note over B: meshly join
    B->>B: check the code, preflight,<br/>derive K_t and the preshared key
    B->>B: temporary tunnel: own key K_t,<br/>peer = inviter key, preshared key, endpoint
    B->>A: WireGuard handshake (UDP 51820)
    B->>A: TCP to 10.100.0.1:51820: hello (name, WireGuard public key)
    A->>B: welcome (network, addresses, inviter)
    A->>A: transaction "invite": the joiner's peer replaces the temporary one
    B->>B: transaction "join": own key, saved configuration
    B->>A: WireGuard handshake with the real keys
    B->>A: TCP through the real tunnel: confirm
    A->>B: ok
    A->>A: close the invite: temporary rule and marker removed
```

Nothing grants access on its own:

- The temporary peer reaches only TCP port 51820 on the inviter's VPN
  address. Default deny applies to everything else.
- The joiner, once added, gets its `/32` as allowed IP and no service. It
  reaches nothing on the inviter until `meshly allow` there.
- Inbound traffic to the joiner is denied until its administrator runs
  `meshly allow` on it.

## Cryptographic primitives

meshly implements no cryptographic algorithm itself. It uses:

| Purpose | Primitive | Implementation |
|---|---|---|
| Secret of the code | 128 random bits | Go standard library `crypto/rand` |
| Temporary keys from the secret | HKDF-SHA256 | Go standard library `crypto/hkdf`, `crypto/sha256` |
| Checksum of the code | SHA-256, truncated | Go standard library `crypto/sha256` |
| WireGuard key pairs | Curve25519 | `golang.zx2c4.com/wireguard/wgctrl/wgtypes` |
| Tunnel encryption and authentication | WireGuard (Noise IK) with a preshared key | Linux kernel WireGuard module |
| Text form of the code | base32 (RFC 4648) | Go standard library `encoding/base32` |

Each node has one key pair: its WireGuard key, generated at `init`
(inviter) or `join` (joiner) and stored in
`/etc/meshly/keys/wireguard.key` (mode `0600`, directory `0700`). The
private key never leaves the node and is never printed. Authenticity during
pairing comes from WireGuard keys alone:

- the joiner knows the inviter's public key from the code, so only the
  inviter can answer through the temporary tunnel;
- the inviter accepts the temporary tunnel only from a node that knows the
  temporary private key and the preshared key, which only the code yields.

## The invite code

### Content

The code is the bytes below, followed by a checksum:

| Field | Size | Content |
|---|---|---|
| family | 1 | `4` (IPv4 endpoint) or `6` (IPv6 endpoint) |
| IP | 4 or 16 | The inviter's public endpoint address |
| port | 2 | The endpoint's UDP port, big-endian |
| key | 32 | The inviter's WireGuard public key |
| CIDR address | 4 | Network address of the VPN CIDR |
| CIDR bits | 1 | Prefix length of the VPN CIDR |
| expiry | 4 | Unix time in seconds (UTC), unsigned big-endian |
| secret | 16 | The secret `S`, 128 random bits |
| checksum | 4 | `SHA-256("meshly-pair/1" \|\| 0x00 \|\| all bytes above)[0:4]` |

The VPN addresses are not in the code: both nodes derive them from the
CIDR. The inviter gets the first host address, the joiner the second
(`model.AllocateAddresses`), for example `10.100.0.1` and `10.100.0.2`.

### Text form

The text form is `m1` followed by the bytes in lowercase base32 without
padding. Only `a`–`z` and `2`–`7` follow the prefix, so a double click in a
terminal selects the whole code. An IPv4 code has 111 characters, an IPv6
code 130. It cannot be much shorter without a server, because the 32 bytes
of the inviter's key must be in it.

`meshly join` parses the code as follows:

- whitespace anywhere and letter case are ignored, so a code that wrapped
  across lines still works;
- `m` followed by a digit other than `1` is a code of another format
  version: *"the invite code was made by another meshly version; upgrade
  meshly on both nodes"*;
- a missing prefix, invalid base32, a wrong length, an unknown family, a
  wrong checksum or an invalid field (the same validators as for the
  configuration: endpoint, key, CIDR) give *"the invite code is damaged or
  incomplete"*. The checksum tells a typo or a truncated paste from a valid
  code. It is not a signature: it protects against mistakes, not against
  someone who writes a different code;
- the code is refused as *expired* once the joiner's clock is more than
  5 minutes (`ClockSkew`) past the expiry. The tolerance covers clocks that
  differ between the nodes. Within it the joiner tries, and an invite that
  has already ended does not answer (exit 13).

Each of these refusals exits with code 4, before anything is changed.

### Derived keys

Both nodes derive the same two keys from the secret `S`:

```
K_t = HKDF-SHA256(secret = S, salt = none, info = "meshly-pair/1 wireguard-key", 32 bytes)
      clamped as a Curve25519 private key (RFC 7748)
PSK = HKDF-SHA256(secret = S, salt = none, info = "meshly-pair/1 preshared-key", 32 bytes)
```

- `K_t` is the joiner's **temporary** WireGuard private key. The inviter
  only uses its public key, for the temporary peer.
- `PSK` is the WireGuard preshared key of the temporary tunnel, set on both
  sides. It adds the secret to the handshake itself.

`K_t` and the PSK are held only in memory and wiped when the command ends.
They are never saved, journaled or printed, and neither is the code apart
from the one line `meshly invite` prints. Fixed test vectors guard the
derivation (`TestSecrets`).

## The inviter: `meshly invite`

1. Check the flags (`--ttl` from 1 minute to 1 hour, default 10 minutes;
   exit 2 otherwise) and take meshly's lock. The lock is held until the
   invite ends: `meshly-check.timer` skips its run while it is held, and
   other changing commands exit 6 with *"meshly invite is waiting for a
   node to join until …; let it finish or cancel it with Ctrl+C"*.
2. Refuse when the network already has a peer (exit 5), when the link is
   stopped (exit 5, *"run `sudo meshly start` first"*) or when this node
   has no public endpoint (exit 2, *"… sudo meshly set endpoint IP"*). Run
   the strict preflight (exit 3), as for `init`.
3. Create the code: the endpoint, the WireGuard public key and the CIDR of
   the saved configuration, the expiry, and a fresh secret `S`. Derive
   `K_t` and the PSK.
4. Apply the temporary state on top of the saved configuration (an engine
   *overlay*; it is never saved in `meshly.json` and never journaled):
   - a WireGuard peer with the public key of `K_t`, the PSK and allowed IP
     `10.100.0.2/32`, without an endpoint;
   - in the firewall table, `10.100.0.2` in `@peers` and
     `10.100.0.2 . tcp . 51820` in `allow_in` (see
     [firewall.md](firewall.md#during-an-invite)).
5. Write `/run/meshly/invite.json` (mode `0600`). It holds only the expiry
   and lets `status`, `doctor` and the busy message show the open invite.
   Journal `invite` `opened, expires <time>`.
6. Listen on TCP `10.100.0.1:51820`, the VPN address only.
7. Print the instructions to stderr and the code to stdout, alone on one
   line, then wait for requests, the expiry, or Ctrl+C.

Each request is one TCP connection carrying one message (see
[Messages](#messages)). The invite answers it according to its state:

| State | Request | Answer |
|---|---|---|
| waiting | `hello` with the inviter's own name | `reject` `name-taken` |
| waiting | `hello` with the inviter's key or the public key of `K_t` | `reject` `invalid` |
| waiting | `hello`, valid | `welcome`; then the joiner is added (below) |
| waiting | `confirm` | `reject` `invalid` (nobody has joined) |
| joined | `hello` | `reject` `used` |
| joined | `confirm` with another key than the joined node's | `reject` `invalid` |
| joined | `confirm` with the joined node's key | `ok`; the invite succeeds |
| any | a message that fails parsing or validation | none: the connection is closed |

**Adding the joiner.** After the `welcome`, a transaction `invite`
(direction backward) adds the joiner to the saved configuration: name,
address `10.100.0.2`, its WireGuard public key, its endpoint if it sent one,
keepalive 25 seconds. In the kernel, its peer replaces the temporary one,
which goes with its PSK. The allow rule for TCP 51820 stays until the
confirmation. If the transaction fails, the invite prints the error, puts
the temporary peer back and keeps waiting.

**Waiting for the confirmation.** The joined node has 1 minute to confirm.
If it does not, a transaction `invite-undo` (direction forward) removes it
again, the invite prints *"Node "home" did not confirm the connection; its
membership was undone."* and, while the code is valid, puts the temporary
peer back and prints *"The code stays valid until …"*. Requests that
arrived before the deadline are answered first, so a confirmation at the
last moment counts.

**End.** The invite ends when:

- the joined node confirmed: *"Node "home" (10.100.0.2) joined. The
  invite is closed."*, exit 0, and the systemd units are installed if they
  are not yet;
- Ctrl+C, SIGTERM or a hang-up of the terminal (SIGHUP, for example a
  closed SSH session) arrives: a node that joined but has not confirmed is
  undone first; exit 10. A SIGHUP that was ignored at start, as under
  `nohup`, stays ignored;
- the code expired while no node had joined: exit 13. A node that joined in
  time may still confirm after the expiry; if it does not, the undo ends the
  invite with exit 13.

On every way out the invite closes the listener, re-applies the saved
configuration (which removes the temporary peer, the PSK and the allow
rule), removes `/run/meshly/invite.json` and journals `invite` `closed:
joined <name>`, `cancelled`, `expired` or `failed`.

## The joiner: `meshly join`

1. Check the flags. The name is `--name`, or else the host name made into a
   node name: its first label, lowercased, every run of other characters
   than `a`–`z` and `0`–`9` turned into one `-`, at most 32 characters. If
   no valid name results, exit 2 with a request for `--name`.
2. Require root (exit 3) **before** reading the code, so the code is not
   pasted for nothing.
3. Read the code: after the prompt `Invite code: ` when stdin and stderr
   are terminals, otherwise the first line of stdin (at most 1 KiB). A code
   given as an argument is refused with exit 2: other users could see it in
   the process list, and it would stay in the shell history. Parse it (see
   [Text form](#text-form)); derive `K_t` and the PSK.
4. Take meshly's lock. Refuse when this node is already a member of a
   network (exit 5). Remove an interface or a table of meshly that no saved
   configuration explains: the leftovers of an interrupted join.
5. Detect the endpoint if `--endpoint auto` was given, pick the listen port,
   resolve the firewall profile and run the preflight for the network of
   the code (CIDR conflicts, interface, port, firewall; exit 3). **Nothing
   has been changed or sent yet.**
6. Load this node's WireGuard key, or generate it. If it equals the
   inviter's key in the code, the code was made on this node: exit 4.
7. Bring up the temporary tunnel through the engine (an overlay, never
   saved or journaled): `meshly0` with address `10.100.0.2/32` and the
   private key `K_t`; one peer, the inviter, with its public key and the
   PSK, endpoint from the code, allowed IP `10.100.0.1/32`, keepalive
   25 seconds; the firewall table with `10.100.0.1` in `@peers` and no
   allow rule.
8. Print *"Connecting to 203.0.113.10:51820..."* and connect to TCP
   `10.100.0.1:51820` through the tunnel, for at most 30 seconds. The
   WireGuard handshake happens on the way. Without an answer the tunnel is
   removed and `join` exits 13: *"the inviting node … did not answer. Either
   its invite is closed (expired, cancelled or already used): run `sudo
   meshly invite` there again; or UDP port 51820 does not get through to
   it: … Nothing was changed on this node."* From the joiner a blocked UDP
   port, an invite that has ended and a code of another invite look the
   same, because WireGuard drops a handshake it cannot authenticate without
   a reply. Ctrl+C gives exit 10 instead.
9. Send `hello` and read the answer. A `reject` is printed as *"the
   inviting node refused: …"* and exits with 5 (`name-taken`), 4 (`used`) or
   1 (`invalid`). A malformed answer exits with 1. In every case the tunnel
   is removed and nothing is changed.
10. Hold the `welcome` against the code: the CIDR, both addresses, the
    inviter's key and endpoint must equal what the code says, and the
    inviter's name must differ from this node's. Otherwise exit 1, nothing
    changed.
11. Build the configuration from the `welcome` and run the transaction
    `join` (direction backward, from no configuration). Its plan moves the
    kernel from the temporary tunnel to the real one in one transaction:
    the node's own private key, the real network ID on the interface, the
    real firewall table, no PSK. A failure rolls back to nothing.
12. Confirm through the real tunnel (see
    [Confirmation](#confirmation-through-the-real-tunnel)).

On success `join` installs the systemd units and prints:

```
Joined network "homelab" as "home" (10.100.0.2).
  peer:  vps 10.100.0.1 via 203.0.113.10:51820
Inbound VPN traffic to this node is denied until you run `meshly allow` here.
```

Both `invite` and `join` print the engine's steps to stderr. Their stdout
carries only the result: the code, or the summary above.

## Messages

The messages travel over TCP to port 51820 on the inviter's VPN address,
inside WireGuard. Each connection carries exactly one request and one
answer.

| Request (joiner → inviter) | Answers |
|---|---|
| `hello` | `welcome` or `reject` |
| `confirm` | `ok` or `reject` |

### Framing and strict parsing

A message is one JSON object on one line, ended by a newline, at most 4096
bytes including the newline (`MaxMessageSize`). Its form is
`{"type":"<type>","<type>":{…}}`, with exactly the one body that matches the
type; `ok` has no body. For example:

```json
{"type":"hello","hello":{"protocol":"meshly-pair/1","name":"home","wg_public_key":"Z4YzTt5wXZdSfsyoVJhIk0Q8KYaqf3moKZi95pr9DmA="}}
```

The decoder (`strictUnmarshal`) accepts exactly one JSON object and
rejects:

- a top-level value that is not an object, and trailing data after it;
- a duplicate key at any nesting level;
- any key outside `[a-z0-9_]{1,64}`. `encoding/json` matches field names
  case-insensitively, so without this rule `"Type"` would silently alias
  `"type"`;
- nesting deeper than 8 levels;
- unknown fields;
- a missing body, a second body, or a body of another type than `type`.

A line that is too long or does not end with a newline is rejected as
well. Both sides validate a message before they send it, and validate what
they receive with the validators of `internal/model`. Each side knows the
code, but the other one may still be malicious.

### Message types

**`hello`** (joiner → inviter):

| Field | Check |
|---|---|
| `protocol` | must be `meshly-pair/1` |
| `name` | node name: `^[a-z]([a-z0-9-]{0,30}[a-z0-9])?$`, reserved names excluded |
| `wg_public_key` | the joiner's own WireGuard public key: base64 of 32 bytes, not all zero |
| `endpoint` | optional; the joiner's public `IP:port` (`--endpoint`). Unspecified, multicast, broadcast, link-local and zoned addresses are refused |

**`welcome`** (inviter → joiner):

| Field | Check |
|---|---|
| `network_id` | 128 bits as 32 lowercase hex characters |
| `network_name` | name, as above |
| `cidr` | private IPv4, canonical, `/16`–`/30`; must equal the code |
| `mtu` | 1280–8920 |
| `inviter` | `name`, `address`, `wg_public_key`, `endpoint` (required); the address, key and endpoint must equal the code |
| `address` | the joiner's VPN address; must equal the code's second host address and differ from the inviter's |

**`reject`** (inviter → joiner): `reason` is `name-taken`, `used` or
`invalid`; `message` is printable ASCII of at most 200 bytes, so a hostile
inviter cannot put terminal escape sequences on the joiner's screen.

**`confirm`** (joiner → inviter): `wg_public_key`, the joiner's own key. It
must equal the key of the node that joined.

**`ok`** (inviter → joiner): no body.

### Timeouts

| Phase | Limit |
|---|---|
| Connect (joiner): the TCP connection through the temporary tunnel, WireGuard handshake included | 30 seconds |
| Exchange: one request and its answer, on either side | 10 seconds |
| Confirm (inviter): from adding the joiner to its `confirm` | 1 minute |
| Confirm (joiner): retries, once a second | ¾ of the inviter's limit (45 seconds) |

A silent peer runs into these limits; the inviter reads every connection in
its own goroutine, so one silent connection never holds up the invite.

## Confirmation through the real tunnel

After the `join` transaction the joiner connects to `10.100.0.1:51820`
again, now through the real tunnel with its own key, and sends `confirm`.
The connection can only pass when the real tunnel works in both
directions, so an `ok` tells both sides that pairing worked:

- the inviter answers `ok`, closes the invite and exits 0;
- the joiner receives `ok`, installs the systemd units and exits 0.

The joiner retries once a second for up to 45 seconds, so it gives up
before the inviter's minute is over. If it gets no `ok`:

- **No WireGuard handshake with the inviter since the switch to the real
  keys.** The real tunnel does not work. A transaction `join-undo`
  (direction forward) removes everything again, including the key if this
  run generated it, and `join` exits 7: *"no connection to the inviting node
  through the new tunnel, so this node was rolled back; run `sudo meshly
  join` again while the invite is open (until …)"*. The inviter undoes its
  side when its minute is over and waits again: the same code can be used
  once more. A handshake from the temporary tunnel does not count, because
  the kernel keeps it when the peer is updated in place.
- **A handshake happened, but no `ok` arrived.** The tunnel works and the
  answer may only have been lost, so the joiner keeps its configuration and
  exits 1: *"joined, but the inviting node did not acknowledge the
  connection; check `meshly status` on both nodes"*. If the inviter got the
  confirmation, both nodes are paired. If it did not, it undoes its side
  after its minute, and `meshly status` on it lists no peer; then run `sudo
  meshly reset` on the joiner and pair again.

## Rollback and cleanup

| Event | Inviter | Joiner |
|---|---|---|
| The joiner gets no answer | unchanged, keeps waiting | temporary tunnel removed; exit 13 |
| `reject` | keeps waiting | temporary tunnel removed; exit 5, 4 or 1 |
| The `join` transaction fails | undoes the joiner after 1 minute, keeps waiting | rolled back to nothing; exit 7 (8 if the rollback failed too: safe mode) |
| No confirmation, no new handshake | undoes the joiner after 1 minute, keeps waiting while the code is valid | `join-undo`; exit 7 |
| Ctrl+C, SIGTERM or hang-up of `invite` | undoes a joiner that has not confirmed; exit 10 | no answer (exit 13) or no confirmation (exit 7) |
| Ctrl+C, SIGTERM or hang-up of `join` | if the joiner was added: undoes it after 1 minute | temporary tunnel removed, or `join-undo`; exit 10 |
| The code expires | exit 13 if no node joined | refuses the code 5 minutes after the expiry (exit 4); before that, no answer (exit 13) |
| `invite` killed (`kill -9`) | the temporary state and `/run/meshly/invite.json` stay until the next command that takes the lock: see below | no answer (exit 13); exit 1 if it had already been added |
| `join` killed | if the joiner was added: undoes it after 1 minute | an interrupted `join` transaction is rolled back by the next command that takes the lock (or `meshly recover`); a temporary tunnel is removed by the next `join` |

**A killed invite.** Its lock goes with the process. The next meshly
command that takes the lock finds the marker, removes it and journals
`invite` `closed: interrupted`. The temporary peer and allow rule go with
the next application of the saved configuration: `meshly-check.timer` does
this within a minute (it sees them as drift), and `sudo meshly start` does
it at once. A joiner that the invite had already added stays, because its
transaction had committed. `/run` is emptied at boot, and the kernel state
is rebuilt from the saved configuration, so a reboot also removes all of
it.

## What the internet sees

While `meshly invite` waits:

- The only port open to the internet is still WireGuard's UDP port. It
  answers nothing to packets without valid keys, so it does not reveal the
  invite.
- The TCP listener is bound to the VPN address only. A packet for the VPN
  address that arrives on any other interface is dropped by `guard_pre`,
  and the allow rule admits only the source `10.100.0.2`. WireGuard accepts
  that source only from the temporary peer, that is, from a holder of `K_t`
  and the PSK, which only the code yields.
- Guessing does not help: the secret has 128 bits, and a failed WireGuard
  handshake gets no answer.

`TestPairingNothingExposed` checks this with real packets: the only new
socket is TCP `10.100.0.1:51820`; the public address does not accept TCP
51820; an outside host with a route to the VPN address through the VPS is
dropped by the guard (its counter grows); and no new UDP socket appears.
The threat model discusses the code itself, and who may hold it, in
[model 4](threat-model.md#4-attacker-who-obtains-or-substitutes-an-invite-code).

## Checks and exit codes

Exit codes are described in [cli.md](cli.md#exit-codes): 2 usage, 3
preflight, 4 invalid code, 5 conflict, 7 rolled back, 10 declined, 13
unreachable.

| Side | Check | Exit | Tested by |
|---|---|---|---|
| code | whitespace and letter case ignored | — | unit `TestParseCodeTolerantInput` |
| code | prefix, base32, length, family, checksum (typo, truncation) | 4 | unit `TestParseCodeErrors`, `FuzzParseCode`; CLI `TestJoinCodeInput`; integration `TestPairingRefusals` |
| code | fields: endpoint, key, CIDR | 4 | unit `TestParseCodeErrors` |
| code | another format version | 4 | unit `TestParseCodeErrors`; CLI `TestJoinCodeInput` |
| code | expired, beyond 5 minutes of clock skew | 4 | unit `TestParseCodeErrors`; CLI `TestJoinCodeInput`; integration `TestPairingRefusals` |
| code | round trip, IPv4 (111 characters) and IPv6 (130) | — | unit `TestCodeRoundTrip` |
| code | derived keys: fixed test vectors, clamping | — | unit `TestSecrets` |
| join | the code given as an argument | 2 | CLI `TestJoinCodeInput`; integration `TestPairingRefusals` |
| join | no code on input | 2 | CLI `TestJoinCodeInput` |
| join | not root, checked before the code is read | 3 | CLI `TestJoinCodeInput` |
| join | no valid name from the host name | 2 | CLI `TestJoinNameFromHostname` |
| join | preflight before any contact | 3 | CLI `TestJoinPreflightConflictBeforeContact` |
| join | already a member of a network | 5 | — |
| join | the code was made on this node | 4 | — |
| join | no answer within 30 seconds; nothing changed | 13 | CLI `TestJoinUnreachable`; integration `TestPairingUDPBlocked`, `TestPairingRefusals` |
| join | name taken | 5 | CLI `TestJoinNameTaken` |
| join | invite already used | 4 | CLI `TestJoinCodeUsed` |
| join | malformed or hostile answer | 1 | unit `TestHostilePeer` |
| join | `welcome` does not match the code | 1 | — |
| join | no confirmation, no handshake since the switch | 7 | CLI `TestConfirmFailureRollsBackBoth`, `TestJoinIgnoresTemporaryHandshake` |
| join | handshake, but no `ok` | 1 | CLI `TestJoinKeepsConfigAfterHandshake` |
| join | hang-up while confirming | 10 | CLI `TestJoinCancelDuringConfirm` |
| join | leftovers of an interrupted join removed | — | CLI `TestJoinCleansLeftovers` |
| join | crash in the `join` transaction | — | integration `TestFaultJoin` |
| invite | not initialized | 9 | CLI `TestInviteRefusals` |
| invite | arguments, `--ttl` outside 1 minute to 1 hour, no endpoint | 2 | CLI `TestInviteRefusals` |
| invite | a peer exists; the link is stopped | 5 | CLI `TestInviteRefusals` |
| invite | message size, framing, strict JSON, fields | — | unit `TestHostilePeer`, `TestMessageSizeBoundary`, `FuzzReadRequest` |
| invite | answers per state (name taken, keys of the invite, used, wrong key) | — | CLI `TestInviteSessionAnswers` |
| invite | a confirmation at the deadline counts | — | CLI `TestInviteConfirmAtDeadline` |
| invite | no confirmation: undo, wait again | — | CLI `TestConfirmFailureRollsBackBoth`; integration `TestFaultJoin` |
| invite | Ctrl+C | 10 | CLI `TestInviteCancelAndExpiry`; integration `TestPairingCleanup` |
| invite | hang-up; SIGHUP ignored under `nohup` | 10 | CLI `TestInviteHangUp`, `TestInterruptibleHangUp` |
| invite | expiry, also with a joined node that did not confirm | 13 | CLI `TestInviteCancelAndExpiry`, `TestInviteExpiresWhileUnconfirmed`; integration `TestPairingRefusals` |
| invite | killed: closed by the next command, removed by the check | — | CLI `TestLeftoverInviteClosed`; integration `TestPairingCleanup` |
| both | full pairing; no PSK, temporary peer or allow rule left; journal records | 0 | CLI `TestPairFlow`; integration `TestPairing` |

"—" in the last column means that no automated test covers this check
specifically.
