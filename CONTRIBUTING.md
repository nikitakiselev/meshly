# Contributing to meshly

Thank you for helping. This guide covers the development setup, the tests and what a good pull request looks like.
By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). **Security issues go through
[SECURITY.md](SECURITY.md), not through public issues.**

## Ways to contribute

- **Bug reports:** open an [issue](https://github.com/nikitakiselev/meshly/issues/new/choose) with
  `meshly version`, the distribution, `meshly doctor --json` and the steps to reproduce.
- **Ideas:** check the [roadmap](docs/roadmap.md) first, then open an issue to discuss before writing a large
  change.
- **Documentation:** fixes and clarifications are always welcome. The Russian README (`README.ru.md`) should stay
  in sync with `README.md`.

## Development setup

You need Go (the toolchain version pinned in `go.mod` is downloaded automatically), `make`, and Docker for the
integration tests. meshly is Linux-only at runtime, but it builds and its unit tests run on macOS too.

```sh
git clone https://github.com/nikitakiselev/meshly && cd meshly
make vet        # gofmt check and go vet (all build tags)
make test       # unit tests
make build      # bin/meshly for linux/$(go env GOARCH)
```

> [!IMPORTANT]
> Never run a development build of meshly on your workstation's own network stack. meshly changes interfaces,
> routes and nftables. The integration tests run every node in its own privileged container with its own network
> namespace; use them, or a disposable VM.

## Tests

| Layer | Command | Notes |
|---|---|---|
| Unit | `make test` (`go test ./...`) | Pure Go; the CLI flow tests (`internal/cli/*_linux_test.go`) need Linux, see below |
| Race | `go test -race ./...` | CI runs this on amd64 and arm64 |
| Fuzz | `make fuzz` (`FUZZTIME=30s` per target) | Bootstrap envelope, rules, endpoints, CIDRs, nft JSON, config |
| Fault injection | `go test -tags meshly_faultinject ./...` | Builds with crash/error injection points; see [docs/testing.md](docs/testing.md) |
| Integration | `make integration` | Docker, privileged containers, kernel with WireGuard and nf_tables. About 10 minutes |

On macOS, run the Linux-only tests in a container:

```sh
GOOS=linux GOARCH=$(go env GOARCH) go test -c -o bin/cli.test ./internal/cli
docker run --rm -v "$PWD/bin":/b:ro debian:12 /b/cli.test
```

Integration tests work with Docker Engine on Linux and with OrbStack on macOS. They create containers and networks
labelled `meshly-it=1` and remove them afterwards. [docs/testing.md](docs/testing.md) describes the lab topology
and lists every scenario.

## Pull requests

- Keep each PR focused on one change. Describe the problem, the change and how you tested it.
- Add tests. A change to network behaviour needs an integration test that checks it with real packets, not only
  a unit test. A claim in the docs needs a test that verifies it.
- Keep the security properties: no shell, no user-supplied commands, no secrets in argv, logs or JSON, and no
  changes outside the `inet meshly` table. Every kernel change goes through the transaction engine.
- Update the docs and `CHANGELOG.md` (`Unreleased` section) for user-visible changes.
- Run `make vet test` before pushing. CI must be green.
- Use clear commit messages in the imperative ("Fix rollback when …"). Squash fixups before merge.

Contributions are licensed under the [Apache License 2.0](LICENSE), the license of the project.

## Releases (maintainers)

1. Update `CHANGELOG.md`: move `Unreleased` to `## [X.Y.Z] - date` and add the compare links.
2. Commit, push and wait for CI.
3. Run `scripts/release.sh X.Y.Z`. It tags the commit and builds reproducible binaries. It signs `SHA256SUMS` with
   the offline release key (`tools/release`; the private key never leaves the release machine) and publishes the
   GitHub release.
4. The [Verify release](.github/workflows/release-verify.yml) workflow rebuilds the release from the tag and checks
   the signature and the checksums.
