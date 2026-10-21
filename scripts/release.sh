#!/bin/sh
# Builds, signs and publishes a meshly release from the current commit.
#
#   scripts/release.sh 0.0.1
#
# Requirements: a clean work tree, tag v<version> on HEAD (created here if
# missing), CHANGELOG.md with a "## [<version>]" section, the private
# release key (see tools/release; default ~/.config/meshly-release/release.key)
# Python 3 and an authenticated gh CLI. The private key never leaves this machine;
# GitHub only receives the signed artifacts.
set -eu

# Keep local release builds on the reviewed security toolchain.
export GOTOOLCHAIN=go1.27.3

die() { printf 'release: %s\n' "$*" >&2; exit 1; }

[ $# = 1 ] || die "usage: scripts/release.sh X.Y.Z"
V=$1
printf '%s' "$V" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' || die "invalid version $V"
cd "$(dirname "$0")/.."

[ -z "$(git status --porcelain)" ] || die "work tree is not clean"
[ -s release-key.pub ] || die "release-key.pub is missing"
[ "$(go run ./tools/release pubkey)" = "$(cat release-key.pub)" ] ||
	die "the private release key does not match release-key.pub"

NOTES=$(awk -v v="$V" '
	$0 ~ "^## \\[" v "\\]" { on = 1; next }
	on && /^## \[/ { exit }
	on { print }' CHANGELOG.md)
[ -n "$NOTES" ] || die "CHANGELOG.md has no section for $V"

if git rev-parse -q --verify "refs/tags/v$V" >/dev/null; then
	[ "$(git rev-parse "v$V^{commit}")" = "$(git rev-parse HEAD)" ] || die "tag v$V does not point at HEAD"
else
	git tag -a "v$V" -m "meshly $V"
fi

# Scan the exact Linux source and built artifacts before signing or publishing.
SCAN_DIR=$(mktemp -d)
trap 'rm -rf "$SCAN_DIR"' EXIT HUP INT TERM
GOBIN="$SCAN_DIR" go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$SCAN_DIR/govulncheck" ./...
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 "$SCAN_DIR/govulncheck" ./...
make dist VERSION="$V" COMMIT="$(git rev-parse --short=12 HEAD)"
for bin in dist/meshly-"$V"-linux-amd64 dist/meshly-"$V"-linux-arm64; do
    go version -m "$bin"
    GOVULNCHECK="$SCAN_DIR/govulncheck" python3 scripts/scan-binary.py "$bin"
done
make sign
for f in dist/meshly-"$V"-linux-amd64 dist/meshly-"$V"-linux-arm64 dist/install.sh dist/SHA256SUMS dist/SHA256SUMS.sig; do
	[ -s "$f" ] || die "missing $f"
done

git push origin "v$V"
printf '%s\n' "$NOTES" | gh release create "v$V" --verify-tag --title "meshly $V" --notes-file - \
	dist/meshly-"$V"-linux-amd64 dist/meshly-"$V"-linux-arm64 dist/install.sh dist/SHA256SUMS dist/SHA256SUMS.sig
printf 'Released v%s.\n' "$V"
