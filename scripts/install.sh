#!/bin/sh
# meshly installer.
#
#   curl -fsSL https://github.com/nikitakiselev/meshly/releases/latest/download/install.sh | sudo sh
#
# Downloads the meshly binary for this machine from GitHub Releases,
# verifies the Ed25519 signature of SHA256SUMS with the release key below
# and the SHA-256 of the binary, and installs it as /usr/local/bin/meshly.
# It changes nothing else: no network, firewall or systemd configuration
# (that is done later by `meshly init` / `meshly join`).
#
# Environment:
#   MESHLY_VERSION=X.Y.Z   install this version instead of the latest
#   MESHLY_BASE_URL=URL    mirror of https://github.com/nikitakiselev/meshly/releases
set -eu

RELEASE_KEY="@RELEASE_KEY@" # base64 Ed25519 public key, set when the release is built
BASE_URL="${MESHLY_BASE_URL:-https://github.com/nikitakiselev/meshly/releases}"
VERSION="${MESHLY_VERSION:-}"
DEST=/usr/local/bin/meshly

say() { printf '%s\n' "$*"; }
die() { printf 'meshly install: error: %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = Linux ] || die "meshly runs on Linux only"
[ "$(id -u)" = 0 ] || die "run as root, e.g.: curl -fsSL .../install.sh | sudo sh"
case "$RELEASE_KEY" in @*) die "this install.sh was not built for a release (no signing key)";; esac
case "$(uname -m)" in
	x86_64 | amd64) ARCH=amd64 ;;
	aarch64 | arm64) ARCH=arm64 ;;
	*) die "unsupported architecture $(uname -m) (supported: amd64, arm64)" ;;
esac
command -v openssl >/dev/null 2>&1 || die "openssl is required to verify the release signature (apt install openssl)"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required (coreutils)"
if command -v curl >/dev/null 2>&1; then
	fetch() { curl -fsSL --proto '=https,http' --retry 3 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -q -O "$2" "$1"; }
else
	die "curl or wget is required"
fi
case "$VERSION" in
	"") DIR="$BASE_URL/latest/download" ;;
	*[!0-9A-Za-z.-]*) die "invalid MESHLY_VERSION" ;;
	*) DIR="$BASE_URL/download/v$VERSION" ;;
esac

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

say "Downloading release information from $DIR ..."
fetch "$DIR/SHA256SUMS" "$TMP/SHA256SUMS" || die "cannot download SHA256SUMS"
fetch "$DIR/SHA256SUMS.sig" "$TMP/SHA256SUMS.sig" || die "cannot download SHA256SUMS.sig"

# Ed25519 over "meshly-release/1" || 0x00 || SHA256SUMS. The PEM wraps the
# raw key in the fixed SubjectPublicKeyInfo prefix for Ed25519.
printf '%s\n' '-----BEGIN PUBLIC KEY-----' "MCowBQYDK2VwAyEA$RELEASE_KEY" '-----END PUBLIC KEY-----' >"$TMP/key.pem"
printf 'meshly-release/1\000' >"$TMP/msg"
cat "$TMP/SHA256SUMS" >>"$TMP/msg"
openssl base64 -d -A -in "$TMP/SHA256SUMS.sig" -out "$TMP/sig" 2>/dev/null || die "malformed SHA256SUMS.sig"
openssl pkeyutl -verify -pubin -inkey "$TMP/key.pem" -rawin -in "$TMP/msg" -sigfile "$TMP/sig" >/dev/null 2>&1 ||
	die "SIGNATURE VERIFICATION FAILED: SHA256SUMS is not signed by the meshly release key; nothing was installed"
say "Signature of SHA256SUMS verified."

LINE=$(grep -E "^[0-9a-f]{64}  meshly-[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?-linux-$ARCH\$" "$TMP/SHA256SUMS" || true)
[ -n "$LINE" ] || die "the release has no binary for linux/$ARCH"
[ "$(printf '%s\n' "$LINE" | wc -l)" = 1 ] || die "SHA256SUMS lists several binaries for linux/$ARCH"
ASSET=${LINE#*  }
REL_VERSION=${ASSET#meshly-}
REL_VERSION=${REL_VERSION%"-linux-$ARCH"}
[ -z "$VERSION" ] || [ "$VERSION" = "$REL_VERSION" ] || die "SHA256SUMS describes $REL_VERSION, expected $VERSION"

say "Downloading $ASSET ..."
fetch "$DIR/$ASSET" "$TMP/$ASSET" || die "cannot download $ASSET"
(cd "$TMP" && printf '%s\n' "$LINE" | sha256sum -c --status) || die "SHA-256 of $ASSET does not match the signed SHA256SUMS"
chmod 0755 "$TMP/$ASSET"
GOT=$("$TMP/$ASSET" version --short 2>/dev/null) || die "the downloaded binary does not run on this system"
[ "$GOT" = "$REL_VERSION" ] || die "the binary reports version $GOT, expected $REL_VERSION"

mkdir -p "$(dirname "$DEST")"
cp "$TMP/$ASSET" "$DEST.new"
chmod 0755 "$DEST.new"
mv -f "$DEST.new" "$DEST"
say "Installed meshly $REL_VERSION to $DEST."
say ""
say "Next steps (see https://github.com/nikitakiselev/meshly#quick-start):"
say "  on the server with a public IP:  sudo meshly init <network> --name <node>"
say "                                   sudo meshly invite   (prints a one-time code)"
say "  on the second server:            sudo meshly join     (asks for the code)"
