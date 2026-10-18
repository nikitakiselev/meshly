# meshly build targets. Release builds are reproducible: CGO off, -trimpath,
# no VCS stamp (untracked files would change it), fixed build ID,
# version/commit/release key injected via -ldflags.
VERSION     ?= $(or $(shell git describe --tags --match 'v*' --exact-match 2>/dev/null | sed 's/^v//'),0.0.0-dev)
COMMIT      ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
RELEASE_KEY ?= $(shell cat release-key.pub 2>/dev/null)
FUZZTIME    ?= 30s
PKG          = github.com/nikitakiselev/meshly/internal
LDFLAGS      = -s -w -buildid= \
               -X $(PKG)/version.Version=$(VERSION) \
               -X $(PKG)/version.Commit=$(COMMIT) \
               -X $(PKG)/upgrade.ReleaseKey=$(RELEASE_KEY)
GOFLAGS_REL  = -trimpath -buildvcs=false -ldflags '$(LDFLAGS)'
export CGO_ENABLED = 0

.PHONY: all build test vet fuzz integration dist sign clean

all: vet test build

build:
	GOOS=linux GOARCH=$(or $(GOARCH),$(shell go env GOARCH)) go build $(GOFLAGS_REL) -o bin/meshly ./cmd/meshly

vet:
	gofmt -l . | (! grep .)
	GOOS=linux go vet ./...
	GOOS=linux go vet -tags meshly_faultinject ./...
	go vet -tags integration ./test/...

test:
	go test ./...

fuzz:
	go test ./internal/model -run '^$$' -fuzz FuzzParseRule -fuzztime $(FUZZTIME)
	go test ./internal/model -run '^$$' -fuzz '^FuzzParseEndpoint$$' -fuzztime $(FUZZTIME)
	go test ./internal/model -run '^$$' -fuzz FuzzParseEndpointOrAddr -fuzztime $(FUZZTIME)
	go test ./internal/model -run '^$$' -fuzz FuzzParseCIDR -fuzztime $(FUZZTIME)
	go test ./internal/nft -run '^$$' -fuzz FuzzParseRuleset -fuzztime $(FUZZTIME)
	go test ./internal/pairing -run '^$$' -fuzz FuzzParseCode -fuzztime $(FUZZTIME)
	go test ./internal/pairing -run '^$$' -fuzz FuzzReadRequest -fuzztime $(FUZZTIME)
	go test ./internal/store -run '^$$' -fuzz FuzzDecodeConfig -fuzztime $(FUZZTIME)

# Integration tests run in privileged Docker containers, each with its own
# network namespace (never on the host network stack). Needs Docker and a
# kernel with WireGuard and nf_tables.
integration:
	go test -tags integration -count=1 -timeout 30m -v ./test/integration/...

# Release artifacts: binaries for amd64/arm64, install.sh with the release
# public key filled in, and SHA256SUMS. Sign them with `make sign`.
dist:
	@test -n "$(RELEASE_KEY)" || { echo "release-key.pub is missing" >&2; exit 1; }
	rm -rf dist && mkdir -p dist
	for arch in amd64 arm64; do \
	  GOOS=linux GOARCH=$$arch go build $(GOFLAGS_REL) -o dist/meshly-$(VERSION)-linux-$$arch ./cmd/meshly || exit 1; \
	done
	sed 's|@RELEASE_KEY@|$(RELEASE_KEY)|' scripts/install.sh > dist/install.sh
	cd dist && sha256sum meshly-$(VERSION)-linux-amd64 meshly-$(VERSION)-linux-arm64 install.sh > SHA256SUMS

# Signs dist/SHA256SUMS with the private release key (outside the repo, see
# tools/release) and checks the result against release-key.pub.
sign:
	go run ./tools/release sign dist/SHA256SUMS
	go run ./tools/release verify -pub '$(RELEASE_KEY)' dist/SHA256SUMS

clean:
	rm -rf bin dist
