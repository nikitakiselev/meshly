package nft

import (
	"net/netip"
	"os"
	"testing"

	"github.com/nikitakiselev/meshly/internal/model"
)

// fixtureInput is the input rendered into testdata/*/meshly.json.
func fixtureInput() Input {
	return Input{
		NetworkID:  "0123456789abcdef0123456789abcdef",
		Interface:  "meshly0",
		LocalAddr:  netip.MustParseAddr("10.100.0.1"),
		CIDR:       netip.MustParsePrefix("10.100.0.0/24"),
		ListenPort: 51820,
		Mark:       model.DefaultFirewallMark,
		Peers:      []netip.Addr{netip.MustParseAddr("10.100.0.2")},
		Allow: []AllowEntry{
			{Peer: netip.MustParseAddr("10.100.0.2"), Proto: model.ProtoTCP, Port: 22},
			{Peer: netip.MustParseAddr("10.100.0.2"), Proto: model.ProtoUDP, Port: 53},
			{Peer: netip.MustParseAddr("10.100.0.2"), Proto: model.ProtoPing},
		},
	}
}

// TestWriteFixtureScript writes the nft script used to regenerate the
// meshly.json fixtures (FIXTURE_OUT=path go test -run TestWriteFixtureScript).
func TestWriteFixtureScript(t *testing.T) {
	out := os.Getenv("FIXTURE_OUT")
	if out == "" {
		t.Skip("FIXTURE_OUT not set")
	}
	r, err := Render(fixtureInput())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, []byte(r.ApplyScript()), 0o644); err != nil {
		t.Fatal(err)
	}
}
