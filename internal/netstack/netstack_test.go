package netstack

import (
	"net/netip"
	"slices"
	"testing"
)

func TestIsDockerBridge(t *testing.T) {
	for name, want := range map[string]bool{
		"docker0": true, "br-3f1c2a9b7d01": true,
		"br-lan": false, "br0": false, "vmbr0": false, "virbr0": false, "lxdbr0": false, "podman0": false,
		"br-3f1c2a9b7d0": false, "br-3f1c2a9b7d012": false, "br-3F1C2A9B7D01": false, "docker1": false,
	} {
		if got := IsDockerBridge(name, "bridge"); got != want {
			t.Errorf("IsDockerBridge(%q, bridge) = %v, want %v", name, got, want)
		}
	}
	if IsDockerBridge("docker0", "veth") || IsDockerBridge("br-3f1c2a9b7d01", "dummy") {
		t.Error("a non-bridge with a Docker name counts as a Docker bridge")
	}
}

func TestWantDockerRouting(t *testing.T) {
	if !WantDockerRouting("meshly0", nil).Empty() {
		t.Fatal("no bridges must mean no routing")
	}
	got := WantDockerRouting("meshly0", []Bridge{
		{Name: "docker0", Prefixes: []netip.Prefix{netip.MustParsePrefix("172.17.0.0/16")}},
		{Name: "br-3f1c2a9b7d01", Prefixes: []netip.Prefix{netip.MustParsePrefix("172.18.0.0/16"), netip.MustParsePrefix("172.19.0.0/24")}},
		{Name: "br-000000000001"}, // no IPv4: in the set, no route
	})
	want := DockerRouting{
		Rules: []PolicyRule{{Iif: "meshly0", Table: 109, Priority: 109}},
		Routes: []TableRoute{
			{Dst: netip.MustParsePrefix("172.17.0.0/16"), Dev: "docker0"},
			{Dst: netip.MustParsePrefix("172.18.0.0/16"), Dev: "br-3f1c2a9b7d01"},
			{Dst: netip.MustParsePrefix("172.19.0.0/24"), Dev: "br-3f1c2a9b7d01"},
			{Dst: netip.MustParsePrefix("0.0.0.0/0")},
		},
	}
	if !got.Equal(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestDockerRoutingEqual(t *testing.T) {
	a := DockerRouting{
		Rules: []PolicyRule{{Iif: "meshly0", Table: 109, Priority: 109}},
		Routes: []TableRoute{
			{Dst: netip.MustParsePrefix("172.17.0.0/16"), Dev: "docker0"},
			{Dst: netip.MustParsePrefix("0.0.0.0/0")},
		},
	}
	b := DockerRouting{
		Rules: a.Rules,
		Routes: []TableRoute{
			{Dst: netip.MustParsePrefix("0.0.0.0/0")},
			{Dst: netip.MustParsePrefix("172.17.0.0/16"), Dev: "docker0"},
		},
		Foreign: 3,
	}
	if !a.Equal(b) || !b.Equal(a) {
		t.Error("order and Foreign must not matter")
	}
	extra := b
	extra.Routes = append([]TableRoute{{Dst: netip.MustParsePrefix("172.18.0.0/16"), Dev: "docker0"}}, b.Routes...)
	if a.Equal(extra) || extra.Equal(a) {
		t.Error("an extra route must differ")
	}
	iif := b
	iif.Rules = []PolicyRule{{Iif: "other0", Table: 109, Priority: 109}}
	if a.Equal(iif) {
		t.Error("a different Iif must differ")
	}
}

// Only bridges that are up are served, each subnet with the first bridge
// (by name) that has it; routes of another program in RouteTable leave none.
func TestServedBridges(t *testing.T) {
	p17, p18 := netip.MustParsePrefix("172.17.0.0/16"), netip.MustParsePrefix("172.18.0.0/16")
	bridges := []Bridge{
		{Name: "br-000000000001", Prefixes: []netip.Prefix{p17, p18}},
		{Name: "br-000000000002", Prefixes: []netip.Prefix{netip.MustParsePrefix("172.20.0.0/16")}, Down: true},
		{Name: "docker0", Prefixes: []netip.Prefix{p17}},
	}
	want := []Bridge{
		{Name: "br-000000000001", Prefixes: []netip.Prefix{p17, p18}},
		{Name: "docker0"},
	}
	got := ServedBridges(bridges, 0)
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i].Name != want[i].Name || !slices.Equal(got[i].Prefixes, want[i].Prefixes) || got[i].Down {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	}
	if !slices.Equal(bridges[2].Prefixes, []netip.Prefix{p17}) {
		t.Fatalf("input changed: %+v", bridges)
	}
	if got := ServedBridges(bridges, 1); got != nil {
		t.Fatalf("with foreign routes: %+v", got)
	}
	if got := ServedBridges(nil, 0); got != nil {
		t.Fatalf("without bridges: %+v", got)
	}
}
