package model

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func validConfig() *Config {
	t0 := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	return &Config{
		SchemaVersion: ConfigSchemaVersion,
		Revision:      3,
		UpdatedAt:     t0,
		AdminState:    AdminUp,
		Network:       Network{ID: strings.Repeat("ab", 16), Name: "homelab", CIDR: netip.MustParsePrefix("10.100.0.0/24")},
		Self: Self{
			Name: "alpha", Address: netip.MustParseAddr("10.100.0.1"), ListenPort: DefaultListenPort,
			Endpoint:    netip.MustParseAddrPort("203.0.113.10:51820"),
			WGPublicKey: b64(1, 32),
		},
		Interface: Interface{Name: DefaultInterface, MTU: DefaultMTU},
		Firewall:  Firewall{Profile: ProfileNftables, Mark: DefaultFirewallMark},
		Peers: []Peer{{
			Name: "beta", Address: netip.MustParseAddr("10.100.0.2"),
			WGPublicKey: b64(3, 32),
			Endpoint:    netip.MustParseAddrPort("198.51.100.20:51820"),
			Keepalive:   DefaultKeepalive, AddedAt: t0,
		}},
		Rules: []Rule{
			{Peer: "beta", Proto: ProtoTCP, Port: 22},
			{Peer: "beta", Proto: ProtoPing},
		},
	}
}

// gamma is a third node, 10.100.0.3, changed by mutate when it is not nil.
func gamma(mutate func(p *Peer)) Peer {
	p := Peer{Name: "gamma", Address: netip.MustParseAddr("10.100.0.3"), WGPublicKey: b64(5, 32), Keepalive: DefaultKeepalive}
	if mutate != nil {
		mutate(&p)
	}
	return p
}

func TestConfigValidateValid(t *testing.T) {
	variants := map[string]func(c *Config){
		"full":               func(*Config) {},
		"down":               func(c *Config) { c.AdminState = AdminDown },
		"no peers, no rules": func(c *Config) { c.Peers, c.Rules = nil, nil },
		"no endpoints":       func(c *Config) { c.Self.Endpoint, c.Peers[0].Endpoint = netip.AddrPort{}, netip.AddrPort{} },
		"ipv6 endpoint":      func(c *Config) { c.Peers[0].Endpoint = netip.MustParseAddrPort("[2001:db8::7]:51820") },
		"profile none":       func(c *Config) { c.Firewall.Profile = ProfileNone },
		"keepalive disabled": func(c *Config) { c.Peers[0].Keepalive = 0 },
		"/30 network":        func(c *Config) { c.Network.CIDR = netip.MustParsePrefix("10.100.0.0/30") },
		"lowest mark bit":    func(c *Config) { c.Firewall.Mark = 1 },
		"same port both ways": func(c *Config) {
			c.Rules = []Rule{{Peer: "beta", Proto: ProtoTCP, Port: 53}, {Peer: "beta", Proto: ProtoUDP, Port: 53}}
		},
		"several peers": func(c *Config) {
			c.Peers = append(c.Peers, gamma(nil))
			c.Rules = append(c.Rules, Rule{Peer: "gamma", Proto: ProtoTCP, Port: 22})
		},
	}
	for name, mutate := range variants {
		c := validConfig()
		mutate(c)
		if err := c.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestConfigValidateInvalid(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(c *Config)
		wantErr string
	}{
		{"schema 0", func(c *Config) { c.SchemaVersion = 0 }, "unsupported config schema_version 0"},
		{"schema 2", func(c *Config) { c.SchemaVersion = 2 }, "unsupported config schema_version 2"},
		{"admin state", func(c *Config) { c.AdminState = "sideways" }, "admin_state"},
		{"admin state empty", func(c *Config) { c.AdminState = "" }, "admin_state"},
		{"network id", func(c *Config) { c.Network.ID = "XYZ" }, "network.id"},
		{"network name", func(c *Config) { c.Network.Name = "all" }, "network.name"},
		{"public cidr", func(c *Config) { c.Network.CIDR = netip.MustParsePrefix("8.8.8.0/24") }, "network.cidr"},
		{"zero cidr", func(c *Config) { c.Network.CIDR = netip.Prefix{} }, "network.cidr"},
		{"self name", func(c *Config) { c.Self.Name = "Alpha" }, "self.name"},
		{"self address outside", func(c *Config) { c.Self.Address = netip.MustParseAddr("10.200.0.1") }, "self.address"},
		{"self address network", func(c *Config) { c.Self.Address = netip.MustParseAddr("10.100.0.0") }, "self.address"},
		{"self address broadcast", func(c *Config) { c.Self.Address = netip.MustParseAddr("10.100.0.255") }, "self.address"},
		{"self address missing", func(c *Config) { c.Self.Address = netip.Addr{} }, "self.address"},
		{"listen port 0", func(c *Config) { c.Self.ListenPort = 0 }, "self.listen_port"},
		{"self endpoint unspecified", func(c *Config) { c.Self.Endpoint = netip.MustParseAddrPort("0.0.0.0:51820") }, "self.endpoint"},
		{"self endpoint port 0", func(c *Config) { c.Self.Endpoint = netip.MustParseAddrPort("203.0.113.10:0") }, "self.endpoint"},
		{"self wg key", func(c *Config) { c.Self.WGPublicKey = "short" }, "self.wg_public_key"},
		{"self wg key zero", func(c *Config) { c.Self.WGPublicKey = b64(0, 32) }, "self.wg_public_key"},
		{"interface lo", func(c *Config) { c.Interface.Name = "lo" }, "interface.name"},
		{"interface long", func(c *Config) { c.Interface.Name = "meshlyinterface0" }, "interface.name"},
		{"mtu", func(c *Config) { c.Interface.MTU = 9000 }, "interface.mtu"},
		{"profile", func(c *Config) { c.Firewall.Profile = "iptables" }, "firewall.profile"},
		{"profile empty", func(c *Config) { c.Firewall.Profile = "" }, "firewall.profile"},
		{"mark zero", func(c *Config) { c.Firewall.Mark = 0 }, "firewall.mark"},
		{"mark two bits", func(c *Config) { c.Firewall.Mark = 0x30000000 }, "firewall.mark"},
		{"peer name equals another peer", func(c *Config) { c.Peers = append(c.Peers, gamma(func(p *Peer) { p.Name = "beta" })) }, `peers[1].name "beta" is not unique`},
		{"peer address equals another peer", func(c *Config) {
			c.Peers = append(c.Peers, gamma(func(p *Peer) { p.Address = netip.MustParseAddr("10.100.0.2") }))
		}, "peers[1].address 10.100.0.2 is not unique"},
		{"peer wg key equals another peer", func(c *Config) { c.Peers = append(c.Peers, gamma(func(p *Peer) { p.WGPublicKey = b64(3, 32) })) }, "peers[1].wg_public_key is not unique"},
		{"peer name invalid", func(c *Config) { c.Peers[0].Name = "-x" }, "peers[0].name"},
		{"peer name equals self", func(c *Config) { c.Peers[0].Name = "alpha"; c.Rules = nil }, `peers[0].name "alpha" is not unique`},
		{"peer address equals self", func(c *Config) { c.Peers[0].Address = c.Self.Address }, "peers[0].address 10.100.0.1 is not unique"},
		{"peer address outside", func(c *Config) { c.Peers[0].Address = netip.MustParseAddr("192.168.0.2") }, "peers[0].address"},
		{"peer wg key equals self", func(c *Config) { c.Peers[0].WGPublicKey = c.Self.WGPublicKey }, "peers[0].wg_public_key is not unique"},
		{"peer wg key invalid", func(c *Config) { c.Peers[0].WGPublicKey = b64(3, 16) }, "peers[0].wg_public_key"},
		{"peer endpoint multicast", func(c *Config) { c.Peers[0].Endpoint = netip.MustParseAddrPort("239.1.1.1:51820") }, "peers[0].endpoint"},
		{"peer endpoint link-local", func(c *Config) { c.Peers[0].Endpoint = netip.MustParseAddrPort("[fe80::1]:51820") }, "peers[0].endpoint"},
		{"peer keepalive negative", func(c *Config) { c.Peers[0].Keepalive = -1 }, "peers[0].keepalive"},
		{"peer keepalive huge", func(c *Config) { c.Peers[0].Keepalive = 86400 }, "peers[0].keepalive"},
		{"rule unknown peer", func(c *Config) { c.Rules = append(c.Rules, Rule{Peer: "gamma", Proto: ProtoTCP, Port: 80}) }, `rules[2] references unknown peer "gamma"`},
		{"rule for self", func(c *Config) { c.Rules = []Rule{{Peer: "alpha", Proto: ProtoTCP, Port: 80}} }, "unknown peer"},
		{"rule duplicate", func(c *Config) { c.Rules = append(c.Rules, Rule{Peer: "beta", Proto: ProtoTCP, Port: 22}) }, `rules[2] duplicates "22/tcp from beta"`},
		{"rule invalid", func(c *Config) { c.Rules[1].Port = 1 }, "rules[1]: ping rules have no port"},
		{"rule no port", func(c *Config) { c.Rules[0].Port = 0 }, "rules[0]"},
		{"rule bad proto", func(c *Config) { c.Rules[0].Proto = "gre" }, "rules[0]"},
	}
	for _, tt := range tests {
		c := validConfig()
		tt.mutate(c)
		err := c.Validate()
		if err == nil {
			t.Errorf("%s: config accepted", tt.name)
			continue
		}
		if !strings.Contains(err.Error(), tt.wantErr) {
			t.Errorf("%s: error %q does not contain %q", tt.name, err, tt.wantErr)
		}
	}
}

func TestConfigValidateCollectsAllErrors(t *testing.T) {
	c := validConfig()
	c.Interface.MTU = 1
	c.Firewall.Mark = 0
	c.Self.ListenPort = 0
	err := c.Validate()
	if err == nil {
		t.Fatal("accepted")
	}
	for _, want := range []string{"interface.mtu", "firewall.mark", "self.listen_port"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
}

func TestConfigValidateZero(t *testing.T) {
	if err := (&Config{}).Validate(); err == nil {
		t.Error("zero config accepted")
	}
	if err := (&Config{SchemaVersion: ConfigSchemaVersion}).Validate(); err == nil {
		t.Error("empty v1 config accepted")
	}
}

func TestConfigClone(t *testing.T) {
	var nilCfg *Config
	if nilCfg.Clone() != nil {
		t.Error("nil.Clone() != nil")
	}
	c := validConfig()
	d := c.Clone()
	if d == c {
		t.Fatal("Clone returned the same pointer")
	}
	d.Peers[0].Name = "changed"
	d.Rules[0].Port = 2222
	d.Network.Name = "other"
	d.Peers = append(d.Peers, Peer{Name: "x"})
	if c.Peers[0].Name != "beta" || c.Rules[0].Port != 22 || c.Network.Name != "homelab" || len(c.Peers) != 1 {
		t.Errorf("Clone shares state with the original: %+v", c)
	}
}

func TestConfigPeerAndRulesFor(t *testing.T) {
	c := validConfig()
	p, ok := c.Peer("beta")
	if !ok || p.Name != "beta" {
		t.Fatalf("Peer(beta) = %v, %v", p, ok)
	}
	p.Keepalive = 99 // returned pointer refers into the slice
	if c.Peers[0].Keepalive != 99 {
		t.Error("Peer() does not return a pointer into the config")
	}
	if _, ok := c.Peer("alpha"); ok {
		t.Error("self found as a peer")
	}
	if _, ok := c.Peer(""); ok {
		t.Error("empty name found")
	}
	if got := c.RulesFor("beta"); len(got) != 2 {
		t.Errorf("RulesFor(beta) = %v", got)
	}
	if got := c.RulesFor("nobody"); got != nil {
		t.Errorf("RulesFor(nobody) = %v", got)
	}
}
