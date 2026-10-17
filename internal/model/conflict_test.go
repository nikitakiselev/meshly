package model

import (
	"net/netip"
	"testing"
)

func used(pairs ...string) []UsedPrefix {
	var out []UsedPrefix
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, UsedPrefix{Prefix: netip.MustParsePrefix(pairs[i]), Source: pairs[i+1]})
	}
	return out
}

func TestFindConflicts(t *testing.T) {
	cidr := netip.MustParsePrefix("10.100.0.0/24")
	tests := []struct {
		name string
		used []UsedPrefix
		want []Conflict
	}{
		{"nothing", nil, nil},
		{"address inside", used("10.100.0.5/32", "address on eth0"),
			[]Conflict{{netip.MustParsePrefix("10.100.0.5/32"), "address on eth0"}}},
		{"wider route", used("10.0.0.0/8", "route via eth1"),
			[]Conflict{{netip.MustParsePrefix("10.0.0.0/8"), "route via eth1"}}},
		{"narrower route", used("10.100.0.128/25", "route via docker0"),
			[]Conflict{{netip.MustParsePrefix("10.100.0.128/25"), "route via docker0"}}},
		{"host bits are masked", used("10.100.0.77/16", "address on eth0"),
			[]Conflict{{netip.MustParsePrefix("10.100.0.0/16"), "address on eth0"}}},
		{"adjacent networks", used("10.99.255.0/24", "a", "10.101.0.0/24", "b"), nil},
		{"default route ignored", used("0.0.0.0/0", "default via eth0"), nil},
		{"ipv6 ignored", used("fd00::/8", "ipv6", "::/0", "v6 default"), nil},
		{"invalid ignored", []UsedPrefix{{Source: "zero"}}, nil},
		{"several", used("10.100.0.0/24", "a", "192.168.1.0/24", "b", "10.100.0.1/32", "c"),
			[]Conflict{{netip.MustParsePrefix("10.100.0.0/24"), "a"}, {netip.MustParsePrefix("10.100.0.1/32"), "c"}}},
	}
	for _, tt := range tests {
		got := FindConflicts(cidr, tt.used)
		if len(got) != len(tt.want) {
			t.Errorf("%s: FindConflicts = %v, want %v", tt.name, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("%s: [%d] = %v, want %v", tt.name, i, got[i], tt.want[i])
			}
		}
	}
}

func TestFindConflictsMappedPrefix(t *testing.T) {
	// FindConflicts unmaps the address but keeps the IPv6 prefix length,
	// so an IPv4-mapped prefix (::ffff:10.100.0.0/120 == 10.100.0.0/24)
	// becomes an invalid prefix and is silently ignored.
	cidr := netip.MustParsePrefix("10.100.0.0/24")
	if got := FindConflicts(cidr, used("::ffff:10.100.0.0/120", "mapped")); len(got) == 0 {
		knownBug(t, "IPv4-mapped prefix overlapping %s is not reported", cidr)
	}
}

func TestConflictString(t *testing.T) {
	c := Conflict{Prefix: netip.MustParsePrefix("10.100.0.0/24"), Source: "route via eth0"}
	if got := c.String(); got != "10.100.0.0/24 (route via eth0)" {
		t.Errorf("String() = %q", got)
	}
}

func TestSuggestCIDR(t *testing.T) {
	tests := []struct {
		name string
		used []UsedPrefix
		want string // "" means no suggestion
	}{
		{"empty system", nil, "10.100.0.0/24"},
		{"default taken", used("10.100.0.0/24", "a"), "10.101.0.0/24"},
		{"several taken", used("10.100.0.0/16", "a", "10.101.0.9/32", "b"), "10.102.0.0/24"},
		{"default route does not matter", used("0.0.0.0/0", "default"), "10.100.0.0/24"},
		{"all of 10/8", used("10.0.0.0/8", "corp"), "172.16.200.0/24"},
		{"10/8 and part of 172.16/12", used("10.0.0.0/8", "a", "172.16.0.0/14", "b"), "172.20.200.0/24"},
		{"everything", used("10.0.0.0/8", "a", "172.16.0.0/12", "b"), ""},
	}
	for _, tt := range tests {
		got, ok := SuggestCIDR(tt.used)
		if tt.want == "" {
			if ok {
				t.Errorf("%s: SuggestCIDR = %s, want none", tt.name, got)
			}
			continue
		}
		if !ok || got.String() != tt.want {
			t.Errorf("%s: SuggestCIDR = %s, %v; want %s", tt.name, got, ok, tt.want)
			continue
		}
		if err := ValidateCIDR(got); err != nil {
			t.Errorf("%s: suggestion %s does not validate: %v", tt.name, got, err)
		}
		if cs := FindConflicts(got, tt.used); len(cs) != 0 {
			t.Errorf("%s: suggestion %s conflicts: %v", tt.name, got, cs)
		}
	}
}
