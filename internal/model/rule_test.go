package model

import (
	"slices"
	"strings"
	"testing"
)

func TestParseRule(t *testing.T) {
	tests := []struct {
		in      string
		want    Rule
		wantErr string
	}{
		{in: "22/tcp from home", want: Rule{Peer: "home", Proto: ProtoTCP, Port: 22}},
		{in: "53/udp from home", want: Rule{Peer: "home", Proto: ProtoUDP, Port: 53}},
		{in: "1/tcp from a", want: Rule{Peer: "a", Proto: ProtoTCP, Port: 1}},
		{in: "65535/udp from node-2", want: Rule{Peer: "node-2", Proto: ProtoUDP, Port: 65535}},
		{in: "ping from home", want: Rule{Peer: "home", Proto: ProtoPing}},

		// shape
		{in: "", wantErr: "expected <port>/<tcp|udp> from <peer>"},
		{in: "22/tcp", wantErr: "expected"},
		{in: "22/tcp from", wantErr: "expected"},
		{in: "22/tcp to home", wantErr: "expected"},
		{in: "22/tcp FROM home", wantErr: "expected"},
		{in: "22/tcp from home extra", wantErr: "expected"},
		{in: "22 tcp from home", wantErr: "expected"},
		{in: "22 from home", wantErr: "invalid service"},
		{in: "ssh from home", wantErr: "invalid service"},

		// ports
		{in: "0/tcp from home", wantErr: "out of range"},
		{in: "65536/tcp from home", wantErr: "out of range"},
		{in: "99999/udp from home", wantErr: "out of range"},
		{in: "022/tcp from home", wantErr: "invalid port"},
		{in: "00/tcp from home", wantErr: "invalid port"},
		{in: "-1/tcp from home", wantErr: "invalid port"},
		{in: "+22/tcp from home", wantErr: "invalid port"},
		{in: "/tcp from home", wantErr: "invalid port"},
		{in: "1000000/tcp from home", wantErr: "invalid port"},
		{in: "ping/tcp from home", wantErr: "invalid port"},

		// protocols
		{in: "22/icmp from home", wantErr: "unsupported protocol"},
		{in: "22/TCP from home", wantErr: "unsupported protocol"},
		{in: "22/ from home", wantErr: "unsupported protocol"},
		{in: "22/tcp/udp from home", wantErr: "unsupported protocol"},
		{in: "22/sctp from home", wantErr: "unsupported protocol"},
		{in: "PING from home", wantErr: "invalid service"},
		{in: "ping/icmp from home", wantErr: "invalid port"},

		// peer names, including reserved words
		{in: "22/tcp from from", wantErr: "reserved"},
		{in: "22/tcp from all", wantErr: "reserved"},
		{in: "22/tcp from any", wantErr: "reserved"},
		{in: "ping from ping", wantErr: "reserved"},
		{in: "ping from self", wantErr: "reserved"},
		{in: "22/tcp from local", wantErr: "reserved"},
		{in: "22/tcp from none", wantErr: "reserved"},
		{in: "22/tcp from default", wantErr: "reserved"},
		{in: "22/tcp from Home", wantErr: "invalid name"},
		{in: "22/tcp from 1home", wantErr: "invalid name"},
		{in: "22/tcp from home_lab", wantErr: "invalid name"},
	}
	for _, tt := range tests {
		got, err := ParseRule(strings.Fields(tt.in))
		if tt.wantErr == "" {
			if err != nil {
				t.Errorf("ParseRule(%q) = %v", tt.in, err)
				continue
			}
			if got != tt.want {
				t.Errorf("ParseRule(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
			if got.String() != tt.in {
				t.Errorf("ParseRule(%q).String() = %q", tt.in, got.String())
			}
			continue
		}
		if err == nil {
			t.Errorf("ParseRule(%q) = %+v, want error containing %q", tt.in, got, tt.wantErr)
			continue
		}
		if !strings.Contains(err.Error(), tt.wantErr) {
			t.Errorf("ParseRule(%q) = %v, want error containing %q", tt.in, err, tt.wantErr)
		}
		if got != (Rule{}) {
			t.Errorf("ParseRule(%q) returned non-zero rule %+v with an error", tt.in, got)
		}
	}
}

func TestParseRuleEmptyArgs(t *testing.T) {
	for _, args := range [][]string{nil, {}, {"", "from", ""}, {"22/tcp", "from", ""}} {
		if _, err := ParseRule(args); err == nil {
			t.Errorf("ParseRule(%q) succeeded", args)
		}
	}
}

func TestRuleValidate(t *testing.T) {
	tests := []struct {
		r       Rule
		wantErr string
	}{
		{Rule{Peer: "home", Proto: ProtoTCP, Port: 22}, ""},
		{Rule{Peer: "home", Proto: ProtoUDP, Port: 65535}, ""},
		{Rule{Peer: "home", Proto: ProtoPing}, ""},
		{Rule{Peer: "home", Proto: ProtoTCP}, "out of range"},
		{Rule{Peer: "home", Proto: ProtoUDP, Port: 0}, "out of range"},
		{Rule{Peer: "home", Proto: ProtoPing, Port: 7}, "ping rules have no port"},
		{Rule{Peer: "home", Proto: "icmp", Port: 7}, "unsupported protocol"},
		{Rule{Peer: "home", Proto: "", Port: 7}, "unsupported protocol"},
		{Rule{Peer: "home", Proto: "TCP", Port: 7}, "unsupported protocol"},
		{Rule{Peer: "", Proto: ProtoTCP, Port: 22}, "peer:"},
		{Rule{Peer: "from", Proto: ProtoTCP, Port: 22}, "reserved"},
	}
	for _, tt := range tests {
		err := tt.r.Validate()
		if tt.wantErr == "" {
			if err != nil {
				t.Errorf("%+v.Validate() = %v", tt.r, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
			t.Errorf("%+v.Validate() = %v, want error containing %q", tt.r, err, tt.wantErr)
		}
	}

	// A huge protocol string is truncated in the error.
	long := Proto(strings.Repeat("p", 1000))
	err := Rule{Peer: "home", Proto: long, Port: 1}.Validate()
	if err == nil || strings.Contains(err.Error(), string(long)) {
		t.Errorf("long protocol echoed in full: %v", err)
	}
}

func TestRuleServiceString(t *testing.T) {
	tests := []struct {
		r             Rule
		svc, rendered string
	}{
		{Rule{Peer: "home", Proto: ProtoTCP, Port: 9100}, "9100/tcp", "9100/tcp from home"},
		{Rule{Peer: "b", Proto: ProtoUDP, Port: 53}, "53/udp", "53/udp from b"},
		{Rule{Peer: "home", Proto: ProtoPing}, "ping", "ping from home"},
	}
	for _, tt := range tests {
		if got := tt.r.Service(); got != tt.svc {
			t.Errorf("Service() = %q, want %q", got, tt.svc)
		}
		if got := tt.r.String(); got != tt.rendered {
			t.Errorf("String() = %q, want %q", got, tt.rendered)
		}
	}
}

func TestSortRules(t *testing.T) {
	rs := []Rule{
		{Peer: "zulu", Proto: ProtoTCP, Port: 22},
		{Peer: "alpha", Proto: ProtoUDP, Port: 53},
		{Peer: "alpha", Proto: ProtoTCP, Port: 9100},
		{Peer: "alpha", Proto: ProtoPing},
		{Peer: "alpha", Proto: ProtoTCP, Port: 22},
		{Peer: "alpha", Proto: ProtoTCP, Port: 65535},
	}
	want := []Rule{
		{Peer: "alpha", Proto: ProtoPing},
		{Peer: "alpha", Proto: ProtoTCP, Port: 22},
		{Peer: "alpha", Proto: ProtoTCP, Port: 9100},
		{Peer: "alpha", Proto: ProtoTCP, Port: 65535},
		{Peer: "alpha", Proto: ProtoUDP, Port: 53},
		{Peer: "zulu", Proto: ProtoTCP, Port: 22},
	}
	SortRules(rs)
	if !slices.Equal(rs, want) {
		t.Errorf("SortRules = %v\nwant %v", rs, want)
	}
	SortRules(nil) // must not panic
}
