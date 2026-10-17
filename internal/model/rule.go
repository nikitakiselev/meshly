package model

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Proto is an application protocol an access rule may allow.
type Proto string

const (
	ProtoTCP Proto = "tcp"
	ProtoUDP Proto = "udp"
	// ProtoPing allows ICMP echo requests (and their replies) only.
	ProtoPing Proto = "ping"
)

// Rule allows a peer to initiate connections to a local service on this
// node's VPN address. Rules are only ever evaluated on the receiving node.
type Rule struct {
	Peer  string `json:"peer"`
	Proto Proto  `json:"proto"`
	Port  uint16 `json:"port,omitempty"`
}

// Validate checks a rule in isolation.
func (r Rule) Validate() error {
	if err := ValidateName(r.Peer); err != nil {
		return fmt.Errorf("peer: %w", err)
	}
	switch r.Proto {
	case ProtoTCP, ProtoUDP:
		return ValidatePort(int(r.Port))
	case ProtoPing:
		if r.Port != 0 {
			return errors.New("ping rules have no port")
		}
		return nil
	default:
		return fmt.Errorf("unsupported protocol %q (supported: tcp, udp, ping)", truncate(string(r.Proto)))
	}
}

// Service renders the service part of the rule ("9100/tcp" or "ping").
func (r Rule) Service() string {
	if r.Proto == ProtoPing {
		return "ping"
	}
	return fmt.Sprintf("%d/%s", r.Port, r.Proto)
}

// String renders the rule in CLI syntax.
func (r Rule) String() string { return r.Service() + " from " + r.Peer }

// ParseRule parses CLI arguments of the form
//
//	<port>/<tcp|udp> from <peer>
//	ping from <peer>
func ParseRule(args []string) (Rule, error) {
	if len(args) != 3 || args[1] != "from" {
		return Rule{}, errors.New("expected <port>/<tcp|udp> from <peer>  (or: ping from <peer>)")
	}
	r := Rule{Peer: args[2]}
	svc := args[0]
	if svc == "ping" {
		r.Proto = ProtoPing
	} else {
		port, proto, ok := strings.Cut(svc, "/")
		if !ok {
			return Rule{}, fmt.Errorf("invalid service %q: expected <port>/<tcp|udp>, e.g. 9100/tcp", truncate(svc))
		}
		p, err := ParsePort(port)
		if err != nil {
			return Rule{}, err
		}
		r.Port = p
		switch Proto(proto) {
		case ProtoTCP, ProtoUDP:
			r.Proto = Proto(proto)
		default:
			return Rule{}, fmt.Errorf("unsupported protocol %q: only tcp and udp (or ping) are supported", truncate(proto))
		}
	}
	if err := r.Validate(); err != nil {
		return Rule{}, err
	}
	return r, nil
}

// SortRules orders rules deterministically (peer, proto, port).
func SortRules(rs []Rule) {
	slices.SortFunc(rs, func(a, b Rule) int {
		if c := strings.Compare(a.Peer, b.Peer); c != 0 {
			return c
		}
		if c := strings.Compare(string(a.Proto), string(b.Proto)); c != 0 {
			return c
		}
		return int(a.Port) - int(b.Port)
	})
}
