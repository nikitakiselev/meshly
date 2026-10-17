package nft

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Ruleset is the parsed output of `nft -j list ruleset`.
type Ruleset struct {
	Version    string
	Tables     []Table
	Chains     []Chain
	Rules      []Rule
	Sets       []Set
	Flowtables []Flowtable
	objects    []object
}

type object struct {
	kind   string
	family string
	table  string
	raw    json.RawMessage
}

// Table is an nftables table.
type Table struct {
	Family  string `json:"family"`
	Name    string `json:"name"`
	Comment string `json:"comment"`
}

// Chain is an nftables chain; Hook is empty for regular chains.
type Chain struct {
	Family string          `json:"family"`
	Table  string          `json:"table"`
	Name   string          `json:"name"`
	Type   string          `json:"type"`
	Hook   string          `json:"hook"`
	Prio   json.RawMessage `json:"prio"`
	Policy string          `json:"policy"`
	Dev    json.RawMessage `json:"dev"`
}

// IsBase reports whether the chain is attached to a hook.
func (c Chain) IsBase() bool { return c.Hook != "" }

// Priority returns the numeric priority of a base chain.
func (c Chain) Priority() int {
	var n int
	if err := json.Unmarshal(c.Prio, &n); err == nil {
		return n
	}
	var s string
	if err := json.Unmarshal(c.Prio, &s); err == nil {
		return namedPriority(s, c.Family, c.Hook)
	}
	return 0
}

func namedPriority(s, family, hook string) int {
	base, off := s, 0
	if i := strings.IndexAny(s, "+-"); i > 0 {
		base = strings.TrimSpace(s[:i])
		fmt.Sscanf(strings.ReplaceAll(s[i:], " ", ""), "%d", &off)
	}
	switch base {
	case "raw":
		return -300 + off
	case "mangle":
		return -150 + off
	case "dstnat":
		return -100 + off
	case "filter":
		return 0 + off
	case "security":
		return 50 + off
	case "srcnat":
		return 100 + off
	}
	return off
}

// Rule is an nftables rule with raw expressions.
type Rule struct {
	Family  string            `json:"family"`
	Table   string            `json:"table"`
	Chain   string            `json:"chain"`
	Handle  int               `json:"handle"`
	Comment string            `json:"comment"`
	Expr    []json.RawMessage `json:"expr"`
}

// Set is a named set.
type Set struct {
	Family string            `json:"family"`
	Table  string            `json:"table"`
	Name   string            `json:"name"`
	Type   json.RawMessage   `json:"type"`
	Elem   []json.RawMessage `json:"elem"`
}

// Flowtable is a flow offload table.
type Flowtable struct {
	Family string          `json:"family"`
	Table  string          `json:"table"`
	Name   string          `json:"name"`
	Dev    json.RawMessage `json:"dev"`
}

// Devices returns the flowtable devices.
func (f Flowtable) Devices() []string { return stringOrList(f.Dev) }

func stringOrList(raw json.RawMessage) []string {
	var one string
	if json.Unmarshal(raw, &one) == nil && one != "" {
		return []string{one}
	}
	var many []string
	_ = json.Unmarshal(raw, &many)
	return many
}

const maxRulesetSize = 64 << 20

// ParseRuleset parses `nft -j list ruleset` output.
func ParseRuleset(b []byte) (*Ruleset, error) {
	if len(b) > maxRulesetSize {
		return nil, errors.New("ruleset JSON too large")
	}
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("parse nft JSON: %w", err)
	}
	rs := &Ruleset{}
	for _, o := range doc.Nftables {
		for kind, raw := range o {
			var hdr struct {
				Family string `json:"family"`
				Table  string `json:"table"`
				Name   string `json:"name"`
				Ver    string `json:"version"`
			}
			_ = json.Unmarshal(raw, &hdr)
			table := hdr.Table
			if kind == "table" {
				table = hdr.Name
			}
			switch kind {
			case "metainfo":
				rs.Version = hdr.Ver
				continue
			case "table":
				var t Table
				if err := json.Unmarshal(raw, &t); err != nil {
					return nil, fmt.Errorf("parse table: %w", err)
				}
				rs.Tables = append(rs.Tables, t)
			case "chain":
				var c Chain
				if err := json.Unmarshal(raw, &c); err != nil {
					return nil, fmt.Errorf("parse chain: %w", err)
				}
				rs.Chains = append(rs.Chains, c)
			case "rule":
				var r Rule
				if err := json.Unmarshal(raw, &r); err != nil {
					return nil, fmt.Errorf("parse rule: %w", err)
				}
				rs.Rules = append(rs.Rules, r)
			case "set", "map":
				var s Set
				if err := json.Unmarshal(raw, &s); err != nil {
					return nil, fmt.Errorf("parse set: %w", err)
				}
				rs.Sets = append(rs.Sets, s)
			case "flowtable":
				var f Flowtable
				if err := json.Unmarshal(raw, &f); err != nil {
					return nil, fmt.Errorf("parse flowtable: %w", err)
				}
				rs.Flowtables = append(rs.Flowtables, f)
			}
			rs.objects = append(rs.objects, object{kind: kind, family: hdr.Family, table: table, raw: raw})
		}
	}
	return rs, nil
}

// Table returns the subset of objects belonging to one table, or nil if
// the table does not exist.
func (rs *Ruleset) Table(family, name string) *Ruleset {
	found := false
	out := &Ruleset{Version: rs.Version}
	for _, t := range rs.Tables {
		if t.Family == family && t.Name == name {
			out.Tables = append(out.Tables, t)
			found = true
		}
	}
	if !found {
		return nil
	}
	for _, c := range rs.Chains {
		if c.Family == family && c.Table == name {
			out.Chains = append(out.Chains, c)
		}
	}
	for _, r := range rs.Rules {
		if r.Family == family && r.Table == name {
			out.Rules = append(out.Rules, r)
		}
	}
	for _, s := range rs.Sets {
		if s.Family == family && s.Table == name {
			out.Sets = append(out.Sets, s)
		}
	}
	for _, o := range rs.objects {
		if o.family == family && o.table == name {
			out.objects = append(out.objects, o)
		}
	}
	return out
}

// ChainRules returns the rules of a chain in evaluation order.
func (rs *Ruleset) ChainRules(family, table, chain string) []Rule {
	var out []Rule
	for _, r := range rs.Rules {
		if r.Family == family && r.Table == table && r.Chain == chain {
			out = append(out, r)
		}
	}
	return out
}

// Chain looks up a chain.
func (rs *Ruleset) Chain(family, table, name string) (Chain, bool) {
	for _, c := range rs.Chains {
		if c.Family == family && c.Table == table && c.Name == name {
			return c, true
		}
	}
	return Chain{}, false
}

// Marker returns the ownership marker comment of the Meshly table.
func (rs *Ruleset) Marker() (network, hash string, ok bool) {
	for _, r := range rs.ChainRules(TableFamily, TableName, "guard_pre") {
		if !strings.HasPrefix(r.Comment, MarkerPrefix+" ") {
			continue
		}
		for _, f := range strings.Fields(strings.TrimPrefix(r.Comment, MarkerPrefix+" ")) {
			k, v, _ := strings.Cut(f, "=")
			switch k {
			case "net":
				network = v
			case "hash":
				hash = v
			}
		}
		return network, hash, true
	}
	return "", "", false
}

// ContentHash is a stable hash of the objects with handles removed and
// counters zeroed, used to detect external modification of the table.
func (rs *Ruleset) ContentHash() string {
	h := sha256.New()
	for _, o := range rs.objects {
		var v any
		if err := json.Unmarshal(o.raw, &v); err != nil {
			continue
		}
		v = normalize(v)
		b, _ := json.Marshal(map[string]any{o.kind: v})
		h.Write(b)
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

func normalize(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			if k == "handle" {
				continue
			}
			if k == "counter" {
				out[k] = map[string]any{"packets": 0, "bytes": 0}
				continue
			}
			out[k] = normalize(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = normalize(x)
		}
		return out
	}
	return v
}

// Counter returns packets of the first counter in the rule whose comment
// equals comment (in the Meshly table), for diagnostics.
func (rs *Ruleset) Counter(chain, comment string) (packets uint64, ok bool) {
	for _, r := range rs.ChainRules(TableFamily, TableName, chain) {
		if r.Comment != comment {
			continue
		}
		for _, e := range r.Expr {
			var c struct {
				Counter *struct {
					Packets uint64 `json:"packets"`
				} `json:"counter"`
			}
			if json.Unmarshal(e, &c) == nil && c.Counter != nil {
				return c.Counter.Packets, true
			}
		}
	}
	return 0, false
}
