package engine

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nikitakiselev/meshly/internal/engine/enginetest"
	"github.com/nikitakiselev/meshly/internal/journal"
	"github.com/nikitakiselev/meshly/internal/model"
	"github.com/nikitakiselev/meshly/internal/netstack"
	"github.com/nikitakiselev/meshly/internal/nft"
	"github.com/nikitakiselev/meshly/internal/store"
	"github.com/nikitakiselev/meshly/internal/wg"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ---- fixtures ----

type env struct {
	t     *testing.T
	k     *enginetest.Kernel
	e     *Engine
	j     *journal.Journal
	paths store.Paths
	keys  *store.Keys
}

func newEnv(t *testing.T) *env {
	t.Helper()
	paths := store.RootedPaths(t.TempDir(), os.Getuid())
	if err := paths.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	keys, _, err := paths.LoadOrCreateKeys()
	if err != nil {
		t.Fatal(err)
	}
	k := enginetest.New()
	now := func() time.Time { return time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC) }
	e := &Engine{Links: k.LinkOps(), WG: k.WGOps(), FW: k.NFT(), Paths: paths, LoadKeys: paths.LoadKeys, Now: now}
	return &env{t: t, k: k, e: e, j: journal.Open(paths.JournalFile(), now), paths: paths, keys: keys}
}

func randKey() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func (v *env) config() *model.Config {
	c := &model.Config{
		SchemaVersion: model.ConfigSchemaVersion, AdminState: model.AdminUp,
		Network:   model.Network{ID: strings.Repeat("ab", 16), Name: "homelab", CIDR: netip.MustParsePrefix("10.100.0.0/24")},
		Self:      model.Self{Name: "vps", Address: netip.MustParseAddr("10.100.0.1"), ListenPort: 51820, WGPublicKey: v.keys.WGPublic()},
		Interface: model.Interface{Name: "meshly0", MTU: 1420},
		Firewall:  model.Firewall{Profile: model.ProfileNone, Mark: model.DefaultFirewallMark},
		Peers: []model.Peer{{Name: "home", Address: netip.MustParseAddr("10.100.0.2"), WGPublicKey: randKey(),
			Keepalive: 25, AddedAt: time.Date(2026, 10, 17, 11, 0, 0, 0, time.UTC)}},
		Rules: []model.Rule{},
	}
	if err := c.Validate(); err != nil {
		v.t.Fatalf("fixture config invalid: %v", err)
	}
	return c
}

func names(steps []Step) []string {
	var n []string
	for _, s := range steps {
		n = append(n, s.Name)
	}
	return n
}

func (v *env) plan(c *model.Config) []string {
	v.t.Helper()
	d, err := DesiredFrom(c, "meshly0")
	if err != nil {
		v.t.Fatal(err)
	}
	o, err := v.e.Observe(context.Background(), "meshly0")
	if err != nil {
		v.t.Fatal(err)
	}
	steps, err := v.e.Plan(d, o)
	if err != nil {
		v.t.Fatal(err)
	}
	return names(steps)
}

func (v *env) commit(c *model.Config) {
	v.t.Helper()
	if _, err := v.e.Execute(context.Background(), v.j, Op{Name: "init", Recovery: journal.Backward, Target: c}); err != nil {
		v.t.Fatal(err)
	}
}

// ---- tests ----

func TestBringUpOrderProtectionFirst(t *testing.T) {
	v := newEnv(t)
	got := v.plan(v.config())
	want := []string{"firewall.apply", "link.create", "link.sysctl", "link.address", "wireguard.configure", "link.up", "routes.sync"}
	if !slices.Equal(got, want) {
		t.Fatalf("plan %v, want %v", got, want)
	}
}

func TestTeardownOrderTrafficPathFirst(t *testing.T) {
	v := newEnv(t)
	c := v.config()
	v.commit(c)
	down := c.Clone()
	down.AdminState = model.AdminDown
	got := v.plan(down)
	want := []string{"link.down", "link.delete", "firewall.remove"}
	if !slices.Equal(got, want) {
		t.Fatalf("plan %v, want %v", got, want)
	}
}

// ufwHost gives the fake kernel the iptables chains UFW leaves behind:
// INPUT with policy drop, OUTPUT with policy accept, each with jumps.
func ufwHost(k *enginetest.Kernel) {
	for _, f := range []string{"ip", "ip6"} {
		k.AddIptables(f, "INPUT", "drop", 3)
		k.AddIptables(f, "OUTPUT", "accept", 3)
	}
}

func ours(rs []enginetest.IptablesRule) []int {
	var out []int
	for i, r := range rs {
		if r.Comment == nft.IptablesComment {
			out = append(out, i)
		}
	}
	return out
}

// The meshly rule goes into the iptables chains right after the table and
// before any traffic path, first in each chain; tear-down removes it after
// the traffic path and before the table.
func TestIptablesIntegration(t *testing.T) {
	v := newEnv(t)
	ufwHost(v.k)
	v.k.AddIptables("ip", "FORWARD", "drop", 1) // not integrated
	c := v.config()
	want := []string{"firewall.apply", "iptables.integrate", "link.create", "link.sysctl", "link.address", "wireguard.configure", "link.up", "routes.sync"}
	if got := v.plan(c); !slices.Equal(got, want) {
		t.Fatalf("plan %v, want %v", got, want)
	}
	v.commit(c)
	for _, f := range []string{"ip", "ip6"} {
		for _, ch := range []string{"INPUT", "OUTPUT"} {
			rs := v.k.IptablesRules(f, ch)
			if got := ours(rs); !slices.Equal(got, []int{0}) || rs[0].Mark != model.DefaultFirewallMark || len(rs) != 4 {
				t.Fatalf("%s filter %s: %+v", f, ch, rs)
			}
		}
	}
	if rs := v.k.IptablesRules("ip", "FORWARD"); len(ours(rs)) != 0 {
		t.Fatalf("FORWARD integrated: %+v", rs)
	}
	if p := v.plan(c); len(p) != 0 {
		t.Fatalf("second plan not empty: %v", p)
	}

	// Removed by iptables-restore: drift, repaired by a reconcile.
	v.k.SetIptablesRules("ip", "INPUT", v.k.IptablesRules("ip", "INPUT")[1:])
	drift, err := v.e.Drift(context.Background(), c)
	if err != nil || len(drift) != 1 || !strings.Contains(drift[0], "ip filter INPUT") {
		t.Fatalf("drift %v, %v", drift, err)
	}
	if _, err := v.e.Reconcile(context.Background(), c, "meshly0", nil); err != nil {
		t.Fatal(err)
	}
	if got := ours(v.k.IptablesRules("ip", "INPUT")); !slices.Equal(got, []int{0}) {
		t.Fatalf("not repaired: %v", got)
	}

	// Moved down by a foreign rule inserted above it, and duplicated:
	// one rule again, first.
	rs := v.k.IptablesRules("ip6", "INPUT")
	rs = append([]enginetest.IptablesRule{{Handle: 900}}, append(rs, enginetest.IptablesRule{Handle: 901, Comment: nft.IptablesComment, Mark: model.DefaultFirewallMark})...)
	v.k.SetIptablesRules("ip6", "INPUT", rs)
	if got := v.plan(c); !slices.Equal(got, []string{"iptables.integrate"}) {
		t.Fatalf("plan %v", got)
	}
	if _, err := v.e.Reconcile(context.Background(), c, "meshly0", nil); err != nil {
		t.Fatal(err)
	}
	if rs := v.k.IptablesRules("ip6", "INPUT"); !slices.Equal(ours(rs), []int{0}) || len(rs) != 5 || rs[1].Handle != 900 {
		t.Fatalf("not first and unique: %+v", rs)
	}

	down := c.Clone()
	down.AdminState = model.AdminDown
	want = []string{"link.down", "link.delete", "iptables.remove", "firewall.remove"}
	if got := v.plan(down); !slices.Equal(got, want) {
		t.Fatalf("plan %v, want %v", got, want)
	}
	if _, err := v.e.Reconcile(context.Background(), down, "meshly0", nil); err != nil {
		t.Fatal(err)
	}
	for _, ch := range v.k.Iptables {
		if len(ours(ch.Rules)) != 0 || len(ch.Rules) == 0 {
			t.Fatalf("%s filter %s after tear-down: %+v", ch.Family, ch.Chain, ch.Rules)
		}
	}
}

// Chains that cannot drop anything are left alone (Docker leaves an empty
// INPUT behind, for example).
func TestIptablesEmptyChainsUntouched(t *testing.T) {
	v := newEnv(t)
	v.k.AddIptables("ip", "INPUT", "accept", 0)
	c := v.config()
	if got := v.plan(c); slices.Contains(got, "iptables.integrate") {
		t.Fatalf("plan %v", got)
	}
	v.commit(c)
	if rs := v.k.IptablesRules("ip", "INPUT"); len(rs) != 0 {
		t.Fatalf("empty chain changed: %+v", rs)
	}
}

// A failed integration rolls back like any other step: nothing of meshly
// stays in the iptables chains.
func TestIptablesIntegrationRollback(t *testing.T) {
	v := newEnv(t)
	ufwHost(v.k)
	v.k.Fail("iptables.apply", 1)
	_, err := v.e.Execute(context.Background(), v.j, Op{Name: "init", Recovery: journal.Backward, Target: v.config()})
	var ae *ApplyError
	if !errors.As(err, &ae) || !ae.RolledBack {
		t.Fatalf("err = %v", err)
	}
	for _, ch := range v.k.Iptables {
		if len(ours(ch.Rules)) != 0 {
			t.Fatalf("%s filter %s: %+v", ch.Family, ch.Chain, ch.Rules)
		}
	}
	if v.k.Table != "" {
		t.Fatal("table left after rollback")
	}
}

func TestIdempotent(t *testing.T) {
	v := newEnv(t)
	c := v.config()
	v.commit(c)
	if p := v.plan(c); len(p) != 0 {
		t.Fatalf("second plan not empty: %v", p)
	}
	before, _ := v.j.Read()
	res, err := v.e.Execute(context.Background(), v.j, Op{Name: "start", Recovery: journal.Backward, Base: c, Target: c.Clone()})
	if err != nil || len(res.Steps) != 0 {
		t.Fatalf("repeated execute: %v %v", res, err)
	}
	after, _ := v.j.Read()
	if len(after) != len(before) {
		t.Fatal("a no-op wrote journal records")
	}
	saved, _ := v.paths.LoadConfig()
	if saved.Revision != 1 {
		t.Fatalf("revision bumped by a no-op: %d", saved.Revision)
	}
}

func TestOwnershipConflicts(t *testing.T) {
	v := newEnv(t)
	v.k.Links["meshly0"] = &netstack.Link{Exists: true, Type: "dummy"}
	_, err := v.e.Execute(context.Background(), v.j, Op{Name: "init", Recovery: journal.Backward, Target: v.config()})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("foreign interface: %v", err)
	}
	if v.k.Table != "" || slices.Contains(v.k.Calls, "nft.apply") {
		t.Fatal("changes made despite conflict")
	}
	v = newEnv(t)
	v.k.Foreign = true
	if _, err := v.e.Execute(context.Background(), v.j, Op{Name: "init", Recovery: journal.Backward, Target: v.config()}); !errors.Is(err, ErrConflict) {
		t.Fatalf("foreign table: %v", err)
	}
	if len(v.k.Links) != 0 {
		t.Fatal("interface created despite conflict")
	}
}

func TestBackwardRollback(t *testing.T) {
	v := newEnv(t)
	base := v.config()
	v.commit(base)
	saved, _ := v.paths.LoadConfig()
	target := saved.Clone()
	target.Rules = []model.Rule{{Peer: "home", Proto: model.ProtoTCP, Port: 22}}
	baseTable := v.k.Table
	v.k.Fail("nft.apply", 1)
	_, err := v.e.Execute(context.Background(), v.j, Op{Name: "allow", Recovery: journal.Backward, Base: saved, Target: target})
	var ae *ApplyError
	if !errors.As(err, &ae) || !ae.RolledBack {
		t.Fatalf("want rollback, got %v", err)
	}
	if v.k.Table != baseTable {
		t.Fatal("firewall not at base after rollback")
	}
	if c, _ := v.paths.LoadConfig(); len(c.Rules) != 0 || c.Revision != saved.Revision {
		t.Fatal("config not at base after rollback")
	}
	if inc, _ := v.j.Incomplete(); inc != nil {
		t.Fatal("journal left incomplete")
	}
}

// A failure after the target was saved must also restore the base config.
func TestBackwardRollbackAfterSave(t *testing.T) {
	v := newEnv(t)
	v.commit(v.config())
	saved, _ := v.paths.LoadConfig()
	target := saved.Clone()
	target.Rules = []model.Rule{{Peer: "home", Proto: model.ProtoTCP, Port: 22}}
	// Verify passes, then the journal commit... we simulate the failure by
	// failing the rollback-visible step: make Verify fail via tamper after
	// apply is impossible here, so call fail() directly.
	if err := v.e.persist(target); err != nil {
		t.Fatal(err)
	}
	err := v.e.fail(context.Background(), v.j, Op{Name: "allow", Recovery: journal.Backward, Base: saved, Target: target}, "x", "meshly0", errors.New("boom"))
	var ae *ApplyError
	if !errors.As(err, &ae) || !ae.RolledBack {
		t.Fatalf("want rollback: %v", err)
	}
	if c, _ := v.paths.LoadConfig(); len(c.Rules) != 0 {
		t.Fatal("saved target survived the rollback")
	}
	if p := v.plan(saved); len(p) != 0 {
		t.Fatalf("kernel not at base: %v", p)
	}
}

func TestForwardCompletes(t *testing.T) {
	v := newEnv(t)
	c := v.config()
	c.Rules = []model.Rule{{Peer: "home", Proto: model.ProtoTCP, Port: 22}}
	v.commit(c)
	saved, _ := v.paths.LoadConfig()
	target := saved.Clone()
	target.Rules = nil
	v.k.Fail("nft.apply", 1) // transient
	res, err := v.e.Execute(context.Background(), v.j, Op{Name: "deny", Recovery: journal.Forward, Base: saved, Target: target})
	if err != nil || res == nil {
		t.Fatalf("forward op not completed: %v", err)
	}
	if got, _ := v.paths.LoadConfig(); len(got.Rules) != 0 {
		t.Fatal("deny not persisted")
	}
	if p := v.plan(target); len(p) != 0 {
		t.Fatalf("kernel not at target: %v", p)
	}
}

func TestSafeModeWhenRollbackFails(t *testing.T) {
	v := newEnv(t)
	v.commit(v.config())
	saved, _ := v.paths.LoadConfig()
	// The nft transaction is atomic and a failing step that changed nothing
	// is trivially reverted, so safe mode needs a partial change (the new
	// firewall table) whose revert fails as well.
	target := saved.Clone()
	target.Interface.MTU = 1380
	target.Rules = []model.Rule{{Peer: "home", Proto: model.ProtoTCP, Port: 22}}
	v.k.Fail("link.mtu", -1)
	v.k.Cascade("link.mtu", "nft.apply") // the firewall revert fails too
	_, err := v.e.Execute(context.Background(), v.j, Op{Name: "set", Recovery: journal.Backward, Base: saved, Target: target})
	var ae *ApplyError
	if !errors.As(err, &ae) || !ae.SafeMode {
		t.Fatalf("want safe mode: %v", err)
	}
	if _, ok := v.k.Links["meshly0"]; ok {
		t.Fatal("interface still present in safe mode")
	}
	recs, _ := v.j.Read()
	if recs[len(recs)-1].Event != journal.EventSafeMode {
		t.Fatalf("journal: %+v", recs[len(recs)-1])
	}
}

// Safe mode leaves the iptables rule alone but marks no transport, so the
// rule lets nothing of meshly through the chains of UFW.
func TestSafeModeIptables(t *testing.T) {
	v := newEnv(t)
	ufwHost(v.k)
	c := v.config()
	v.commit(c)
	n := len(v.k.Scripts)
	if err := v.e.SafeMode(context.Background(), c, ""); err != nil {
		t.Fatal(err)
	}
	if len(v.k.Scripts) != n+1 {
		t.Fatalf("want one lockdown script, got %d", len(v.k.Scripts)-n)
	}
	if s := v.k.Scripts[n]; strings.Contains(s, "wireguard transport") || !strings.Contains(s, "table inet meshly") {
		t.Fatalf("lockdown script:\n%s", s)
	}
	if got := ours(v.k.IptablesRules("ip", "INPUT")); !slices.Equal(got, []int{0}) {
		t.Fatalf("iptables rule: %v", got)
	}
}

func TestRecoverDirections(t *testing.T) {
	ctx := context.Background()
	t.Run("backward interrupted before save is rolled back", func(t *testing.T) {
		v := newEnv(t)
		v.commit(v.config())
		saved, _ := v.paths.LoadConfig()
		target := saved.Clone()
		target.Rules = []model.Rule{{Peer: "home", Proto: model.ProtoTCP, Port: 22}}
		target.Revision = saved.Revision + 1
		_ = v.j.Append(journal.Record{OpID: "op1", Event: journal.EventBegin, Op: "allow", Recovery: journal.Backward, Target: target, Interface: "meshly0", BaseRevision: saved.Revision})
		// The firewall already has the new rule (crash after apply).
		d, _ := DesiredFrom(target, "meshly0")
		_ = v.e.applyFirewall(ctx, d.Firewall)
		rec, err := v.e.Recover(ctx, v.j)
		if err != nil || rec.Mode != "rolled-back" {
			t.Fatalf("%+v %v", rec, err)
		}
		if p := v.plan(saved); len(p) != 0 {
			t.Fatalf("kernel not back at base: %v", p)
		}
	})
	t.Run("forward interrupted is completed", func(t *testing.T) {
		v := newEnv(t)
		c := v.config()
		c.Rules = []model.Rule{{Peer: "home", Proto: model.ProtoTCP, Port: 22}}
		v.commit(c)
		saved, _ := v.paths.LoadConfig()
		target := saved.Clone()
		target.Rules = nil
		target.Revision = saved.Revision + 1
		_ = v.j.Append(journal.Record{OpID: "op2", Event: journal.EventBegin, Op: "deny", Recovery: journal.Forward, Target: target, Interface: "meshly0"})
		rec, err := v.e.Recover(ctx, v.j)
		if err != nil || rec.Mode != "rolled-forward" {
			t.Fatalf("%+v %v", rec, err)
		}
		if got, _ := v.paths.LoadConfig(); len(got.Rules) != 0 {
			t.Fatal("deny not completed in the config")
		}
		if p := v.plan(target); len(p) != 0 {
			t.Fatalf("kernel not at target: %v", p)
		}
		if inc, _ := v.j.Incomplete(); inc != nil {
			t.Fatal("still incomplete")
		}
	})
	t.Run("nothing to recover", func(t *testing.T) {
		v := newEnv(t)
		if rec, err := v.e.Recover(ctx, v.j); rec != nil || err != nil {
			t.Fatalf("%+v %v", rec, err)
		}
	})
}

func TestDriftDetected(t *testing.T) {
	v := newEnv(t)
	c := v.config()
	v.commit(c)
	saved, _ := v.paths.LoadConfig()
	v.k.Links["meshly0"].MTU = 1500
	v.k.Tamper = true
	v.k.Sysctl["meshly0"] = []string{"forwarding"}
	drift, err := v.e.Drift(context.Background(), saved)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(drift, "\n")
	for _, want := range []string{"modified outside meshly", "mtu", "sysctls"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("drift %q misses %q", joined, want)
		}
	}
}

func TestEndpointHint(t *testing.T) {
	v := newEnv(t)
	c := v.config()
	v.commit(c)
	pub := c.Peers[0].WGPublicKey
	learned := netip.MustParseAddrPort("198.51.100.2:40000")
	d := v.k.Devs["meshly0"]
	d.Peers[0].Endpoint, d.Peers[0].LastHandshake = learned, v.e.Now().Add(-time.Minute)
	saved, _ := v.paths.LoadConfig()
	down := saved.Clone()
	down.AdminState = model.AdminDown
	if _, err := v.e.Reconcile(context.Background(), down, "meshly0", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := v.e.Reconcile(context.Background(), saved, "meshly0", nil); err != nil {
		t.Fatal(err)
	}
	ps, ok := v.k.Devs["meshly0"].Peer(pub)
	if !ok || ps.Endpoint != learned {
		t.Fatalf("remembered endpoint not used after restart: %+v", ps)
	}
	if p := v.plan(saved); len(p) != 0 {
		t.Fatalf("endpoint hint causes drift: %v", p)
	}
}

// ---- overlay ----

func genKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func tempOverlay(t *testing.T) (*Overlay, string, wgtypes.Key) {
	t.Helper()
	temp := genKey(t).PublicKey().String()
	psk := genKey(t)
	return &Overlay{
		Peer:  &wg.DesiredPeer{PublicKey: temp, AllowedIP: netip.MustParsePrefix("10.100.0.2/32"), Keepalive: 25, PresharedKey: psk},
		Allow: []nft.AllowEntry{{Peer: netip.MustParseAddr("10.100.0.2"), Proto: model.ProtoTCP, Port: 51820}},
	}, temp, psk
}

func TestOverlayPeerAndAllow(t *testing.T) {
	v := newEnv(t)
	ctx := context.Background()
	c := v.config()
	c.Peers = nil
	v.commit(c)
	ov, temp, psk := tempOverlay(t)
	if err := v.e.ApplyOverlay(ctx, c, "meshly0", ov); err != nil {
		t.Fatal(err)
	}
	if _, ok := mustObserve(t, v).Peer(temp); !ok {
		t.Fatal("temporary peer missing")
	}
	if got := v.k.PresharedKey(temp); got != psk {
		t.Fatal("preshared key not applied")
	}
	l, _ := v.k.LinkOps().Observe("meshly0")
	if len(l.Routes) != 1 || l.Routes[0].Dst != netip.MustParsePrefix("10.100.0.2/32") {
		t.Fatalf("routes %v", l.Routes)
	}
	if last := v.k.Scripts[len(v.k.Scripts)-1]; !strings.Contains(last, "10.100.0.2 . tcp . 51820") || !strings.Contains(last, exclusiveRule) {
		t.Fatalf("allow entry or its exclusive rule missing in:\n%s", last)
	}
	if drift, err := v.e.Drift(ctx, c); err != nil || len(drift) == 0 {
		t.Fatalf("drift while overlay is in place: %v %v", drift, err)
	}
	if _, err := v.e.Reconcile(ctx, c, "meshly0", nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := mustObserve(t, v).Peer(temp); ok {
		t.Fatal("temporary peer still present")
	}
	if got := v.k.PresharedKey(temp); got != (wgtypes.Key{}) {
		t.Fatal("preshared key not cleared")
	}
	if drift, _ := v.e.Drift(ctx, c); len(drift) != 0 {
		t.Fatalf("drift after removing overlay: %v", drift)
	}
	if last := v.k.Scripts[len(v.k.Scripts)-1]; strings.Contains(last, "tcp . 51820") || strings.Contains(last, "tcp dport 51820") {
		t.Fatalf("allow entry or its exclusive rule still present in:\n%s", last)
	}
	plain, err := DesiredFrom(c, "meshly0")
	if err != nil {
		t.Fatal(err)
	}
	if last := v.k.Scripts[len(v.k.Scripts)-1]; last != plain.Firewall.ApplyScript() {
		t.Fatalf("the table without the overlay differs from the saved configuration's:\n%s", last)
	}
}

// exclusiveRule is what the overlay's allow entry adds to guard_in: the
// pairing port answers its peer through the tunnel only.
const exclusiveRule = `ip daddr 10.100.0.1 tcp dport 51820 iifname . ip saddr != { "meshly0" . 10.100.0.2 } counter drop`

func mustObserve(t *testing.T, v *env) *wg.Device {
	t.Helper()
	d, err := v.e.WG.Observe("meshly0")
	if err != nil || d == nil {
		t.Fatalf("observe: %v %v", d, err)
	}
	return d
}

func TestOverlayPrivateKey(t *testing.T) {
	v := newEnv(t)
	c := v.config()
	c.Peers = nil
	v.e.LoadKeys = func() (*store.Keys, error) { return nil, errors.New("no key file") }
	k := genKey(t)
	if err := v.e.ApplyOverlay(context.Background(), c, "meshly0", &Overlay{PrivateKey: &k}); err != nil {
		t.Fatal(err)
	}
	if got := mustObserve(t, v).PublicKey; got != k.PublicKey().String() {
		t.Fatalf("public key %s, want %s", got, k.PublicKey())
	}
}

func TestOverlayFailureRestoresConfig(t *testing.T) {
	v := newEnv(t)
	c := v.config()
	c.Peers = nil
	v.commit(c)
	ov, _, _ := tempOverlay(t)
	v.k.Fail("wireguard.configure", 1)
	err := v.e.ApplyOverlay(context.Background(), c, "meshly0", ov)
	if err == nil || !strings.Contains(err.Error(), "wireguard.configure") || !strings.Contains(err.Error(), "fake wireguard.configure failure") {
		t.Fatalf("want the original configure error, got %v", err)
	}
	if drift, err := v.e.Drift(context.Background(), c); err != nil || len(drift) != 0 {
		t.Fatalf("drift after failed overlay: %v %v", drift, err)
	}
}

func TestExecuteWithOverlay(t *testing.T) {
	v := newEnv(t)
	ctx := context.Background()
	base := v.config()
	base.Peers = nil
	v.commit(base)
	// Armed state: the inviter waits with a temporary peer and allow.
	armed, temp, psk := tempOverlay(t)
	if err := v.e.ApplyOverlay(ctx, base, "meshly0", armed); err != nil {
		t.Fatal(err)
	}
	// The pairing completes: the real peer replaces the temporary one.
	target := v.config()
	ov := &Overlay{Allow: armed.Allow}
	if _, err := v.e.Execute(ctx, v.j, Op{Name: "invite", Recovery: journal.Backward, Base: base, Target: target, Overlay: ov}); err != nil {
		t.Fatal(err)
	}
	dev := mustObserve(t, v)
	if _, ok := dev.Peer(temp); ok {
		t.Fatal("temporary peer still present")
	}
	if v.k.PresharedKey(temp) != (wgtypes.Key{}) {
		t.Fatal("temporary preshared key not cleared")
	}
	if _, ok := dev.Peer(target.Peers[0].WGPublicKey); !ok {
		t.Fatal("real peer missing")
	}
	if last := v.k.Scripts[len(v.k.Scripts)-1]; !strings.Contains(last, "10.100.0.2 . tcp . 51820") || !strings.Contains(last, exclusiveRule) {
		t.Fatalf("allow entry or its exclusive rule missing in:\n%s", last)
	}
	saved, err := v.paths.LoadConfig()
	if err != nil || len(saved.Peers) != 1 || len(saved.Rules) != 0 {
		t.Fatalf("saved config %+v %v", saved, err)
	}
	raw, err := os.ReadFile(v.paths.JournalFile())
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []wgtypes.Key{psk, v.keys.WG} {
		if strings.Contains(string(raw), k.String()) || strings.Contains(string(raw), string(k[:])) {
			t.Fatal("journal contains key material")
		}
	}
}

func TestInPlaceUpdateClearsPresharedKey(t *testing.T) {
	v := newEnv(t)
	ctx := context.Background()
	c := v.config()
	c.Peers = nil
	p := genKey(t).PublicKey().String()
	psk := genKey(t)
	tmpPriv := genKey(t)
	ov := &Overlay{PrivateKey: &tmpPriv, Peer: &wg.DesiredPeer{PublicKey: p, AllowedIP: netip.MustParsePrefix("10.100.0.2/32"), PresharedKey: psk}}
	if err := v.e.ApplyOverlay(ctx, c, "meshly0", ov); err != nil {
		t.Fatal(err)
	}
	if v.k.PresharedKey(p) != psk {
		t.Fatal("preshared key not applied")
	}
	c2 := v.config()
	c2.Peers[0].WGPublicKey = p
	c2.Peers[0].Keepalive = 0
	if _, err := v.e.Reconcile(ctx, c2, "meshly0", nil); err != nil {
		t.Fatal(err)
	}
	if v.k.PresharedKey(p) != (wgtypes.Key{}) {
		t.Fatal("preshared key survived an in-place update")
	}
}
