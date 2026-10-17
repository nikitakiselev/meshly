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
	"github.com/nikitakiselev/meshly/internal/store"
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
		Self:      model.Self{Name: "vps", Address: netip.MustParseAddr("10.100.0.1"), ListenPort: 51820, WGPublicKey: v.keys.WGPublic(), IdentityKey: v.keys.IdentityPublic()},
		Interface: model.Interface{Name: "meshly0", MTU: 1420},
		Firewall:  model.Firewall{Profile: model.ProfileNone, Mark: model.DefaultFirewallMark},
		Peers: []model.Peer{{Name: "home", Address: netip.MustParseAddr("10.100.0.2"), WGPublicKey: randKey(), IdentityKey: randKey(),
			Keepalive: 25, AddedAt: time.Date(2026, 10, 17, 11, 0, 0, 0, time.UTC), TrustedVia: "approve", TrustDigest: strings.Repeat("cd", 32)}},
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
