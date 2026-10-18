//go:build integration

package integration

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

type statusJSON struct {
	Initialized bool `json:"initialized"`
	Transaction struct {
		Incomplete bool `json:"incomplete"`
	} `json:"transaction"`
	Drift []string `json:"drift"`
}

func status(t *testing.T, n *Node) statusJSON {
	t.Helper()
	r := n.MustMeshly("status", "--json")
	var s statusJSON
	if err := json.Unmarshal([]byte(r.Out), &s); err != nil {
		t.Fatalf("status --json: %v\n%s", err, r.Out)
	}
	return s
}

// settle runs recovery after an injected failure and checks the global
// invariant: no interrupted transaction, and the kernel matches the saved
// configuration exactly (or nothing of meshly exists when there is none).
func settle(t *testing.T, n *Node, r Result) {
	t.Helper()
	switch r.Code {
	case 0, 7, 8, 137:
	default:
		t.Fatalf("unexpected exit code: %s", r)
	}
	if strings.Contains(r.Out+r.Err, "PRIVATE KEY") {
		t.Fatal("secret in output")
	}
	if r.Code == 137 {
		rec := n.Meshly("recover")
		if rec.Code != 0 && rec.Code != 8 {
			t.Fatalf("recover: %s", rec)
		}
	}
	s := status(t, n)
	if s.Transaction.Incomplete {
		t.Fatal("transaction still incomplete after recovery")
	}
	if s.Initialized {
		if len(s.Drift) != 0 && r.Code != 8 {
			t.Fatalf("kernel differs from saved configuration: %v", s.Drift)
		}
		return
	}
	if n.Sh("ip link show meshly0").Code == 0 {
		t.Fatal("interface exists without configuration")
	}
	if n.Sh("nft list table inet meshly").Code == 0 {
		t.Fatal("firewall table exists without configuration")
	}
}

var actions = []string{"error", "crash"}

// Scenario 15 for a bring-up from nothing (init): every failure point
// leaves either nothing or the complete, verified configuration.
func TestFaultsInit(t *testing.T) {
	l := newLab(t, distros[0])
	vps := l.Node("vps")
	points := []string{"tx:after-begin", "step:firewall.apply", "step:link.create", "step:link.sysctl", "step:link.address",
		"step:wireguard.configure", "step:link.up", "tx:before-verify", "tx:before-save", "tx:before-commit"}
	for _, p := range points {
		for _, a := range actions {
			l.Run(p+"="+a, func(t *testing.T) {
				r := vps.Meshly("MESHLY_FAULT="+p+"="+a, "init", "homelab", "--name", "vps", "--endpoint", "198.51.100.10:51820")
				if a == "error" && r.Code != 7 && p != "tx:before-commit" {
					t.Fatalf("want exit 7 (rolled back): %s", r)
				}
				settle(t, vps, r)
				vps.MustMeshly("reset", "--yes")
				settle(t, vps, Result{})
			})
		}
	}
}

// Scenario 15 for access-opening changes (allow): the rule is either fully
// in effect or not at all, and never in the kernel without the config.
func TestFaultsAllow(t *testing.T) {
	l := newLab(t, distros[0])
	vps, home := l.Pair()
	vps.Listen("tcp", 8080)
	points := []string{"tx:after-begin", "step:firewall.apply", "tx:before-verify", "tx:before-save", "tx:before-commit"}
	for _, p := range points {
		for _, a := range actions {
			l.Run(p+"="+a, func(t *testing.T) {
				r := vps.Meshly("MESHLY_FAULT="+p+"="+a, "allow", "8080/tcp", "from", "home")
				settle(t, vps, r)
				inConfig := strings.Contains(vps.MustMeshly("rules").Out, "8080/tcp from home")
				reachable := home.Probe("tcp", "10.100.0.1", 8080)
				if inConfig != reachable {
					t.Fatalf("rule in config=%v but reachable=%v", inConfig, reachable)
				}
				vps.MustMeshly("deny", "8080/tcp", "from", "home")
			})
		}
	}
	// The rollback itself fails: safe mode closes the VPN path.
	l.Run("safe-mode", func(t *testing.T) {
		r := vps.Meshly("MESHLY_FAULT=step:firewall.apply=error,tx:rollback=error", "allow", "8080/tcp", "from", "home")
		if r.Code != 8 {
			t.Fatalf("want exit 8 (safe mode): %s", r)
		}
		if vps.Sh("ip link show meshly0").Code == 0 {
			t.Fatal("interface still present in safe mode")
		}
		if out := vps.MustSh("nft list set inet meshly peers"); strings.Contains(out, "elements") {
			t.Fatalf("safe mode table still admits peers:\n%s", out)
		}
		if home.Probe("tcp", "10.100.0.1", 8080) {
			t.Fatal("service reachable in safe mode")
		}
		vps.MustMeshly("start")
		l.WaitHandshake(home, 40*time.Second)
		if home.Probe("tcp", "10.100.0.1", 8080) {
			t.Fatal("the failed allow became effective after start")
		}
		settle(t, vps, Result{})
	})
}

// Scenario 15 for access-reducing changes: interruption completes them;
// access is closed afterwards in every case.
func TestFaultsReduce(t *testing.T) {
	l := newLab(t, distros[0])
	vps, home := l.Pair()
	vps.Listen("tcp", 8080)
	vps.MustMeshly("allow", "8080/tcp", "from", "home")
	if !home.Probe("tcp", "10.100.0.1", 8080) {
		t.Fatal("baseline")
	}
	points := []string{"tx:after-begin", "step:firewall.apply", "tx:before-verify", "tx:before-commit"}
	for _, p := range points {
		for _, a := range actions {
			l.Run("deny/"+p+"="+a, func(t *testing.T) {
				r := vps.Meshly("MESHLY_FAULT="+p+"="+a, "deny", "8080/tcp", "from", "home")
				settle(t, vps, r)
				if strings.Contains(vps.MustMeshly("rules").Out, "8080/tcp") || home.Probe("tcp", "10.100.0.1", 8080) {
					t.Fatal("deny was undone by the failure")
				}
				vps.MustMeshly("allow", "8080/tcp", "from", "home")
			})
		}
	}
	stopPoints := []string{"tx:after-begin", "step:link.down", "step:link.delete", "step:firewall.remove", "tx:before-verify", "tx:before-commit"}
	for _, p := range stopPoints {
		for _, a := range actions {
			l.Run("stop/"+p+"="+a, func(t *testing.T) {
				r := vps.Meshly("MESHLY_FAULT="+p+"="+a, "stop")
				settle(t, vps, r)
				if vps.Sh("ip link show meshly0").Code == 0 {
					t.Fatal("link still up after interrupted stop")
				}
				vps.MustMeshly("start")
			})
		}
	}
	revokePoints := []string{"step:firewall.apply", "step:wireguard.configure", "step:routes.sync", "tx:before-commit"}
	for i, p := range revokePoints {
		a := actions[i%2]
		l.Run("revoke/"+p+"="+a, func(t *testing.T) {
			r := vps.Meshly("MESHLY_FAULT="+p+"="+a, "revoke", "home", "--yes")
			settle(t, vps, r)
			if out := vps.MustSh("wg show meshly0 peers"); strings.TrimSpace(out) != "" {
				t.Fatal("peer still configured after interrupted revoke")
			}
			if home.Probe("tcp", "10.100.0.1", 8080) {
				t.Fatal("access after interrupted revoke")
			}
		})
		if t.Failed() {
			return
		}
		// Re-pair for the next case.
		home.MustMeshly("reset", "--yes")
		l.Pair()
		vps.MustMeshly("allow", "8080/tcp", "from", "home")
	}
}

// A join interrupted on the joining node is rolled back there; the
// inviter undoes the membership that was never confirmed, and the same code
// pairs.
func TestFaultJoin(t *testing.T) {
	if os.Getenv("MESHLY_IT_SHORT") != "" {
		t.Skip("MESHLY_IT_SHORT set")
	}
	l := newLab(t, distros[0])
	vps, home := l.Node("vps"), l.Node("home")
	vps.MustMeshly("init", "homelab", "--name", "vps", "--endpoint", "198.51.100.10:51820")
	code := vps.Invite()
	r := home.JoinEnv([]string{"MESHLY_FAULT=step:wireguard.configure=crash"}, code)
	if r.Code != 137 {
		t.Fatalf("want crash: %s", r)
	}
	settle(t, home, r)
	waitFor(t, "the inviter undoes the unconfirmed join", 90*time.Second, func() bool {
		return strings.Contains(vps.Sh("cat /root/invite.err").Out, "did not confirm")
	})
	if r := home.Join(code); r.Code != 0 {
		t.Fatalf("join after the crash: %s\ninvite stderr:\n%s", r, vps.Sh("cat /root/invite.err").Out)
	}
	if c, inv := vps.InviteExit(30 * time.Second); c != 0 {
		t.Fatalf("invite: exit %d\n%s", c, inv)
	}
	l.WaitHandshake(home, 20*time.Second)
}
