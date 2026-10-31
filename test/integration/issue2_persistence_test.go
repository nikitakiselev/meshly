//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

type persistenceConfig struct {
	Revision   uint64            `json:"revision"`
	AdminState string            `json:"admin_state"`
	Rules      []json.RawMessage `json:"rules"`
	Peers      []json.RawMessage `json:"peers"`
}

func readPersistenceConfig(t *testing.T, n *Node) persistenceConfig {
	t.Helper()
	var c persistenceConfig
	if err := json.Unmarshal([]byte(n.MustSh("cat /etc/meshly/meshly.json")), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// Replacing a single history filename with a directory fails atomic writes
// deterministically without preventing normal startup path validation.
func blockPersistenceRevision(n *Node, revision uint64) func() {
	path := fmt.Sprintf("/var/lib/meshly/history/meshly-%d.json", revision)
	n.MustSh(fmt.Sprintf("if [ -f %s ]; then mv %s %s.issue2; fi; mkdir %s", path, path, path, path))
	return func() {
		n.MustSh(fmt.Sprintf("rmdir %s; if [ -f %s.issue2 ]; then mv %s.issue2 %s; fi", path, path, path, path))
	}
}

func assertPersistenceClosed(t *testing.T, vps, home *Node) {
	t.Helper()
	if vps.Sh("ip link show meshly0").Code == 0 {
		t.Fatal("VPN interface exists while persistence failure keeps recovery pending")
	}
	if home.Probe("tcp", "10.100.0.1", 8080) {
		t.Fatal("service reachable while persistence failure keeps recovery pending")
	}
	if !status(t, vps).Transaction.Incomplete {
		t.Fatal("safe mode discarded pending recovery intent")
	}
}

func retryBlockedPersistence(t *testing.T, vps, home *Node) {
	t.Helper()
	for _, args := range [][]string{{"service", "check"}, {"start"}, {"recover"}, {"service", "start"}} {
		r := vps.Meshly(args...)
		if r.Code != 8 {
			t.Fatalf("%s: want safe mode while persistence blocked: %s", strings.Join(args, " "), r)
		}
		assertPersistenceClosed(t, vps, home)
	}
}

// Failed history writes must not let service checks, starts, or recover
// resurrect the access removed by deny, revoke, or stop.
func TestIssue2ForwardPersistenceFailure(t *testing.T) {
	for _, name := range []string{"deny", "revoke", "stop"} {
		t.Run(name, func(t *testing.T) {
			l := newLab(t, distros[0])
			vps, home := l.Pair()
			vps.Listen("tcp", 8080)
			vps.MustMeshly("allow", "8080/tcp", "from", "home")
			if !home.Probe("tcp", "10.100.0.1", 8080) {
				t.Fatal("baseline service unreachable")
			}
			base := readPersistenceConfig(t, vps)
			unblock := blockPersistenceRevision(vps, base.Revision+1)
			args := map[string][]string{"deny": {"deny", "8080/tcp", "from", "home"}, "revoke": {"revoke", "home", "--yes"}, "stop": {"stop"}}[name]
			if r := vps.Meshly(args...); r.Code != 8 {
				t.Fatalf("want safe mode on failed write: %s", r)
			}
			assertPersistenceClosed(t, vps, home)
			retryBlockedPersistence(t, vps, home)
			unblock()
			vps.MustMeshly("recover")
			vps.MustMeshly("service", "check")
			vps.MustMeshly("service", "start")
			got := readPersistenceConfig(t, vps)
			if got.Revision != base.Revision+1 {
				t.Fatalf("target revision not persisted: %d", got.Revision)
			}
			switch name {
			case "deny":
				if len(got.Rules) != 0 {
					t.Fatal("deny was undone")
				}
			case "revoke":
				if len(got.Peers) != 0 || len(got.Rules) != 0 {
					t.Fatal("revoke was undone")
				}
			case "stop":
				if got.AdminState != "down" || vps.Sh("ip link show meshly0").Code == 0 {
					t.Fatal("stop was undone")
				}
			}
			if home.Probe("tcp", "10.100.0.1", 8080) {
				t.Fatal("removed access reopened after persistence recovery")
			}
			if status(t, vps).Transaction.Incomplete {
				t.Fatal("successful recovery remains pending")
			}
		})
	}
}

// The target is saved before the injected commit failure; restoring its
// base then fails. Later recovery must restore the base, never the grant.
func TestIssue2BackwardBasePersistenceFailure(t *testing.T) {
	l := newLab(t, distros[0])
	vps, home := l.Pair()
	vps.Listen("tcp", 8080)
	base := readPersistenceConfig(t, vps)
	unblock := blockPersistenceRevision(vps, base.Revision)
	r := vps.Meshly("MESHLY_FAULT=tx:before-commit=error", "allow", "8080/tcp", "from", "home")
	if r.Code != 8 {
		t.Fatalf("want safe mode on failed rollback save: %s", r)
	}
	if got := readPersistenceConfig(t, vps); len(got.Rules) != 1 {
		t.Fatal("regression setup did not save target grant")
	}
	assertPersistenceClosed(t, vps, home)
	retryBlockedPersistence(t, vps, home)
	unblock()
	vps.MustMeshly("recover")
	vps.MustMeshly("service", "check")
	vps.MustMeshly("start")
	got := readPersistenceConfig(t, vps)
	if got.Revision != base.Revision || len(got.Rules) != 0 {
		t.Fatal("recovery restored failed grant")
	}
	if home.Probe("tcp", "10.100.0.1", 8080) {
		t.Fatal("failed grant opened service after recovery")
	}
	if status(t, vps).Transaction.Incomplete {
		t.Fatal("successful rollback remains pending")
	}
}
