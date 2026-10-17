//go:build integration

package integration

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// tamper flips one byte of the signed payload of a bootstrap envelope.
func tamper(t *testing.T, doc []byte) []byte {
	t.Helper()
	var env map[string]any
	if err := json.Unmarshal(doc, &env); err != nil {
		t.Fatal(err)
	}
	p, err := base64.RawURLEncoding.DecodeString(env["payload"].(string))
	if err != nil {
		t.Fatal(err)
	}
	p[len(p)/2] ^= 0x01
	env["payload"] = base64.RawURLEncoding.EncodeToString(p)
	out, _ := json.Marshal(env)
	return out
}

// Trust needs both admins; files are verified, bound and one-time.
func TestBootstrapTrust(t *testing.T) {
	l := newLab(t, distros[0])
	vps, home, third := l.Node("vps"), l.Node("home"), l.Node("lanhost")
	r := vps.MustMeshly("init", "homelab", "--name", "vps", "--endpoint", "198.51.100.10:51820")
	vpsFP := fingerprint(t, r.Out)
	vps.MustMeshly("invite", "--out", "/root/home.invite")
	inv := vps.ReadFile("/root/home.invite")

	// A modified invite is rejected before anything is generated.
	home.WriteFile("/root/bad.invite", tamper(t, inv))
	home.ExpectCode(4, "join", "/root/bad.invite", "--name", "home", "--expect-fingerprint", vpsFP)
	if home.Sh("test -e /etc/meshly/keys/wireguard.key").Code == 0 {
		t.Fatal("keys generated for a rejected invite")
	}
	// A wrong expected fingerprint (e.g. the invite was swapped) stops join.
	home.WriteFile("/root/home.invite", inv)
	home.ExpectCode(10, "join", "/root/home.invite", "--name", "home", "--expect-fingerprint", "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")

	r = home.MustMeshly("join", "/root/home.invite", "--name", "home", "--expect-fingerprint", vpsFP, "--out", "/root/home.request")
	homeFP := fpOf(t, r.Out, "your fingerprint: ")
	if s := status(t, home); s.Initialized {
		t.Fatal("join alone made the node a member")
	}
	if home.Sh("ip link show meshly0").Code == 0 {
		t.Fatal("join created the interface before approval")
	}
	req := home.ReadFile("/root/home.request")

	// A second candidate with the same invite.
	third.WriteFile("/root/home.invite", inv)
	r = third.MustMeshly("join", "/root/home.invite", "--name", "intruder", "--expect-fingerprint", vpsFP, "--out", "/root/x.request")
	thirdFP := fpOf(t, r.Out, "your fingerprint: ")
	thirdReq := third.ReadFile("/root/x.request")

	// A modified request is rejected; approval needs the right fingerprint.
	vps.WriteFile("/root/bad.request", tamper(t, req))
	vps.ExpectCode(4, "approve", "/root/bad.request", "--expect-fingerprint", homeFP)
	vps.WriteFile("/root/home.request", req)
	vps.ExpectCode(10, "approve", "/root/home.request")
	vps.ExpectCode(10, "approve", "/root/home.request", "--expect-fingerprint", thirdFP)
	if s := vps.MustSh("wg show meshly0 peers"); strings.TrimSpace(s) != "" {
		t.Fatal("peer added without approval")
	}
	vps.MustMeshly("approve", "/root/home.request", "--expect-fingerprint", homeFP, "--out", "/root/home.accept")

	// The invite is used up: the second request is refused even after the
	// first peer is gone.
	vps.WriteFile("/root/x.request", thirdReq)
	if r := vps.ExpectCode(4, "approve", "/root/x.request", "--expect-fingerprint", thirdFP); !strings.Contains(r.Err, "one-time") {
		t.Fatalf("second request on one invite: %s", r)
	}
	acc := vps.ReadFile("/root/home.accept")

	// The accept only activates the node whose request it answers.
	third.WriteFile("/root/home.accept", acc)
	third.ExpectCode(4, "activate", "/root/home.accept")
	home.WriteFile("/root/bad.accept", tamper(t, acc))
	home.ExpectCode(4, "activate", "/root/bad.accept")
	home.WriteFile("/root/home.accept", acc)
	home.MustMeshly("activate", "/root/home.accept")
	l.WaitHandshake(home, 20*time.Second)

	vps.MustMeshly("revoke", "home", "--yes")
	r = vps.ExpectCode(4, "approve", "/root/x.request", "--expect-fingerprint", thirdFP)
	if !strings.Contains(r.Err, "one-time") {
		t.Fatalf("reuse not reported as such: %s", r)
	}
	r = vps.ExpectCode(4, "approve", "/root/home.request", "--expect-fingerprint", homeFP)
	if !strings.Contains(r.Err, "revoked") {
		t.Fatalf("re-approval of a revoked node: %s", r)
	}

	// Secrets never appear in output or in files meant to be copied.
	priv := strings.TrimSpace(vps.MustSh("cat /etc/meshly/keys/wireguard.key"))
	idPriv := strings.TrimSpace(vps.MustSh("cat /etc/meshly/keys/identity.key"))
	for _, out := range []string{
		vps.MustMeshly("status", "--json").Out, vps.MustMeshly("status").Out,
		vps.Meshly("doctor", "--json").Out, vps.MustMeshly("logs", "--json").Out,
		string(inv), string(acc), vps.MustSh("cat /etc/meshly/meshly.json /var/lib/meshly/*.json* /var/lib/meshly/history/* 2>/dev/null"),
	} {
		if strings.Contains(out, priv) || strings.Contains(out, idPriv) {
			t.Fatal("a private key appears in output or a shareable file")
		}
	}
	if perm := strings.TrimSpace(vps.MustSh("stat -c %a /etc/meshly/keys /etc/meshly/keys/wireguard.key /etc/meshly/keys/identity.key | tr '\\n' ' '")); perm != "700 600 600" {
		t.Fatalf("key permissions: %s", perm)
	}
	if out := vps.MustSh("ps -eo args"); strings.Contains(out, priv) {
		t.Fatal("private key in a process argument vector")
	}
}

// Invites expire.
func TestInviteExpiry(t *testing.T) {
	if os.Getenv("MESHLY_IT_SHORT") != "" {
		t.Skip("MESHLY_IT_SHORT set")
	}
	l := newLab(t, distros[0])
	vps, home := l.Node("vps"), l.Node("home")
	r := vps.MustMeshly("init", "homelab", "--name", "vps", "--endpoint", "198.51.100.10:51820")
	vpsFP := fingerprint(t, r.Out)
	vps.MustMeshly("invite", "--ttl", "1m", "--out", "/root/home.invite")
	Transfer(vps, "/root/home.invite", home, "/root/home.invite")
	r = home.MustMeshly("join", "/root/home.invite", "--name", "home", "--expect-fingerprint", vpsFP, "--out", "/root/home.request")
	Transfer(home, "/root/home.request", vps, "/root/home.request")
	time.Sleep(65 * time.Second)
	r = vps.ExpectCode(4, "approve", "/root/home.request", "--expect-fingerprint", fpOf(t, r.Out, "your fingerprint: "))
	if !strings.Contains(r.Err, "expire") {
		t.Fatalf("expiry not reported: %s", r)
	}
}

// Without --endpoint, init finds the public address on the interface with
// the default route; a node behind NAT advertises none.
func TestEndpointDetected(t *testing.T) {
	l := newLab(t, distros[0])
	vps, home := l.Node("vps"), l.Node("home")
	endpoint := func(n *Node) string {
		t.Helper()
		var s struct {
			Config struct {
				Endpoint string `json:"endpoint"`
			} `json:"config"`
		}
		r := n.MustMeshly("status", "--json")
		if err := json.Unmarshal([]byte(r.Out), &s); err != nil {
			t.Fatalf("status --json: %v\n%s", err, r.Out)
		}
		return s.Config.Endpoint
	}
	// The lab's wan is an internal Docker network without a gateway; give
	// the vps the default route a real server has.
	vps.MustSh("ip route replace default via 198.51.100.2")
	r := vps.MustMeshly("init", "homelab", "--name", "vps")
	if !strings.Contains(r.Out, "198.51.100.10:51820, detected on eth0") || endpoint(vps) != "198.51.100.10:51820" {
		t.Fatalf("vps endpoint %q, init output:\n%s", endpoint(vps), r.Out)
	}
	r = home.MustMeshly("init", "homelab", "--name", "home")
	if !strings.Contains(r.Out, "no public IPv4 address") || endpoint(home) != "" {
		t.Fatalf("home endpoint %q, init output:\n%s", endpoint(home), r.Out)
	}
}
