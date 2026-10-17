package diag

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nikitakiselev/meshly/internal/model"
	"github.com/nikitakiselev/meshly/internal/preflight"
	"github.com/nikitakiselev/meshly/internal/store"
)

// DoctorSchema identifies the JSON layout of Doctor.
const DoctorSchema = "meshly.doctor/v1"

// Finding is one diagnosis. Certainty says whether the cause is an
// observed fact or an inference.
type Finding struct {
	ID        string `json:"id"`
	Status    string `json:"status"` // ok, info, warn, fail
	Certainty string `json:"certainty,omitempty"`
	Detail    string `json:"detail"`
	Fix       string `json:"fix,omitempty"`
}

// Certainty levels.
const (
	Fact     = "observed"
	Likely   = "likely"
	Possible = "possible"
)

// Doctor is the doctor report.
type Doctor struct {
	Schema   string    `json:"schema"`
	Findings []Finding `json:"findings"`
	Summary  string    `json:"summary"`
}

func (d *Doctor) add(id, status, certainty, detail, fix string) {
	d.Findings = append(d.Findings, Finding{ID: id, Status: status, Certainty: certainty, Detail: detail, Fix: fix})
}

// Worst returns the most severe status.
func (d *Doctor) Worst() string {
	w := "ok"
	rank := map[string]int{"ok": 0, "info": 0, "warn": 1, "fail": 2}
	for _, f := range d.Findings {
		if rank[f.Status] > rank[w] {
			w = f.Status
		}
	}
	return w
}

// Probe is an optional active check of a service on the peer.
type Probe struct {
	Peer  string
	Proto model.Proto
	Port  uint16
}

// RunDoctor performs all checks. It opens no listening port.
func RunDoctor(ctx context.Context, d Deps, sys *preflight.System, probe *Probe) *Doctor {
	doc := &Doctor{Schema: DoctorSchema, Findings: []Finding{}}
	rep := &preflight.Report{}
	sys.Base(ctx, rep)
	for _, c := range rep.Checks {
		doc.add(c.ID, string(c.Status), Fact, c.Detail, c.Fix)
	}
	cfg, err := d.Paths.LoadConfig()
	if errors.Is(err, store.ErrNotInitialized) {
		doc.add("config", "info", Fact, "meshly is not initialized on this node", "meshly init <network> --name <node>   or   sudo meshly join")
		return finish(doc)
	}
	if err != nil {
		doc.add("config", "fail", Fact, err.Error(), "restore /etc/meshly/meshly.json from /var/lib/meshly/history/ or run `meshly reset`")
		return finish(doc)
	}
	doc.add("config", "ok", Fact, fmt.Sprintf("configuration revision %d is valid (admin state %s)", cfg.Revision, cfg.AdminState), "")
	if d.Privileged {
		if keys, err := d.Paths.LoadKeys(); err != nil {
			doc.add("keys", "fail", Fact, err.Error(), "keys must be root-owned 0600 files in /etc/meshly/keys (0700)")
		} else {
			if keys.WGPublic() != cfg.Self.WGPublicKey {
				doc.add("keys", "fail", Fact, "the key file does not match the public key in the configuration", "restore the original key; changing the key requires pairing again (meshly reset, then join again)")
			} else {
				doc.add("keys", "ok", Fact, "key files are private and match the configuration", "")
			}
			keys.Wipe()
		}
	}
	frep := &preflight.Report{}
	if d.Privileged {
		sys.Firewall(ctx, frep, cfg, true)
		for _, c := range frep.Checks {
			doc.add(c.ID, string(c.Status), Fact, c.Detail, c.Fix)
		}
		checkNftablesService(ctx, doc, d, cfg)
	}
	st := Collect(ctx, d)
	if st.Service != nil {
		switch {
		case !st.Service.Systemd:
			doc.add("service", "warn", Fact, "systemd is not available: no autostart", "")
		case !st.Service.Installed:
			doc.add("service", "warn", Fact, "meshly.service is not installed", "run `meshly start` to install and enable it")
		case st.Service.Enabled != "enabled":
			doc.add("service", "warn", Fact, "meshly.service is "+st.Service.Enabled+": the link will not come back after reboot", "meshly start")
		case cfg.AdminState == model.AdminUp && st.Service.Active != "active":
			doc.add("service", "warn", Fact, "meshly.service is "+st.Service.Active+" (systemd active state is independent of connectivity)", "meshly start; journalctl -u meshly")
		default:
			doc.add("service", "ok", Fact, fmt.Sprintf("meshly.service %s/%s, check timer %s", st.Service.Active, st.Service.Enabled, st.Service.TimerActive), "")
		}
	}
	if st.Transaction.Incomplete {
		doc.add("transaction", "fail", Fact, fmt.Sprintf("operation %q (%s) did not finish", st.Transaction.IncompleteOp, st.Transaction.IncompleteID), "run `meshly recover` (any mutating command also recovers first)")
	} else if st.Transaction.LastEvent == "safe-mode" || st.Transaction.LastEvent == "rolled-back" {
		doc.add("transaction", "warn", Fact, fmt.Sprintf("last operation %q ended with %s: %s", st.Transaction.LastOp, st.Transaction.LastEvent, st.Transaction.LastDetail), "fix the cause and repeat the operation; `meshly start` re-applies the configuration")
	} else {
		doc.add("transaction", "ok", Fact, "no interrupted operation", "")
	}
	if cfg.AdminState != model.AdminUp {
		doc.add("link", "info", Fact, "the link is stopped by the administrator (meshly stop)", "meshly start")
		return finish(doc)
	}
	if !d.Privileged {
		doc.add("privileges", "warn", Fact, "not running as root: kernel state cannot be inspected", "sudo meshly doctor")
		return finish(doc)
	}
	if len(st.Drift) > 0 {
		doc.add("drift", "fail", Fact, "kernel state differs from the configuration: "+strings.Join(st.Drift, "; "), "meshly start   (re-applies the saved configuration)")
	} else {
		doc.add("drift", "ok", Fact, "interface, WireGuard, routes and firewall match the configuration", "")
	}
	if st.Interface != nil && st.Interface.ForeignRoutes > 0 {
		doc.add("routes", "warn", Fact, fmt.Sprintf("%d route(s) on %s were not created by meshly (traffic to them is dropped by the policy)", st.Interface.ForeignRoutes, cfg.Interface.Name), "remove them: ip route show dev "+cfg.Interface.Name)
	}
	checkMTU(doc, cfg)
	if len(cfg.Peers) == 0 {
		doc.add("peer", "info", Fact, "no peer yet", "run `sudo meshly invite` on this node and `sudo meshly join` on the other")
	}
	for _, p := range st.Peers {
		peerFindings(doc, cfg, st, p)
	}
	listenerFindings(doc, cfg)
	if probe != nil {
		runProbe(ctx, doc, cfg, st, *probe)
	}
	return finish(doc)
}

func finish(doc *Doctor) *Doctor {
	switch doc.Worst() {
	case "fail":
		doc.Summary = "problems found"
	case "warn":
		doc.Summary = "working with warnings"
	default:
		doc.Summary = "no problems found"
	}
	return doc
}

func peerFindings(doc *Doctor, cfg *model.Config, st *Status, p PeerInfo) {
	id := "peer:" + p.Name
	if !p.InWireGuard {
		doc.add(id, "fail", Fact, "peer is missing from the WireGuard interface", "meshly start")
		return
	}
	weListen := cfg.Self.Endpoint.IsValid() || p.ConfiguredEndpoint == ""
	switch p.Connectivity {
	case "handshake-recent":
		doc.add(id, "ok", Fact, fmt.Sprintf("handshake %ds ago, endpoint %s, rx %d B, tx %d B", *p.HandshakeAge, p.CurrentEndpoint, p.RxBytes, p.TxBytes), "")
	case "handshake-stale":
		msg := fmt.Sprintf("last handshake %ds ago (idle or peer unreachable)", *p.HandshakeAge)
		if p.Keepalive == 0 && weListen {
			doc.add(id, "info", Likely, msg+"; this node does not send keepalives, so an idle link looks stale", "")
		} else {
			doc.add(id, "warn", Possible, msg+"; the peer may be down, or UDP is blocked", "check the peer: `meshly status` there")
		}
	case "no-handshake":
		transport := st.Firewall != nil && st.Firewall.TransportPkts != nil
		switch {
		case weListen && transport && *st.Firewall.TransportPkts == 0:
			doc.add(id, "fail", Fact,
				fmt.Sprintf("no WireGuard UDP packet reached this host on port %d since the firewall table was loaded (%s)", cfg.Self.ListenPort, st.Firewall.AppliedAt.Format(time.RFC3339)),
				"the peer is not running meshly yet, or UDP is blocked before this host: check the cloud security group / provider firewall / router port forwarding for UDP "+strconv.Itoa(int(cfg.Self.ListenPort))+" (meshly does not manage them)")
		case weListen && transport:
			doc.add(id, "fail", Likely,
				fmt.Sprintf("%d UDP packets arrived on port %d but no handshake completed", *st.Firewall.TransportPkts, cfg.Self.ListenPort),
				"the packets are not from this peer's key (wrong peer, peer reset its keys) — compare the WireGuard public keys shown by `meshly status` on both nodes")
		case p.TxBytes > 0 && p.RxBytes == 0:
			doc.add(id, "fail", Possible,
				fmt.Sprintf("handshake initiations are sent to %s but nothing comes back", p.ConfiguredEndpoint),
				"possible causes (meshly cannot tell them apart from here): the peer is down, UDP is blocked on the path or by the peer's cloud firewall, the endpoint is wrong (`meshly set peer-endpoint`), or the peer revoked this node")
		default:
			doc.add(id, "warn", Possible, "no handshake yet and no traffic was attempted", "generate traffic (e.g. `meshly doctor --probe 22/tcp`) or wait for keepalive")
		}
	}
	if st.Firewall != nil && st.Firewall.DeniedPkts != nil && *st.Firewall.DeniedPkts > 0 {
		doc.add("policy", "info", Fact, fmt.Sprintf("%d packet(s) from the VPN were dropped by the default-deny policy since %s (connections to services that are not allowed)", *st.Firewall.DeniedPkts, st.Firewall.AppliedAt.Format(time.RFC3339)), "if a peer needs a service here: meshly allow <port>/<proto> from <peer>")
	}
}

// listenerFindings checks, for each allow rule, whether a local socket
// listens where the peer can reach it (facts from /proc/net).
func listenerFindings(doc *Doctor, cfg *model.Config) {
	for _, r := range cfg.Rules {
		if r.Proto == model.ProtoPing {
			continue
		}
		addrs := listeningAddrs(r.Proto, r.Port)
		id := "service:" + r.Service()
		reachable := false
		for _, a := range addrs {
			if a.IsUnspecified() || a == cfg.Self.Address {
				reachable = true
			}
		}
		switch {
		case reachable:
			doc.add(id, "ok", Fact, fmt.Sprintf("a service listens on %s and is allowed from %s", r.Service(), r.Peer), "")
		case len(addrs) > 0:
			var s []string
			for _, a := range addrs {
				s = append(s, a.String())
			}
			doc.add(id, "warn", Fact, fmt.Sprintf("%s is allowed but the service listens only on %s, not on %s", r.Service(), strings.Join(s, ", "), cfg.Self.Address), "bind the service to "+cfg.Self.Address.String()+" or 0.0.0.0")
		default:
			doc.add(id, "warn", Fact, fmt.Sprintf("%s is allowed from %s but no service is listening on that port", r.Service(), r.Peer), "start the service")
		}
	}
}

func listeningAddrs(proto model.Proto, port uint16) []netip.Addr {
	files := []string{"/proc/net/tcp", "/proc/net/tcp6"}
	state := "0A"
	if proto == model.ProtoUDP {
		files, state = []string{"/proc/net/udp", "/proc/net/udp6"}, "07"
	}
	var out []netip.Addr
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		lines := bytes.Split(b, []byte("\n"))
		for _, l := range lines[1:] {
			fs := strings.Fields(string(l))
			if len(fs) < 4 || fs[3] != state {
				continue
			}
			hexAddr, hexPort, ok := strings.Cut(fs[1], ":")
			if !ok {
				continue
			}
			p, err := strconv.ParseUint(hexPort, 16, 16)
			if err != nil || uint16(p) != port {
				continue
			}
			if a, ok := parseProcAddr(hexAddr); ok {
				out = append(out, a)
			}
		}
	}
	return out
}

func parseProcAddr(h string) (netip.Addr, bool) {
	b := make([]byte, len(h)/2)
	for i := range b {
		v, err := strconv.ParseUint(h[2*i:2*i+2], 16, 8)
		if err != nil {
			return netip.Addr{}, false
		}
		b[i] = byte(v)
	}
	// /proc stores addresses as host-order 32-bit words.
	for i := 0; i+4 <= len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	a, ok := netip.AddrFromSlice(b)
	return a.Unmap(), ok
}

func checkMTU(doc *Doctor, cfg *model.Config) {
	ifs, err := net.Interfaces()
	if err != nil {
		return
	}
	minOuter := 0
	for _, i := range ifs {
		if i.Name == cfg.Interface.Name || i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 {
			continue
		}
		if addrs, _ := i.Addrs(); len(addrs) == 0 {
			continue
		}
		if minOuter == 0 || i.MTU < minOuter {
			minOuter = i.MTU
		}
	}
	if minOuter > 0 && cfg.Interface.MTU > minOuter-80 {
		doc.add("mtu", "warn", Likely, fmt.Sprintf("interface MTU %d is larger than the smallest outer MTU %d minus WireGuard overhead (80)", cfg.Interface.MTU, minOuter), fmt.Sprintf("meshly set mtu %d   (on both nodes)", minOuter-80))
	}
}

func checkNftablesService(ctx context.Context, doc *Doctor, d Deps, cfg *model.Config) {
	b, err := os.ReadFile("/etc/nftables.conf")
	if err != nil || !bytes.Contains(b, []byte("flush ruleset")) {
		return
	}
	if d.Systemd == nil || !d.Systemd.Available {
		return
	}
	if _, enabled := d.Systemd.State(ctx, "nftables.service"); enabled != "enabled" {
		return
	}
	sev, msg := "info", "/etc/nftables.conf contains `flush ruleset`: starting or reloading nftables removes the meshly table for a moment until meshly re-applies it (automatic)"
	if cfg.Firewall.Profile == model.ProfileNone {
		sev = "warn"
		msg += "; with profile none the VPN is unprotected during that short window"
	} else {
		msg += "; with profile nftables VPN traffic is dropped (fail-closed) during that window"
	}
	doc.add("nftables-reload", sev, Fact, msg, "prefer `table inet filter; delete table inet filter` over `flush ruleset` in /etc/nftables.conf")
}

func runProbe(ctx context.Context, doc *Doctor, cfg *model.Config, st *Status, pr Probe) {
	p, ok := cfg.Peer(pr.Peer)
	if !ok {
		doc.add("probe", "fail", Fact, "unknown peer "+pr.Peer, "")
		return
	}
	id := fmt.Sprintf("probe:%d/%s", pr.Port, pr.Proto)
	target := netip.AddrPortFrom(p.Address, pr.Port).String()
	recent := false
	for _, pi := range st.Peers {
		if pi.Name == p.Name && pi.Connectivity == "handshake-recent" {
			recent = true
		}
	}
	dialer := net.Dialer{Timeout: 3 * time.Second, LocalAddr: localAddr(pr.Proto, cfg.Self.Address)}
	switch pr.Proto {
	case model.ProtoTCP:
		c, err := dialer.DialContext(ctx, "tcp", target)
		switch {
		case err == nil:
			c.Close()
			doc.add(id, "ok", Fact, "connected to "+target+" through the VPN", "")
		case errors.Is(err, syscall.ECONNREFUSED):
			doc.add(id, "warn", Likely, target+" refused the connection: the peer allows the port but no service listens there", "start the service on "+p.Name)
		case recent:
			doc.add(id, "fail", Likely, target+" timed out although the link has a recent handshake: the peer's policy does not allow this port", fmt.Sprintf("on %s run: meshly allow %d/tcp from %s", p.Name, pr.Port, cfg.Self.Name))
		default:
			doc.add(id, "fail", Possible, target+" timed out and there is no recent handshake: the peer may be down or unreachable", "see the peer findings above")
		}
	case model.ProtoUDP:
		c, err := dialer.DialContext(ctx, "udp", target)
		if err != nil {
			doc.add(id, "fail", Fact, err.Error(), "")
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = c.Write([]byte("meshly-probe\n"))
		buf := make([]byte, 64)
		_, err = c.Read(buf)
		switch {
		case err == nil:
			doc.add(id, "ok", Fact, target+" answered through the VPN", "")
		case errors.Is(err, syscall.ECONNREFUSED):
			doc.add(id, "warn", Likely, target+" reported port unreachable: allowed by the peer but nothing listens", "start the service on "+p.Name)
		default:
			doc.add(id, "info", Possible, target+": no answer; for UDP this is inconclusive (the service may not reply, or the port is not allowed)", fmt.Sprintf("on %s check: meshly rules", p.Name))
		}
	default:
		doc.add(id, "fail", Fact, "probes support tcp and udp", "")
	}
}

func localAddr(proto model.Proto, a netip.Addr) net.Addr {
	if proto == model.ProtoUDP {
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(a, 0))
	}
	return net.TCPAddrFromAddrPort(netip.AddrPortFrom(a, 0))
}
