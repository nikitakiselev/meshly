// Package preflight verifies system capabilities before Meshly changes
// anything: kernel WireGuard, nftables, privileges, systemd, unsupported
// firewall managers, foreign firewall compatibility and conflicts of
// addresses, interfaces and ports. It checks capabilities, not distribution
// names.
package preflight

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/nikitakiselev/meshly/internal/model"
	"github.com/nikitakiselev/meshly/internal/nft"
	"golang.org/x/sys/unix"
)

// Status of a check.
type Status string

const (
	OK   Status = "ok"
	Warn Status = "warn"
	Fail Status = "fail"
	Info Status = "info"
)

// Check is one preflight result.
type Check struct {
	ID     string `json:"id"`
	Status Status `json:"status"`
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

// Report is a list of checks.
type Report struct {
	Checks []Check `json:"checks"`
}

func (r *Report) add(id string, st Status, detail, fix string) {
	r.Checks = append(r.Checks, Check{ID: id, Status: st, Detail: detail, Fix: fix})
}

// Failures returns failed checks.
func (r *Report) Failures() []Check {
	var out []Check
	for _, c := range r.Checks {
		if c.Status == Fail {
			out = append(out, c)
		}
	}
	return out
}

// Error summarises failures, or nil.
func (r *Report) Error() error {
	f := r.Failures()
	if len(f) == 0 {
		return nil
	}
	var b strings.Builder
	b.WriteString("preflight failed, nothing was changed:")
	for _, c := range f {
		fmt.Fprintf(&b, "\n  ✗ %s: %s", c.ID, c.Detail)
		if c.Fix != "" {
			fmt.Fprintf(&b, "\n    fix: %s", c.Fix)
		}
	}
	return &Error{msg: b.String(), Report: r}
}

// Error is a preflight failure.
type Error struct {
	msg    string
	Report *Report
}

func (e *Error) Error() string { return e.msg }

// Links is the subset of netstack used here.
type Links interface {
	UsedPrefixes(exclude string) ([]model.UsedPrefix, error)
	LocalAddrs() ([]netip.Addr, error)
	DefaultRouteAddrs() ([]model.LinkAddr, error)
	LinkExists(name string) (exists, owned bool, kind string, err error)
}

// System gives access to the host; replaceable in tests.
type System struct {
	NFT      nft.Client
	Links    Links
	Root     string // filesystem root for /proc, /sys, /etc lookups ("/")
	Euid     int
	Exec     func(ctx context.Context, path string, args ...string) ([]byte, error)
	Systemd  bool // PID 1 is systemd
	KernelRe string
}

// NewSystem returns the production system view.
func NewSystem(n nft.Client, l Links) *System {
	var uts unix.Utsname
	_ = unix.Uname(&uts)
	_, err := os.Stat("/run/systemd/system")
	return &System{
		NFT: n, Links: l, Root: "/", Euid: os.Geteuid(), Exec: runFixed,
		Systemd: err == nil, KernelRe: unix.ByteSliceToString(uts.Release[:]),
	}
}

func runFixed(ctx context.Context, path string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	return cmd.Output()
}

func (s *System) path(p string) string { return filepath.Join(s.Root, p) }

// Base checks the capabilities every mutating command needs.
func (s *System) Base(ctx context.Context, r *Report) {
	if runtime.GOOS != "linux" {
		r.add("os", Fail, "meshly manages Linux kernel networking only", "")
		return
	}
	if s.Euid != 0 {
		r.add("privileges", Fail, "this command changes network configuration and must run as root", "run it with sudo")
	} else {
		r.add("privileges", OK, "running as root", "")
	}
	s.checkWireGuard(r)
	s.checkNft(ctx, r)
	if s.Systemd {
		r.add("systemd", OK, "systemd is the init system", "")
	} else {
		r.add("systemd", Warn, "systemd is not running: autostart after reboot is not available", "on supported systems (Debian 12, Ubuntu 24.04) systemd is PID 1")
	}
}

func (s *System) checkWireGuard(r *Report) {
	if _, err := os.Stat(s.path("/sys/module/wireguard")); err == nil {
		r.add("wireguard", OK, "kernel WireGuard module is loaded", "")
		return
	}
	modDir := s.path("/lib/modules/" + s.KernelRe)
	for _, f := range []string{"modules.builtin", "modules.dep"} {
		b, err := os.ReadFile(filepath.Join(modDir, f))
		if err == nil && bytes.Contains(b, []byte("/wireguard.ko")) {
			r.add("wireguard", OK, "kernel WireGuard module is available ("+f+")", "")
			return
		}
	}
	r.add("wireguard", Fail, "kernel WireGuard is not available for kernel "+s.KernelRe,
		"install the distribution kernel (Debian 12 / Ubuntu 24.04 include WireGuard) or run `modprobe wireguard`; meshly does not install packages itself")
}

func (s *System) checkNft(ctx context.Context, r *Report) {
	if _, err := os.Stat(s.path(nft.Binary)); err != nil {
		r.add("nftables", Fail, nft.Binary+" not found", "apt install nftables")
		return
	}
	v, err := nft.Version(ctx, s.NFT.R)
	if err != nil {
		r.add("nftables", Fail, err.Error(), "apt install --reinstall nftables")
		return
	}
	vs := fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2])
	if !nft.VersionAtLeast(v, nft.MinVersion) {
		r.add("nftables", Fail, "nftables "+vs+" is older than the supported 1.0.6", "upgrade to Debian 12 / Ubuntu 24.04 nftables")
		return
	}
	r.add("nftables", OK, "nftables "+vs, "")
}

// Managers detects firewall managers: firewalld and legacy iptables are
// refused, UFW is reported.
func (s *System) Managers(ctx context.Context, r *Report, a *nft.Analysis) {
	firewalld := a != nil && a.FirewalldTables
	if _, err := os.Stat(s.path("/run/firewalld/firewalld.pid")); err == nil {
		firewalld = true
	}
	if s.Systemd && s.Exec != nil {
		if out, _ := s.Exec(ctx, "/usr/bin/systemctl", "is-active", "firewalld.service"); strings.TrimSpace(string(out)) == "active" {
			firewalld = true
		}
	}
	if firewalld {
		r.add("firewall-manager", Fail, "firewalld is active; meshly has no firewalld adapter in this version",
			"stop and disable firewalld (systemctl disable --now firewalld) and manage nftables natively, or do not use meshly on this host")
	}
	if a != nil && a.Fail2ban {
		r.add("fail2ban", Info, "fail2ban is active: the addresses it bans stay banned for traffic through meshly", "")
	}
	if a != nil && a.UFWChains || s.UFWEnabled() {
		r.add("ufw", Info, "UFW is enabled: meshly keeps its rule at the top of the iptables INPUT and OUTPUT chains, and UFW decides all other traffic", "")
	}
	for _, f := range []string{"/proc/net/ip_tables_names", "/proc/net/ip6_tables_names"} {
		b, err := os.ReadFile(s.path(f))
		if err != nil || len(bytes.TrimSpace(b)) == 0 {
			continue
		}
		save := "/usr/sbin/iptables-legacy-save"
		if strings.Contains(f, "ip6") {
			save = "/usr/sbin/ip6tables-legacy-save"
		}
		out, err := []byte(nil), fmt.Errorf("not installed")
		if _, serr := os.Stat(s.path(save)); serr == nil && s.Exec != nil {
			out, err = s.Exec(ctx, save)
		}
		if err != nil {
			r.add("iptables-legacy", Fail, "legacy iptables tables exist ("+strings.Join(strings.Fields(string(b)), ", ")+") and cannot be inspected",
				"remove legacy iptables rules or install iptables to let meshly inspect them")
			continue
		}
		if legacyHasRules(out) {
			r.add("iptables-legacy", Fail, "legacy iptables (xtables) rules are present; meshly cannot integrate with them",
				"switch iptables (and UFW, which uses it) to the nftables backend: update-alternatives --set iptables /usr/sbin/iptables-nft and --set ip6tables /usr/sbin/ip6tables-nft, then reload the rules; meshly never migrates firewalls itself")
		}
	}
	if !firewalld {
		r.add("firewall-manager", OK, "no unsupported firewall manager detected", "")
	}
}

// SavedIptablesRules lists the files of netfilter-persistent that contain
// meshly's rule for the iptables chains.
func (s *System) SavedIptablesRules() []string {
	var out []string
	for _, f := range []string{"/etc/iptables/rules.v4", "/etc/iptables/rules.v6"} {
		if b, err := os.ReadFile(s.path(f)); err == nil && bytes.Contains(b, []byte(nft.IptablesComment)) {
			out = append(out, f)
		}
	}
	return out
}

// UFWEnabled reports whether UFW is enabled in its configuration.
func (s *System) UFWEnabled() bool {
	b, err := os.ReadFile(s.path("/etc/ufw/ufw.conf"))
	return err == nil && ufwEnabled(b)
}

func ufwEnabled(b []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(l, "ENABLED=") {
			v := strings.Trim(strings.TrimPrefix(l, "ENABLED="), `"'`)
			return strings.EqualFold(v, "yes")
		}
	}
	return false
}

func legacyHasRules(save []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(save))
	for sc.Scan() {
		l := sc.Text()
		if strings.HasPrefix(l, "-A ") {
			return true
		}
		if strings.HasPrefix(l, ":") {
			f := strings.Fields(l)
			if len(f) >= 2 && f[1] != "ACCEPT" && f[1] != "-" {
				return true
			}
		}
	}
	return false
}

// AnalysisContext builds the nft analysis context for a config.
func (s *System) AnalysisContext(c *model.Config) nft.Context {
	ctx := nft.Context{Interface: c.Interface.Name, LocalVPN: c.Self.Address, ListenPort: c.Self.ListenPort, Mark: c.Firewall.Mark,
		Network: c.Network.CIDR}
	for _, p := range c.Peers {
		ctx.Peers = append(ctx.Peers, p.Address)
		if p.Endpoint.IsValid() {
			ctx.Endpoints = append(ctx.Endpoints, p.Endpoint.Addr())
		}
	}
	if s.Links != nil {
		ctx.LocalAddrs, _ = s.Links.LocalAddrs()
	}
	return ctx
}

// Firewall analyses the live ruleset for cfg and evaluates the profile.
// strict=false downgrades compatibility failures to warnings (used for
// access-reducing operations, which must never be blocked).
func (s *System) Firewall(ctx context.Context, r *Report, c *model.Config, strict bool) *nft.Analysis {
	rs, err := s.NFT.ListRuleset(ctx)
	if err != nil {
		r.add("nftables-ruleset", Fail, "cannot read the nftables ruleset: "+err.Error(), "check that nf_tables is available in the kernel")
		return nil
	}
	a := nft.Analyze(rs, s.AnalysisContext(c))
	s.Managers(ctx, r, a)
	EvaluateFirewall(r, a, c.Firewall.Profile, c.Firewall.Mark, strict)
	Bans(r, a, c)
	return a
}

// Bans warns about peers listed in a ban list, such as fail2ban's. The
// ban drops their traffic on purpose, so it never blocks an operation.
func Bans(r *Report, a *nft.Analysis, c *model.Config) {
	for _, ch := range a.Chains {
		for _, b := range ch.Bans {
			for _, addr := range b.Addrs {
				who := addr.String() + " (an address of the VPN network)"
				for _, p := range c.Peers {
					switch {
					case p.Address == addr:
						who = addr.String() + " (peer " + p.Name + ")"
					case p.Endpoint.Addr().Unmap() == addr:
						who = addr.String() + " (endpoint of peer " + p.Name + ")"
					}
				}
				if b.Fail2ban(ch.Table) {
					r.add("firewall-ban", Warn, fmt.Sprintf("fail2ban has banned %s in set %s of table %s %s: its traffic through meshly is dropped until the ban ends", who, b.Set, ch.Family, ch.Table),
						fmt.Sprintf("sudo fail2ban-client unban %s   (to never ban it, add it to ignoreip in /etc/fail2ban/jail.local)", addr))
					continue
				}
				r.add("firewall-ban", Warn, fmt.Sprintf("set %s in table %s %s lists %s: chain %s drops its traffic through meshly", b.Set, ch.Family, ch.Table, who, ch.Chain),
					fmt.Sprintf("sudo nft delete element %s %s %s { %s }", ch.Family, ch.Table, b.Set, addr))
			}
		}
	}
}

// EvaluateFirewall turns an analysis into checks for a profile.
func EvaluateFirewall(r *Report, a *nft.Analysis, profile string, mark uint32, strict bool) {
	fail := Fail
	if !strict {
		fail = Warn
	}
	rule := nft.IntegrationRule(mark)
	if a.OurTablePresent && !a.OurTableOwned {
		r.add("firewall-table", Fail, "a table inet meshly exists but was not created by meshly", "rename or delete that table; meshly never takes over foreign objects")
	}
	for _, f := range a.Flowtables {
		r.add("flowtable", fail, "flowtable "+f+" offloads traffic of the meshly interface, which bypasses the policy", "remove the meshly interface from the flowtable devices")
	}
	for _, c := range a.Unsupported() {
		r.add("firewall-chain", fail, fmt.Sprintf("chain %s %s %s (hook %s): %s", c.Family, c.Table, c.Chain, c.Hook, c.Detail), "this firewall configuration is outside the supported profiles (see docs/firewall.md)")
	}
	needs := a.NeedsIntegration()
	for _, c := range needs {
		where := fmt.Sprintf("chain %s %s %s (hook %s, policy %s)", c.Family, c.Table, c.Chain, c.Hook, c.Policy)
		if c.Status == "misplaced-integration" {
			r.add("firewall-integration", fail, where+": "+c.Detail, "move the rule `"+rule+"` above the rules that drop or reject")
			continue
		}
		if profile == model.ProfileNone {
			r.add("firewall-integration", fail, where+" would drop meshly traffic: "+c.Detail+"; profile \"none\" requires a host without a filtering firewall",
				"use profile nftables (meshly init --firewall nftables) and add to that chain, before any drop/reject rule:\n      "+rule)
		} else {
			r.add("firewall-integration", fail, where+" has no meshly integration rule ("+c.Detail+")",
				"add to that chain in /etc/nftables.conf, before any drop/reject rule, then reload nftables:\n      "+rule)
		}
	}
	integrated := 0
	for _, c := range a.Chains {
		if c.Status == "integrated" && !c.ByMeshly {
			integrated++
		}
	}
	if ipt := a.ByMeshly(); len(ipt) > 0 {
		var names []string
		for _, c := range ipt {
			names = append(names, c.Family+" "+c.Table+" "+c.Chain)
		}
		r.add("firewall-iptables", Info, "iptables chains "+strings.Join(names, ", ")+" filter traffic: meshly keeps its rule at the top of them, so only what meshly's policy accepts passes them", "")
	}
	if len(needs) == 0 && len(a.Unsupported()) == 0 {
		switch {
		case profile == model.ProfileNftables && integrated == 0:
			r.add("firewall-profile", Warn, "profile nftables is configured but no native nftables chain needs integration", "")
		case profile == model.ProfileNftables:
			r.add("firewall-profile", OK, fmt.Sprintf("native nftables profile: integration rule present in %d chain(s)", integrated), "")
		default:
			r.add("firewall-profile", OK, "no native nftables chain affects meshly traffic (profile none)", "")
		}
	}
	if a.DockerDetected {
		r.add("docker", Info, fmt.Sprintf("Docker rules detected (%d DNAT rules): published container ports are NOT reachable through the VPN; forwarding and DNAT from the VPN are blocked", a.DNATRules), "")
	}
	for _, c := range a.NetdevChains {
		r.add("netdev", Warn, c+" exists; netdev hooks run before meshly and may drop WireGuard transport", "")
	}
}

// AutoProfile chooses a profile from an analysis.
func AutoProfile(a *nft.Analysis) string {
	for _, c := range a.Chains {
		if !c.ByMeshly && (c.Status == "integrated" || c.Status == "needs-integration" || c.Status == "misplaced-integration") {
			return model.ProfileNftables
		}
	}
	return model.ProfileNone
}

// Conflicts checks the VPN CIDR, the interface name and the listen port.
func (s *System) Conflicts(r *Report, cidr netip.Prefix, ifname string, listenPort uint16) {
	exists, owned, kind, err := s.Links.LinkExists(ifname)
	switch {
	case err != nil:
		r.add("interface", Fail, "cannot inspect interfaces: "+err.Error(), "")
	case exists && !owned:
		r.add("interface", Fail, fmt.Sprintf("interface %s already exists (type %s) and is not managed by meshly", ifname, kind), "choose another name with --interface")
	default:
		r.add("interface", OK, "interface name "+ifname+" is available", "")
	}
	used, err := s.Links.UsedPrefixes(ifname)
	if err != nil {
		r.add("addresses", Fail, "cannot inspect addresses and routes: "+err.Error(), "")
	} else if cs := model.FindConflicts(cidr, used); len(cs) > 0 {
		var parts []string
		for _, c := range cs {
			parts = append(parts, c.String())
		}
		fix := "choose another network with --cidr"
		if alt, ok := model.SuggestCIDR(used); ok {
			fix += fmt.Sprintf(" (for example --cidr %s)", alt)
		}
		r.add("addresses", Fail, fmt.Sprintf("VPN network %s overlaps existing addresses/routes: %s", cidr, strings.Join(parts, "; ")), fix)
	} else {
		r.add("addresses", OK, fmt.Sprintf("VPN network %s does not overlap local addresses or routes", cidr), "")
	}
	if listenPort != 0 {
		if inUse := s.UDPPortInUse(listenPort); inUse && !owned {
			r.add("listen-port", Fail, fmt.Sprintf("UDP port %d is already in use", listenPort), "choose another port with --listen-port")
		} else {
			r.add("listen-port", OK, fmt.Sprintf("UDP port %d is available", listenPort), "")
		}
	}
}

// UDPPortInUse parses /proc/net/udp{,6} for a bound local port.
func (s *System) UDPPortInUse(port uint16) bool {
	for _, f := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		for _, p := range LocalPorts(s.path(f), "") {
			if p == port {
				return true
			}
		}
	}
	return false
}

// LocalPorts lists local ports from a /proc/net/{tcp,udp}[6] table; with
// state set, only sockets in that hex state (e.g. "0A" = LISTEN).
func LocalPorts(path, state string) []uint16 {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []uint16
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 {
			continue
		}
		if state != "" && f[3] != state {
			continue
		}
		_, portHex, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		if p, err := strconv.ParseUint(portHex, 16, 16); err == nil {
			out = append(out, uint16(p))
		}
	}
	return out
}

// PickListenPort returns 51820 if free, else a free port in 49152-65535.
func (s *System) PickListenPort(randUint func() uint32) uint16 {
	if !s.UDPPortInUse(model.DefaultListenPort) {
		return model.DefaultListenPort
	}
	for i := 0; i < 64; i++ {
		p := uint16(49152 + randUint()%16384)
		if !s.UDPPortInUse(p) {
			return p
		}
	}
	return 0
}
