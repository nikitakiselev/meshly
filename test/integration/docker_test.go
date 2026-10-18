//go:build integration

package integration

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Containers through the tunnel with a real Docker daemon on the nodes
// (docs/firewall.md#docker): a port published by Docker opens to a peer
// with meshly allow, a container connects to a peer like a program on its
// host, and Docker networks that come and go are followed within seconds.
// Nothing else opens (TestDockerHostContained).

// FetchOK reports whether url answers "ok" to curl on the node.
func (n *Node) FetchOK(url string) bool {
	return strings.TrimSpace(n.Sh("curl -m 3 -s "+url).Out) == "ok"
}

// FetchOKFromContainer is FetchOK from a new container on network.
func (n *Node) FetchOKFromContainer(network, url string) bool {
	return strings.TrimSpace(n.FetchFromContainer(network, url).Out) == "ok"
}

// Connects reports whether a TCP connection to addr:port is established:
// for servers that send nothing first, like HTTP.
func (n *Node) Connects(addr string, port int) bool {
	return n.Sh(fmt.Sprintf("/opt/it/fileserver -connect -tcp-dial %s:%d -timeout 2s", addr, port)).Code == 0
}

// ServeHTTPHost serves "ok" over HTTP on port of the node itself.
func (n *Node) ServeHTTPHost(port int) {
	n.lab.t.Helper()
	n.MustSh(fmt.Sprintf("mkdir -p /srv/www && echo ok > /srv/www/index.html && nohup /opt/it/fileserver -serve-dir /srv/www -listen :%d >/dev/null 2>&1 &", port))
	n.WaitFor("http server on the host", 5*time.Second, func() bool { return n.FetchOK(fmt.Sprintf("http://127.0.0.1:%d/", port)) })
}

// ServeToken runs container name with the lab's token server (see Listen)
// on proto/port, published on hostPort. Its token matches Probe on
// hostPort; received lines go to /tmp/recv-tcp-<port> in the container.
func (n *Node) ServeToken(name, proto string, hostPort, port int) {
	n.lab.t.Helper()
	n.MustDocker("run", "-d", "--name", name, "-p", fmt.Sprintf("%d:%d/%s", hostPort, port, proto),
		"-v", "/opt/it:/opt/it:ro", "--tmpfs", "/tmp", "--entrypoint", "/opt/it/fileserver", "it-busybox",
		"-"+proto, strconv.Itoa(port), "-token", fmt.Sprintf("%s-%s-%d", name, proto, hostPort))
	n.WaitFor(name+" serving", 10*time.Second, func() bool { return n.Probe(proto, "127.0.0.1", hostPort) })
}

// forwardFirst reports whether meshly's rule is the first rule of the
// iptables FORWARD chain.
func (n *Node) forwardFirst() bool { return n.iptablesFirst("iptables -S FORWARD") }

// withoutRules removes the rules of an iptables chain in table that contain
// match, until restore puts them back: at the end of t at the latest.
func (n *Node) withoutRules(t *testing.T, table, chain, match string) (restore func()) {
	t.Helper()
	var removed []string
	restore = sync.OnceFunc(func() {
		for _, r := range removed {
			if res := n.Sh("iptables -t " + table + " " + r); res.Code != 0 {
				t.Errorf("%s: restore rule %s: %s", n.Name, r, res)
			}
		}
	})
	t.Cleanup(restore)
	out := strings.TrimSpace(n.MustSh("iptables -t " + table + " -S " + chain + " | grep -F -- '" + match + "' || true"))
	if out == "" {
		return restore
	}
	for _, r := range strings.Split(out, "\n") {
		n.MustSh("iptables -t " + table + " " + strings.Replace(r, "-A ", "-D ", 1))
		removed = append(removed, r)
	}
	return restore
}

// withoutRawGuard removes, until the end of t, Docker's raw PREROUTING
// rules that drop packets for the container address addr arriving on
// another interface than its bridge: they come before meshly and would
// hide what meshly drops.
func (n *Node) withoutRawGuard(t *testing.T, addr string) {
	t.Helper()
	n.withoutRules(t, "raw", "PREROUTING", "-d "+addr+"/32 ")
}

// deleteRule deletes the rule with comment from chain of table inet meshly.
func (n *Node) deleteRule(chain, comment string) {
	n.lab.t.Helper()
	out := n.MustSh("nft -a list chain inet meshly " + chain)
	m := regexp.MustCompile(`comment "` + regexp.QuoteMeta(comment) + `" # handle (\d+)`).FindStringSubmatch(out)
	if m == nil {
		n.lab.t.Fatalf("%s: no rule %q in chain %s:\n%s", n.Name, comment, chain, out)
	}
	n.MustSh("nft delete rule inet meshly " + chain + " handle " + m[1])
}

// ProbeFromContainer is Probe from a new container on Docker's default
// network, with the lab's fileserver.
func (n *Node) ProbeFromContainer(proto, addr string, port int) bool {
	r := n.Docker("run", "--rm", "-v", "/opt/it:/opt/it:ro", "--entrypoint", "/opt/it/fileserver", "it-busybox",
		"-probe", fmt.Sprintf("-%s-dial", proto), fmt.Sprintf("%s:%d", addr, port), "-timeout", "2s")
	return r.Code == 0 && strings.Contains(r.Out, fmt.Sprintf("-%s-%d", proto, port))
}

// unwatched stops meshly-watch.service and meshly-check.timer, which would
// repair what t breaks, until repair runs meshly service check and starts
// both again: at the end of t at the latest.
func (n *Node) unwatched(t *testing.T) (repair func()) {
	t.Helper()
	repair = sync.OnceFunc(func() {
		for _, c := range []string{"meshly service check", "systemctl start meshly-watch.service meshly-check.timer"} {
			if r := n.Sh(c); r.Code != 0 {
				t.Errorf("%s: repair: %s: %s", n.Name, c, r)
			}
		}
	})
	t.Cleanup(repair)
	n.MustSh("systemctl stop meshly-watch.service meshly-check.timer")
	return repair
}

// unroutable reports whether ip route get failed for want of a route.
func unroutable(r Result) bool {
	return r.Code != 0 && (strings.Contains(r.Err, "No route to host") || strings.Contains(r.Err, "Network is unreachable"))
}

// counted returns the packets counted by the rule with comment in chain of
// table inet meshly.
func (n *Node) counted(chain, comment string) int {
	n.lab.t.Helper()
	out := n.MustSh("nft list chain inet meshly " + chain)
	m := regexp.MustCompile(`counter packets (\d+) bytes \d+ [^\n]*comment "` + regexp.QuoteMeta(comment) + `"`).FindStringSubmatch(out)
	if m == nil {
		n.lab.t.Fatalf("%s: no counter %q in chain %s:\n%s", n.Name, comment, chain, out)
	}
	c, _ := strconv.Atoi(m[1])
	return c
}

// A port published by Docker on the vps: closed until allow, then open to
// home and to nothing else; deny closes it, an established flow too.
func TestDockerPublishedPort(t *testing.T) {
	forDistros(t, func(t *testing.T, distro string) {
		l := newDockerLab(t, distro)
		l.Node("vps").DockerStart()
		vps, home := l.Pair()
		web := vps.ServeHTTP("web", "9104:8080")
		vps.ServeHTTP("local", "127.0.0.1:9105:8080")
		vps.ServeToken("udp", "udp", 5140, 5140)
		// A port of the same container that is not published.
		vps.MustDocker("exec", "-d", "web", "/busybox", "httpd", "-f", "-p", "8081", "-h", "/www")
		vps.WaitFor("unpublished port serving", 5*time.Second, func() bool { return vps.FetchOK("http://" + web + ":8081/") })
		const url = "http://10.100.0.1:9104/"

		l.Run("closed-without-allow", func(t *testing.T) {
			if home.Connects("10.100.0.1", 9104) {
				t.Fatal("published port reachable through the VPN without allow")
			}
		})

		l.Run("allowed", func(t *testing.T) {
			vps.MustMeshly("allow", "9104/tcp", "from", "home")
			if !home.FetchOK(url) {
				t.Fatalf("allowed published port unreachable:\n%s", home.Sh("curl -m 3 -sS "+url))
			}
		})

		l.Run("unpublished-port", func(t *testing.T) {
			vps.MustMeshly("allow", "8081/tcp", "from", "home")
			if home.Connects("10.100.0.1", 8081) {
				t.Fatal("an unpublished container port is reachable through the VPN")
			}
		})

		// home routes the container's address into the tunnel, past its own
		// meshly table (with the watch and the check timer stopped, which
		// would repair it). Docker's own guard comes first on vps: raw
		// PREROUTING drops packets for a container that arrive on another
		// interface. Without it, meshly's from_vpn is what drops them.
		l.Run("container-address", func(t *testing.T) {
			pub := strings.TrimSpace(vps.MustSh("wg show meshly0 public-key"))
			vps.withoutRawGuard(t, web)
			repair := sync.OnceFunc(func() {
				for _, c := range []string{"ip route del " + web + "/32 dev meshly0 2>/dev/null || true", "meshly service check", "systemctl start meshly-watch.service meshly-check.timer"} {
					if r := home.Sh(c); r.Code != 0 {
						t.Errorf("home: repair: %s: %s", c, r)
					}
				}
			})
			t.Cleanup(repair)
			home.MustSh("systemctl stop meshly-watch.service meshly-check.timer && nft delete table inet meshly")
			home.MustSh(fmt.Sprintf("wg set meshly0 peer %s allowed-ips 10.100.0.1/32,%s/32 && ip route replace %s/32 dev meshly0", pub, web, web))
			before := vps.counted("from_vpn", "only the local vpn address")
			if home.Connects(web, 8080) || home.Connects(web, 8081) {
				t.Fatal("container address reachable through the VPN")
			}
			if after := vps.counted("from_vpn", "only the local vpn address"); after <= before {
				t.Fatalf("meshly did not drop the packets to the container address: counter %d -> %d", before, after)
			}

			repair()
			if out := strings.TrimSpace(home.MustSh("wg show meshly0 allowed-ips")); out != pub+"\t10.100.0.1/32" {
				t.Fatalf("allowed-ips not repaired: %q", out)
			}
			if out := home.MustSh("ip route show " + web + "/32"); strings.TrimSpace(out) != "" {
				t.Fatalf("route to the container left on home: %s", out)
			}
			if !home.FetchOK(url) {
				t.Fatal("published port unreachable after home was repaired")
			}
		})

		// Published on 127.0.0.1 only: closed through the VPN, like a program
		// that listens on localhost only.
		l.Run("localhost-only", func(t *testing.T) {
			vps.MustMeshly("allow", "9105/tcp", "from", "home")
			if !vps.FetchOK("http://127.0.0.1:9105/") {
				t.Fatal("baseline: the port published on 127.0.0.1 does not answer there")
			}
			if home.Connects("10.100.0.1", 9105) {
				t.Fatal("a port published on 127.0.0.1 only is reachable through the VPN")
			}
		})

		// Published on the VPN address only, as docs/firewall.md suggests:
		// closed until allow, then open. Docker binds that address when the
		// container starts, so while the link is stopped it cannot start.
		// Docker 29 also disconnects a container whose start failed from its
		// network, and starting it again runs it without one: it is created
		// again, as the docs say.
		l.Run("vpn-address", func(t *testing.T) {
			const vpnURL = "http://10.100.0.1:9106/"
			vps.ServeHTTP("vpn", "10.100.0.1:9106:8080")
			if home.Connects("10.100.0.1", 9106) {
				t.Fatal("a port published on the VPN address is reachable without allow")
			}
			vps.MustMeshly("allow", "9106/tcp", "from", "home")
			if !home.FetchOK(vpnURL) {
				t.Fatalf("allowed port published on the VPN address unreachable:\n%s", home.Sh("curl -m 3 -sS "+vpnURL))
			}

			vps.MustMeshly("stop")
			r := vps.Docker("restart", "-t", "0", "vpn")
			vps.MustMeshly("start")
			if r.Code == 0 || !strings.Contains(r.Out+r.Err, "cannot assign requested address") {
				t.Fatalf("restart of a container published on the VPN address with the link stopped: %s", r)
			}
			vps.MustDocker("rm", "-f", "vpn")
			vps.ServeHTTP("vpn", "10.100.0.1:9106:8080")
			home.WaitFor("port published on the VPN address after meshly start", 30*time.Second, func() bool { return home.FetchOK(vpnURL) })
		})

		// UDP like TCP. The flow from a fixed source port stays the same
		// conntrack entry: deny stops it as well as new flows.
		l.Run("udp", func(t *testing.T) {
			flow := func() bool {
				return strings.Contains(home.Sh("echo probe | nc -u -w2 -p 40000 10.100.0.1 5140").Out, "-udp-5140")
			}
			if home.Probe("udp", "10.100.0.1", 5140) {
				t.Fatal("published UDP port reachable without allow")
			}
			vps.MustMeshly("allow", "5140/udp", "from", "home")
			if !home.Probe("udp", "10.100.0.1", 5140) || !flow() {
				t.Fatal("allowed published UDP port unreachable")
			}
			vps.MustMeshly("deny", "5140/udp", "from", "home")
			if flow() || home.Probe("udp", "10.100.0.1", 5140) {
				t.Fatal("published UDP port reachable after deny")
			}
		})

		// As TestDenyStopsEstablishedFlow, with a container behind 9104 that
		// records what it receives.
		l.Run("deny-stops-established-flow", func(t *testing.T) {
			vps.MustDocker("rm", "-f", "web")
			vps.ServeToken("sink", "tcp", 9104, 8080)
			home.MustSh("nohup /opt/it/fileserver -stream 10.100.0.1:9104 >/dev/null 2>&1 &")
			lines := func() int {
				n, _ := strconv.Atoi(strings.TrimSpace(vps.Docker("exec", "sink", "/busybox", "sh", "-c", "wc -l < /tmp/recv-tcp-8080").Out))
				return n
			}
			vps.WaitFor("stream started", 10*time.Second, func() bool { return lines() >= 5 })
			if out := vps.MustSh("conntrack -L -p tcp --dport 9104 2>/dev/null"); !strings.Contains(out, "ESTABLISHED") {
				t.Fatalf("no established flow: %s", out)
			}
			vps.MustMeshly("deny", "9104/tcp", "from", "home")
			time.Sleep(500 * time.Millisecond) // in-flight segments
			before := lines()
			time.Sleep(3 * time.Second)
			if after := lines(); after != before {
				t.Fatalf("established flow continues after deny: %d -> %d lines", before, after)
			}
			if home.Connects("10.100.0.1", 9104) {
				t.Fatal("new connections possible after deny")
			}
		})
	})
}

// Containers on home connect to vps like programs on home: only to what
// vps allows, and vps sees home's VPN address.
func TestDockerClient(t *testing.T) {
	forDistros(t, func(t *testing.T, distro string) {
		l := newDockerLab(t, distro)
		home := l.Node("home")
		home.DockerStart()
		home.MustDocker("network", "create", "it-net")
		vps, home := l.Pair()
		vps.ServeHTTPHost(8080)
		const url = "http://10.100.0.1:8080/"
		networks := []string{"", "it-net"} // docker0 and a br-<id>

		l.Run("closed-without-allow", func(t *testing.T) {
			for _, network := range networks {
				if home.FetchOKFromContainer(network, url) {
					t.Fatalf("container on network %q reaches vps without allow", network)
				}
			}
		})

		l.Run("allowed", func(t *testing.T) {
			vps.MustMeshly("allow", "8080/tcp", "from", "home")
			for _, network := range networks {
				if r := home.FetchFromContainer(network, url); strings.TrimSpace(r.Out) != "ok" {
					t.Fatalf("container on network %q cannot reach an allowed port of vps: %s", network, r)
				}
			}
			out := vps.MustSh("conntrack -L -p tcp --dport 8080 2>/dev/null")
			if !strings.Contains(out, "src=10.100.0.2 ") || strings.Contains(out, "src=172.") {
				t.Fatalf("vps does not see home's VPN address as the source:\n%s", out)
			}
		})

		l.Run("container-to-container", func(t *testing.T) {
			vps.DockerStart()
			vps.ServeHTTP("web", "9104:8080")
			vps.MustMeshly("allow", "9104/tcp", "from", "home")
			home.WaitFor("container on home reaches a published port of vps", 10*time.Second, func() bool {
				return home.FetchOKFromContainer("it-net", "http://10.100.0.1:9104/")
			})
		})
	})
}

// A Docker network created or removed while meshly runs is followed within
// seconds by meshly-watch.service, without any command.
func TestDockerNetworkLifecycle(t *testing.T) {
	forDistros(t, func(t *testing.T, distro string) {
		l := newDockerLab(t, distro)
		home := l.Node("home")
		home.DockerStart()
		vps, home := l.Pair()
		for _, n := range []*Node{vps, home} {
			if out := strings.TrimSpace(n.Sh("systemctl is-active meshly-watch.service").Out); out != "active" {
				t.Fatalf("%s: meshly-watch.service %s", n.Name, out)
			}
		}
		vps.ServeHTTPHost(8080)
		vps.MustMeshly("allow", "8080/tcp", "from", "home")
		const url = "http://10.100.0.1:8080/"
		var bridge string
		logged := func(t *testing.T, change string) {
			t.Helper()
			if out := home.MustMeshly("logs").Out; !strings.Contains(out, "Docker networks changed: "+change) {
				t.Fatalf("logs do not show %q:\n%s", change, out)
			}
		}

		l.Run("network-created", func(t *testing.T) {
			id := strings.TrimSpace(home.MustDocker("network", "create", "it-new").Out)
			bridge = "br-" + id[:12]
			deadline := time.Now().Add(10 * time.Second)
			home.WaitFor(bridge+" in docker_ifs", time.Until(deadline), func() bool {
				return strings.Contains(home.Sh("nft list set inet meshly docker_ifs").Out, `"`+bridge+`"`)
			})
			home.WaitFor("policy routing rule", time.Until(deadline), func() bool {
				return strings.Contains(home.Sh("ip rule").Out, "iif meshly0 lookup 109")
			})
			home.WaitFor(bridge+" in table 109", time.Until(deadline), func() bool {
				return strings.Contains(home.Sh("ip route show table 109").Out, "dev "+bridge)
			})
			home.WaitFor("meshly rule first in FORWARD", time.Until(deadline), home.forwardFirst)
			home.WaitFor("container on "+bridge+" reaches vps", time.Until(deadline), func() bool {
				return home.FetchOKFromContainer("it-new", url)
			})
			logged(t, "+"+bridge)
		})

		l.Run("network-removed", func(t *testing.T) {
			home.MustDocker("network", "rm", "it-new")
			deadline := time.Now().Add(10 * time.Second)
			home.WaitFor(bridge+" gone from docker_ifs", time.Until(deadline), func() bool {
				r := home.Sh("nft list set inet meshly docker_ifs")
				return r.Code == 0 && !strings.Contains(r.Out, bridge)
			})
			home.WaitFor(bridge+" gone from table 109", time.Until(deadline), func() bool {
				r := home.Sh("ip route show table 109")
				return r.Code == 0 && !strings.Contains(r.Out, bridge)
			})
			logged(t, "-"+bridge)
		})

		// The last Docker bridge disappears: everything Docker needed goes.
		l.Run("docker-gone", func(t *testing.T) {
			home.MustSh("systemctl stop docker docker.socket && ip link del docker0")
			deadline := time.Now().Add(10 * time.Second)
			home.WaitFor("no forwarding on meshly0", time.Until(deadline), func() bool {
				return strings.TrimSpace(home.Sh("sysctl -n net.ipv4.conf.meshly0.forwarding").Out) == "0"
			})
			home.WaitFor("no policy routing rule", time.Until(deadline), func() bool {
				r := home.Sh("ip rule")
				return r.Code == 0 && !strings.Contains(r.Out, "lookup 109")
			})
			home.WaitFor("no meshly rule in FORWARD", time.Until(deadline), func() bool {
				r := home.Sh("iptables -S FORWARD")
				return r.Code == 0 && !strings.Contains(r.Out, "meshly")
			})
			home.WaitFor("table without docker_ifs", time.Until(deadline), func() bool {
				r := home.Sh("nft list table inet meshly")
				return r.Code == 0 && !strings.Contains(r.Out, "docker_ifs")
			})
			if out := home.MustSh("ip route show table 109"); strings.TrimSpace(out) != "" {
				t.Fatalf("routes left in table 109:\n%s", out)
			}
			logged(t, "-docker0")
		})
	})
}

// Docker installed and started after meshly, restarted, and started again
// after a reboot.
func TestDockerAfterMeshly(t *testing.T) {
	forDistros(t, func(t *testing.T, distro string) {
		l := newDockerLab(t, distro)
		vps, home := l.Pair()
		vps.Listen("tcp", 8080)
		vps.MustMeshly("allow", "8080/tcp", "from", "home")
		// Allowed before the container exists: no meshly command follows.
		vps.MustMeshly("allow", "9104/tcp", "from", "home")
		served := func() bool { return home.FetchOK("http://10.100.0.1:9104/") }

		l.Run("docker-started", func(t *testing.T) {
			vps.DockerStart()
			if p := strings.TrimSpace(vps.MustSh("iptables -S FORWARD | head -n 1")); p != "-P FORWARD DROP" {
				t.Fatalf("Docker did not set the FORWARD policy to drop: %s", p)
			}
			vps.ServeHTTP("web", "9104:8080")
			deadline := time.Now().Add(10 * time.Second)
			vps.WaitFor("meshly rule first in FORWARD", time.Until(deadline), vps.forwardFirst)
			home.WaitFor("published port through the VPN", time.Until(deadline), served)
		})

		l.Run("docker-restarted", func(t *testing.T) {
			vps.MustSh("systemctl restart docker")
			vps.WaitFor("meshly rule first in FORWARD after the restart", 10*time.Second, vps.forwardFirst)
			if n := strings.Count(vps.MustSh("iptables -S FORWARD"), "meshly:v1 integration"); n != 1 {
				t.Fatalf("%d meshly rules in FORWARD", n)
			}
			vps.MustDocker("start", "web") // containers stop with Docker
			home.WaitFor("published port after the restart", 10*time.Second, served)
		})

		l.Run("reboot", func(t *testing.T) {
			vps.Reboot()
			vps.Listen("tcp", 8080)
			waitFor(t, "tunnel after the reboot", 60*time.Second, func() bool { return home.Probe("tcp", "10.100.0.1", 8080) })
			vps.DockerStart()
			vps.MustDocker("rm", "-f", "web")
			vps.ServeHTTP("web", "9104:8080")
			home.WaitFor("published port after the reboot", 10*time.Second, served)
		})
	})
}

// UFW enabled before Docker: the published port works, meshly keeps its
// rule first in FORWARD, also after ufw reload.
func TestDockerUFW(t *testing.T) {
	forDistros(t, func(t *testing.T, distro string) {
		l := newDockerLab(t, distro)
		vps := l.Node("vps")
		vps.MustSh("ufw allow 22/tcp && ufw --force enable")
		vps.DockerStart()
		vps, home := l.Pair()
		vps.ServeHTTP("web", "9104:8080")
		vps.MustMeshly("allow", "9104/tcp", "from", "home")
		const url = "http://10.100.0.1:9104/"

		l.Run("allowed", func(t *testing.T) {
			if !home.FetchOK(url) {
				t.Fatalf("published port unreachable through UFW:\n%s", vps.Sh("iptables -S FORWARD"))
			}
			if r := vps.MustMeshly("status"); !strings.Contains(r.Out, "ip filter FORWARD ok") {
				t.Fatalf("status does not show meshly's rule first in FORWARD:\n%s", r.Out)
			}
		})

		l.Run("ufw-reload", func(t *testing.T) {
			vps.MustSh("ufw reload")
			vps.WaitFor("meshly rule first in FORWARD after ufw reload", 10*time.Second, vps.forwardFirst)
			if !home.FetchOK(url) {
				t.Fatal("published port unreachable after ufw reload")
			}
		})
	})
}

// Docker's nftables firewall backend: meshly works with it like with its
// iptables rules, and doctor only informs about Docker's chains.
func TestDockerNftablesBackend(t *testing.T) {
	forDistros(t, func(t *testing.T, distro string) {
		l := newDockerLab(t, distro)
		vps := l.Node("vps")
		version := strings.TrimSpace(vps.MustSh("docker --version"))
		// The nftables backend does not start without forwarding.
		vps.MustSh(`sysctl -qw net.ipv4.ip_forward=1 && echo '{"storage-driver":"vfs","firewall-backend":"nftables"}' > /etc/docker/daemon.json`)
		if r := vps.Sh("systemctl start docker"); r.Code != 0 {
			t.Skipf("%s does not start with its nftables firewall backend: %s", version, vps.Sh("journalctl -u docker --no-pager | tail -n 3").Out)
		}
		vps.DockerStart()
		vps.MustDocker("network", "create", "it-net")
		vps, home := l.Pair()
		vps.Listen("tcp", 22)
		vps.MustMeshly("allow", "22/tcp", "from", "home")
		if !home.Probe("tcp", "10.100.0.1", 22) {
			t.Fatal("allowed port of the host unreachable with Docker's nftables backend")
		}
		vps.ServeHTTP("web", "9104:8080")
		if home.Connects("10.100.0.1", 9104) {
			t.Fatalf("%s, nftables backend: published port reachable without allow", version)
		}
		vps.MustMeshly("allow", "9104/tcp", "from", "home")
		if !home.FetchOK("http://10.100.0.1:9104/") {
			t.Fatalf("%s, nftables backend: published port unreachable after allow", version)
		}
		home.ServeHTTPHost(8080)
		home.MustMeshly("allow", "8080/tcp", "from", "vps")
		for _, network := range []string{"", "it-net"} {
			if r := vps.FetchFromContainer(network, "http://10.100.0.2:8080/"); strings.TrimSpace(r.Out) != "ok" {
				t.Fatalf("%s, nftables backend: container on network %q cannot reach an allowed port of home: %s", version, network, r)
			}
		}
		doc := vps.Meshly("doctor")
		if !strings.Contains(doc.Out, "· firewall-forward ") || strings.Contains(doc.Out, "! firewall-forward ") {
			t.Fatalf("doctor does not report Docker's chains as information:\n%s", doc.Out)
		}
		t.Logf("%s, nftables backend: published ports and container connections work", version)
	})
}

// A host firewall with its own forward chain (policy drop): the tunnel
// between the hosts works, doctor warns and prints the rule, and with that
// rule the published port works.
func TestDockerNativeForwardChain(t *testing.T) {
	forDistros(t, func(t *testing.T, distro string) {
		l := newDockerLab(t, distro)
		vps := l.Node("vps")
		vps.DockerStart()
		vps.MustSh(`nft -f - <<'EOF'
table inet hostfw {
	chain forward { type filter hook forward priority 0; policy drop; }
}
EOF`)
		vps, home := l.Pair()
		vps.Listen("tcp", 8080)
		vps.MustMeshly("allow", "8080/tcp", "from", "home")
		vps.ServeHTTP("web", "9104:8080")
		vps.MustMeshly("allow", "9104/tcp", "from", "home")
		const url = "http://10.100.0.1:9104/"

		l.Run("without-integration", func(t *testing.T) {
			if !home.Probe("tcp", "10.100.0.1", 8080) {
				t.Fatal("allowed port of the host unreachable with a forward chain policy drop")
			}
			if home.Connects("10.100.0.1", 9104) {
				t.Fatal("baseline: the forward chain does not drop the published port")
			}
			r := vps.ExpectCode(11, "doctor")
			if !strings.Contains(r.Out, "firewall-forward") || !strings.Contains(r.Out, "chain inet hostfw forward (hook forward, policy drop)") || !strings.Contains(r.Out, integrationRule) {
				t.Fatalf("doctor does not warn about the forward chain with the rule to add:\n%s", r.Out)
			}
		})

		l.Run("with-integration", func(t *testing.T) {
			vps.MustSh("nft 'insert rule inet hostfw forward " + integrationRule + "'")
			home.WaitFor("published port with the integration rule", 10*time.Second, func() bool { return home.FetchOK(url) })
			if r := vps.Meshly("doctor"); strings.Contains(r.Out, "chain inet hostfw forward") {
				t.Fatalf("doctor still warns about the integrated forward chain:\n%s", r.Out)
			}
		})
	})
}

// A Docker host whose peer turns against it, as in
// TestCompromisedPeerContained: forwarding for containers opens nothing
// else. The home LAN stays closed to vps, also through a foreign DNAT on an
// allowed port and while the meshly table is gone; nothing from the LAN is
// forwarded into the tunnel; a local redirect is dropped; container
// addresses and unpublished ports stay closed. Each check also makes sure
// that it is meshly that drops the packets.
func TestDockerHostContained(t *testing.T) {
	forDistros(t, func(t *testing.T, distro string) {
		l := newDockerLab(t, distro)
		home, lanhost := l.Node("home"), l.Node("lanhost")
		// Forwarding is on before Docker starts, as on a host that routes
		// already: Docker leaves the FORWARD policy at accept, and only
		// meshly keeps the tunnel apart from the LAN.
		home.MustSh("sysctl -qw net.ipv4.ip_forward=1 && systemctl start docker")
		home.DockerStart()
		if p := strings.TrimSpace(home.MustSh("iptables -S FORWARD | head -n 1")); p != "-P FORWARD ACCEPT" {
			t.Fatalf("Docker changed the FORWARD policy: %s", p)
		}
		vps, home := l.Pair()
		web := home.ServeHTTP("web", "9104:8080")
		// A port of the same container that is not published.
		home.MustDocker("exec", "-d", "web", "/busybox", "httpd", "-f", "-p", "8081", "-h", "/www")
		home.WaitFor("unpublished port serving", 5*time.Second, func() bool { return home.FetchOK("http://" + web + ":8081/") })
		// A foreign table DNATs an allowed port to the LAN host and
		// redirects another to a local port without a rule. The LAN host's
		// replies return through home. Behind 8888 and 8889 the token is
		// that of another port, so Connects checks them, not Probe.
		home.MustSh(`nft -f - <<'EOF'
table ip foreign {
	chain prerouting {
		type nat hook prerouting priority dstnat;
		tcp dport 8888 dnat to 192.168.77.20:80
		tcp dport 8889 redirect to :22
	}
	chain postrouting { type nat hook postrouting priority srcnat; ip daddr 192.168.77.20 masquerade; }
}
EOF`)
		home.Listen("tcp", 22)
		lanhost.Listen("tcp", 80)
		for _, p := range []string{"9104/tcp", "8888/tcp", "8889/tcp"} {
			home.MustMeshly("allow", p, "from", "vps")
		}

		// vps turns against home as in TestCompromisedPeerContained and
		// routes home's Docker network into the tunnel too. Its watch and
		// check timer would undo that.
		subnet := strings.TrimSpace(home.MustDocker("network", "inspect", "-f", "{{range .IPAM.Config}}{{.Subnet}}{{end}}", "bridge").Out)
		pub := strings.TrimSpace(vps.MustSh("wg show meshly0 peers"))
		t.Cleanup(func() {
			for _, c := range []string{"ip route del 192.168.77.0/24 dev meshly0 2>/dev/null || true", "ip route del " + subnet + " dev meshly0 2>/dev/null || true"} {
				if r := vps.Sh(c); r.Code != 0 {
					t.Errorf("vps: restore: %s: %s", c, r)
				}
			}
		})
		vps.unwatched(t)
		compromise(t, vps)
		vps.MustSh(fmt.Sprintf("wg set meshly0 peer %s allowed-ips 10.100.0.2/32,10.100.0.0/24,192.168.77.0/24,%s && ip route replace %s dev meshly0", pub, subnet, subnet))
		if !vps.FetchOK("http://10.100.0.2:9104/") {
			t.Fatal("baseline: published and allowed port unreachable")
		}
		// home's route for a packet from vps to dst.
		routeFromVPN := func(dst string) Result { return home.Sh("ip route get " + dst + " from 10.100.0.1 iif meshly0") }

		// from_vpn drops the LAN address. The DNAT on an allowed port gets
		// past it, and policy routing refuses it before the forward hook.
		l.Run("lan", func(t *testing.T) {
			before := home.counted("from_vpn", "only the local vpn address")
			if vps.Probe("tcp", "192.168.77.20", 80) {
				t.Fatal("compromised peer reaches the home LAN")
			}
			if after := home.counted("from_vpn", "only the local vpn address"); after <= before {
				t.Fatalf("meshly did not drop the packets to the LAN host: counter %d -> %d", before, after)
			}
			before = home.counted("guard_fwd", "no forwarding from the vpn")
			if vps.Connects("10.100.0.2", 8888) {
				t.Fatal("DNAT on an allowed port reaches the LAN host")
			}
			if r := routeFromVPN("192.168.77.20"); !unroutable(r) {
				t.Fatalf("policy routing does not refuse the LAN host to the tunnel: %s", r)
			}
			if after := home.counted("guard_fwd", "no forwarding from the vpn"); after != before {
				t.Fatalf("DNAT to the LAN host reached the forward hook: counter %d -> %d", before, after)
			}
		})

		// Without the routing rule, guard_fwd alone drops the DNAT to the
		// LAN; service check brings the rule back.
		l.Run("lan-without-routing-rule", func(t *testing.T) {
			repair := home.unwatched(t)
			home.MustSh("ip rule del iif meshly0 lookup 109")
			before := home.counted("guard_fwd", "no forwarding from the vpn")
			if vps.Connects("10.100.0.2", 8888) {
				t.Fatal("DNAT on an allowed port reaches the LAN host without the routing rule")
			}
			if after := home.counted("guard_fwd", "no forwarding from the vpn"); after <= before {
				t.Fatalf("meshly did not drop the DNAT to the LAN host: counter %d -> %d", before, after)
			}
			repair()
			if out := home.MustSh("ip rule"); !strings.Contains(out, "iif meshly0 lookup 109") {
				t.Fatalf("service check did not restore the routing rule:\n%s", out)
			}
		})

		l.Run("local-redirect", func(t *testing.T) {
			before := home.counted("guard_in", "dnat from the vpn is not supported")
			if vps.Connects("10.100.0.2", 8889) {
				t.Fatal("local redirect on an allowed port reaches a port without a rule")
			}
			if after := home.counted("guard_in", "dnat from the vpn is not supported"); after <= before {
				t.Fatalf("meshly did not drop the redirect: counter %d -> %d", before, after)
			}
		})

		// Docker's own guard comes first: raw PREROUTING drops packets for
		// a container that arrive on another interface. Without it,
		// meshly's from_vpn is what drops them.
		l.Run("containers", func(t *testing.T) {
			home.withoutRawGuard(t, web)
			home.MustMeshly("allow", "8081/tcp", "from", "vps")
			before := home.counted("from_vpn", "only the local vpn address")
			for _, port := range []int{8080, 8081} {
				if vps.Connects(web, port) {
					t.Fatalf("container address reachable through the VPN on port %d", port)
				}
			}
			if after := home.counted("from_vpn", "only the local vpn address"); after <= before {
				t.Fatalf("meshly did not drop the packets to the container address: counter %d -> %d", before, after)
			}
			if vps.Connects("10.100.0.2", 8081) {
				t.Fatal("an unpublished container port is reachable through the VPN")
			}
			if !vps.FetchOK("http://10.100.0.2:9104/") {
				t.Fatal("published and allowed port unreachable")
			}
		})

		// lanhost routes vps's VPN address through home. A datagram needs
		// no reply: vps would log one that gets through. With rp_filter on
		// (Ubuntu sets 2), the kernel drops them before the forward hook,
		// since the reverse path lookup for a packet leaving through meshly0
		// follows meshly's routing rule to its unreachable default. With
		// rp_filter off (the higher of all and the LAN interface counts),
		// guard_fwd alone decides.
		l.Run("lan-into-vpn", func(t *testing.T) {
			vps.Listen("tcp", 8080)
			vps.Listen("udp", 5353)
			dev := regexp.MustCompile(` dev (\S+)`).FindStringSubmatch(home.MustSh("ip -o route get 192.168.77.20"))
			if dev == nil {
				t.Fatal("home: no route to the LAN host")
			}
			for _, conf := range []string{"all", dev[1]} {
				key := "net.ipv4.conf." + conf + ".rp_filter"
				old := strings.TrimSpace(home.MustSh("sysctl -n " + key))
				t.Cleanup(func() {
					if r := home.Sh("sysctl -qw " + key + "=" + old); r.Code != 0 {
						t.Errorf("home: restore %s: %s", key, r)
					}
				})
				home.MustSh("sysctl -qw " + key + "=0")
			}
			if r := home.Sh("ip route get 10.100.0.1 from 192.168.77.20 iif " + dev[1]); r.Code != 0 || !strings.Contains(r.Out, "dev meshly0") {
				t.Fatalf("setup: home does not route the LAN to the tunnel (rp_filter?): %s", r)
			}
			t.Cleanup(func() {
				if r := lanhost.Sh("ip route del 10.100.0.1/32 2>/dev/null || true"); r.Code != 0 {
					t.Errorf("lanhost: restore: %s", r)
				}
			})
			lanhost.MustSh("ip route replace 10.100.0.1/32 via 192.168.77.10")
			before := home.counted("guard_fwd", "no forwarding into the vpn")
			if lanhost.Probe("tcp", "10.100.0.1", 8080) || lanhost.Probe("udp", "10.100.0.1", 5353) {
				t.Fatal("the home LAN reaches vps through the tunnel")
			}
			if hits := vps.Sh("cat /tmp/hits-tcp-8080 /tmp/hits-udp-5353 2>/dev/null").Out; hits != "" {
				t.Fatalf("vps received packets from the home LAN: %s", hits)
			}
			if after := home.counted("guard_fwd", "no forwarding into the vpn"); after <= before {
				t.Fatalf("meshly did not drop the packets from the LAN: counter %d -> %d", before, after)
			}
		})

		// Everything that leaves through meshly0 has home's VPN address as
		// its source. Without meshly's SNAT, and without Docker's masquerade
		// (which picks that address too), guard_post drops what a container
		// sends to vps. vps, without its table, takes any source from home
		// and would log a datagram that arrives.
		l.Run("container-source", func(t *testing.T) {
			vps.Listen("tcp", 3100)
			vps.Listen("udp", 3100)
			repair := home.unwatched(t)
			restore := home.withoutRules(t, "nat", "POSTROUTING", "-s "+subnet+" ")
			home.deleteRule("nat_out", "containers appear as this node")
			before := home.counted("guard_post", "only the vpn address into the vpn")
			if home.ProbeFromContainer("tcp", "10.100.0.1", 3100) || home.ProbeFromContainer("udp", "10.100.0.1", 3100) {
				t.Fatal("a container reaches vps without meshly's SNAT and Docker's masquerade")
			}
			if hits := vps.Sh("cat /tmp/hits-tcp-3100 /tmp/hits-udp-3100 2>/dev/null").Out; hits != "" {
				t.Fatalf("vps received packets from a container address: %s", hits)
			}
			if after := home.counted("guard_post", "only the vpn address into the vpn"); after <= before {
				t.Fatalf("meshly did not drop the packets with a container source: counter %d -> %d", before, after)
			}
			restore()
			repair()
			if !home.ProbeFromContainer("tcp", "10.100.0.1", 3100) {
				t.Fatal("a container does not reach vps after the repair")
			}
		})

		// The second layer, until service check repairs the table: policy
		// routing passes only Docker's networks from the tunnel. (Ports
		// Docker publishes on all addresses are open meanwhile, a known
		// limitation, so they are not checked here.)
		l.Run("without-table", func(t *testing.T) {
			repair := home.unwatched(t)
			home.MustSh("nft delete table inet meshly")
			if r := routeFromVPN("192.168.77.20"); !unroutable(r) {
				t.Fatalf("policy routing does not refuse the LAN host to the tunnel: %s", r)
			}
			if r := routeFromVPN(web); r.Code != 0 || !strings.Contains(r.Out, "dev docker0") {
				t.Fatalf("policy routing does not pass the container to docker0: %s", r)
			}
			if vps.Probe("tcp", "192.168.77.20", 80) || vps.Connects("10.100.0.2", 8888) {
				t.Fatal("compromised peer reaches the home LAN without the meshly table")
			}
			if home.Sh("nft list table inet meshly").Code == 0 {
				t.Fatal("the table came back before service check")
			}
			repair()
			if r := home.Sh("nft list table inet meshly"); r.Code != 0 {
				t.Fatalf("service check did not restore the table: %s", r)
			}
		})

		l.Run("one-routing-rule", func(t *testing.T) {
			out := home.MustSh("ip rule")
			if n := strings.Count(out, "iif meshly0"); n != 1 {
				t.Fatalf("%d routing rules for meshly0:\n%s", n, out)
			}
		})
	})
}
