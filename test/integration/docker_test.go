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
			var removed []string
			t.Cleanup(func() {
				for _, r := range removed {
					if res := vps.Sh("iptables -t raw " + r); res.Code != 0 {
						t.Errorf("vps: restore Docker's rule %s: %s", r, res)
					}
				}
			})
			if out := strings.TrimSpace(vps.MustSh("iptables -t raw -S PREROUTING | grep -F -- '-d " + web + "/32 ' || true")); out != "" {
				for _, r := range strings.Split(out, "\n") {
					vps.MustSh("iptables -t raw " + strings.Replace(r, "-A ", "-D ", 1))
					removed = append(removed, r)
				}
			}
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
