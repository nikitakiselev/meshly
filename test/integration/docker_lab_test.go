//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newDockerLab is newSystemdLab on distro, with vps and home on the
// docker-<distro> image: Docker CE is installed but not running until
// DockerStart.
func newDockerLab(t *testing.T, distro string) *Lab {
	t.Helper()
	img := images["docker-"+distro]
	if img == "" {
		t.Fatalf("no image docker-%s (MESHLY_IT_DISTROS=%s)", distro, strings.Join(distros, ","))
	}
	return newLabWith(t, distro, img)
}

// importBusybox builds the image it-busybox offline from the node's files:
// /busybox (the entrypoint), /www/index.html ("ok") and /nc, a netcat
// that listens on UDP (-u -l -p PORT): busybox's own nc where it can,
// otherwise nc.openbsd with its libraries.
const importBusybox = `set -e
d=$(mktemp -d)
mkdir "$d/www"
cp /bin/busybox "$d/busybox"
echo ok > "$d/www/index.html"
if busybox nc --help 2>&1 | grep -qw -- -u; then
	ln -s busybox "$d/nc"
else
	cp /bin/nc.openbsd "$d/nc"
	for l in $(ldd /bin/nc.openbsd | grep -o '/[^ ]*'); do cp --parents -L "$l" "$d"; done
fi
tar -C "$d" -c . | docker import -c 'ENTRYPOINT ["/busybox"]' - it-busybox
rm -rf "$d"`

// DockerStart starts Docker on a node of newDockerLab, waits until it
// answers and, the first time, imports it-busybox. Lab nodes inherit
// net.ipv4.ip_forward=1 from the outer host; as on a fresh server, Docker
// finds forwarding off, enables it itself and then sets the policy of the
// iptables FORWARD chain to drop. Docker already running (its nftables
// backend refuses to start without forwarding) is left alone.
func (n *Node) DockerStart() {
	n.lab.t.Helper()
	n.MustSh("systemctl is-active -q docker || { sysctl -qw net.ipv4.ip_forward=0 && systemctl start docker; }")
	n.WaitFor("docker info", 30*time.Second, func() bool { return n.Docker("info").Code == 0 })
	if n.Docker("image", "inspect", "it-busybox").Code != 0 {
		n.MustSh(importBusybox)
	}
}

// Docker runs the docker CLI on the node.
func (n *Node) Docker(args ...string) Result {
	return n.exec(nil, "", append([]string{"docker"}, args...)...)
}

func (n *Node) MustDocker(args ...string) Result {
	n.lab.t.Helper()
	r := n.Docker(args...)
	if r.Code != 0 {
		n.lab.t.Fatalf("%s: docker %s: %s", n.Name, strings.Join(args, " "), r)
	}
	return r
}

// ServeHTTP runs container name with an HTTP server on port 8080 that
// answers "ok", published as publish (docker run -p), and returns the
// container's address once the server answers.
func (n *Node) ServeHTTP(name, publish string) string {
	n.lab.t.Helper()
	n.MustDocker("run", "-d", "--name", name, "-p", publish, "it-busybox", "httpd", "-f", "-p", "8080", "-h", "/www")
	n.WaitFor(name+" serving", 10*time.Second, func() bool {
		return strings.TrimSpace(n.Docker("exec", name, "/busybox", "wget", "-qO-", "http://127.0.0.1:8080/").Out) == "ok"
	})
	return strings.TrimSpace(n.MustDocker("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name).Out)
}

// FetchFromContainer fetches url with wget in a new container on network
// ("" for Docker's default network).
func (n *Node) FetchFromContainer(network, url string) Result {
	// busybox 1.35 (Debian 12) wget crashes with -T, so timeout bounds it;
	// that needs --init, since PID 1 of a container ignores SIGTERM.
	args := []string{"run", "--rm", "--init"}
	if network != "" {
		args = append(args, "--network", network)
	}
	return n.Docker(append(args, "it-busybox", "timeout", "3", "/busybox", "wget", "-qO-", url)...)
}

// TestCaptureDockerRuleset refreshes the captures of a real Docker CE in
// internal/nft/testdata (TestAnalyzeDockerCE). It runs only with
// MESHLY_IT_CAPTURE set, once per distribution (deb12, u2404, deb13):
//
//	MESHLY_IT_CAPTURE="$PWD/internal/nft/testdata" MESHLY_IT_DISTROS=deb12 \
//	  go test -tags integration -count=1 -run TestCaptureDockerRuleset -v ./test/integration/...
//
// With Docker running on home, a network it-net and a published container
// port, it writes nft-<version>/docker-ce.json. On Ubuntu 24.04 it also
// writes docker-ce-ufw.json with UFW enabled, and docker-ce-nftables.json
// from vps with Docker's nftables firewall backend.
func TestCaptureDockerRuleset(t *testing.T) {
	dir := os.Getenv("MESHLY_IT_CAPTURE")
	if dir == "" {
		t.Skip("set MESHLY_IT_CAPTURE to internal/nft/testdata to refresh the Docker CE captures")
	}
	for _, d := range distros {
		t.Run(d, func(t *testing.T) {
			l := newDockerLab(t, d)
			vps, home := l.Node("vps"), l.Node("home")
			if v := home.MustSh("iptables -V"); !strings.Contains(v, "nf_tables") {
				t.Fatalf("Docker would not use iptables-nft: %s", v)
			}
			// The lab's own Docker keeps the rules of its DNS server
			// (DOCKER_OUTPUT, DOCKER_POSTROUTING) in every node; no host has
			// them, and the lab needs no DNS.
			home.MustSh("nft delete table ip nat")
			vps.MustSh("nft delete table ip nat")
			home.DockerStart()
			home.MustDocker("network", "create", "it-net")
			ip := home.ServeHTTP("web", "9104:8080")
			for network, url := range map[string]string{"": "http://" + ip + ":8080/", "it-net": "http://" + home.IP + ":9104/"} {
				if r := home.FetchFromContainer(network, url); strings.TrimSpace(r.Out) != "ok" {
					t.Fatalf("fetch %s from network %q: %s", url, network, r)
				}
			}
			captureRuleset(t, home, dir, "docker-ce")
			if d != "u2404" {
				return
			}
			home.MustSh("ufw --force enable")
			captureRuleset(t, home, dir, "docker-ce-ufw")

			// The nftables backend does not start without forwarding.
			vps.MustSh(`sysctl -qw net.ipv4.ip_forward=1 && echo '{"storage-driver":"vfs","firewall-backend":"nftables"}' > /etc/docker/daemon.json`)
			if r := vps.Sh("systemctl start docker"); r.Code != 0 {
				t.Logf("Docker does not start with its nftables backend, no capture: %s", vps.Sh("journalctl -u docker --no-pager | tail -n 3").Out)
				return
			}
			vps.DockerStart()
			vps.MustDocker("network", "create", "it-net")
			vps.ServeHTTP("web", "9104:8080")
			captureRuleset(t, vps, dir, "docker-ce-nftables")
		})
	}
}

// captureRuleset writes the node's ruleset to <dir>/nft-<version>/<name>.json.
func captureRuleset(t *testing.T, n *Node, dir, name string) {
	t.Helper()
	v := strings.Fields(n.MustSh("nft -v")) // nftables v1.0.6 (Lester Gooch #5)
	if len(v) < 2 || !strings.HasPrefix(v[1], "v") {
		t.Fatalf("%s: nft -v: %q", n.Name, v)
	}
	path := filepath.Join(dir, "nft-"+strings.TrimPrefix(v[1], "v"), name+".json")
	must(t, os.MkdirAll(filepath.Dir(path), 0o755))
	must(t, os.WriteFile(path, []byte(n.MustSh("nft -j list ruleset")), 0o644))
	t.Logf("%s: %s, %s, %s", path, strings.TrimSpace(n.MustSh("docker --version")),
		strings.TrimSpace(n.MustSh("iptables -V")), strings.Join(v, " "))
}
