package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
)

var helpTexts = map[string]string{
	"init": `meshly init <network> --name <node> [--endpoint IP[:PORT]|auto|none] [options]

Create a new network on this node and bring up the protected interface.
Usually run on the server whose UDP port is reachable from the internet.

  --name NAME          name of this node (a-z, 0-9, '-')
  --endpoint ADDR      public IP or IP:PORT other nodes connect to (the port
                       defaults to --listen-port). Default auto: the public
                       IPv4 address of this server's interface, found
                       locally. none = no public address
  --listen-port PORT   local UDP port (default: endpoint port or 51820)
  --cidr CIDR          VPN network (default 10.100.0.0/24, IPv4 /16-/30)
  --mtu N              interface MTU (default 1420)
  --interface NAME     interface name (default meshly0)
  --firewall PROFILE   auto | none | nftables (default auto)
  --dry-run            show what would change, change nothing

Examples:
  meshly init homelab --name vps
  meshly init homelab --name vps --endpoint 203.0.113.10`,
	"allow": `meshly allow <port>/<tcp|udp> from <peer> [--dry-run]
meshly allow ping from <peer>

Allow <peer> to open connections to this node's VPN address on the port.
The rule applies only on this node, only through the VPN, only in the
peer → this node direction. Public interfaces are not opened.

Examples:
  meshly allow 9100/tcp from home
  meshly allow 53/udp from home`,
	"deny": `meshly deny <port>/<tcp|udp> from <peer> [--dry-run]
meshly deny ping from <peer>

Remove the allow rule. Packets of already established connections to that
service are dropped as well.`,
	"rules":   "meshly rules [--json]\n\nList allow rules of this node.",
	"revoke":  "meshly revoke <peer> [--yes] [--dry-run]\n\nClose all access of the peer first, then remove it from WireGuard and routing.",
	"status":  "meshly status [--json]\n\nShow saved configuration, interface, peer, routes, firewall, last handshake,\ntransfer counters, interrupted operations and drift. Runs without root with\nreduced detail.",
	"doctor":  "meshly doctor [--json] [--probe <port>/<tcp|udp>] [--peer NAME]\n\nDiagnose problems. Each finding says whether it is observed or inferred.\n--probe connects to the peer's service through the VPN (no port is opened\nlocally).\n\nExit codes: 0 no problems, 11 warnings, 12 problems.",
	"start":   "meshly start [--dry-run]\n\nBring the link up from the saved configuration and enable autostart.",
	"stop":    "meshly stop [--dry-run]\n\nStop the link: traffic path first, protective firewall last. The link stays\nstopped after reboot until `meshly start`.",
	"restart": "meshly restart\n\nTear the link down and bring it up again.",
	"set": `meshly set <setting> <value> [--dry-run]

  mtu <1280-8920>                 interface MTU (set the same value on both nodes)
  keepalive <seconds>             persistent keepalive towards all peers (0 = off)
  endpoint <IP[:PORT]|auto|none>  this node's public address (used in new invites;
                                  the port defaults to the listen port)
  peer-endpoint <peer> <IP[:PORT]|none>   where to reach the peer (the port
                                  defaults to the current one, or 51820)
  cidr <CIDR>                     VPN network (only before a peer joins)

Examples:
  meshly set mtu 1380
  meshly set endpoint auto
  meshly set peer-endpoint vps 198.51.100.7`,
	"logs":    "meshly logs [-n N] [--json]\n\nShow the operation journal (who changed what, rollbacks, recoveries).\nService output is in: journalctl -u meshly",
	"upgrade": "meshly upgrade [--check] [--version X.Y.Z] [--force] [--yes]\n\nDownload a release from github.com/nikitakiselev/meshly, verify the Ed25519\nsignature of SHA256SUMS with the key built into this binary and the SHA-256\nof the binary, replace the executable atomically (previous one kept as\n<exe>.prev) and restart meshly.service. Downgrades need --force.",
	"reset":   "meshly reset [--yes]\n\nStop the link and remove configuration, keys and units\nfrom this node. The operation journal is kept for audit.",
	"version": "meshly version [--short] [--json]",
	"recover": "meshly recover\n\nFinish or roll back an operation interrupted by a crash or power loss (every\ncommand does this first; this command does only that).",
	"service": "meshly service start|stop|reload|check|install\n\nEntry points used by meshly.service and meshly-check.service; not meant to be\nrun by hand. `install` (re)writes the unit files for the current binary.",
	"help":    "meshly help [command]",
}

func (a *App) usage(w io.Writer) {
	fmt.Fprint(w, `meshly — a protected WireGuard link between two Linux servers

Usage: meshly <command> [arguments]

Typical setup:
  vps$  meshly init homelab --name vps
  vps$  meshly allow 22/tcp from home

Commands:
`)
	for _, c := range commands() {
		if !c.hidden {
			fmt.Fprintf(w, "  %-9s %s\n", c.name, c.summary)
		}
	}
	fmt.Fprint(w, "\nRun `meshly help <command>` for details. Exit codes: see docs/cli.md.\n")
}

func (a *App) commandHelp(w io.Writer, name string) {
	if t, ok := helpTexts[name]; ok {
		fmt.Fprintln(w, "Usage: "+strings.TrimSpace(t))
		return
	}
	a.usage(w)
}

func (a *App) cmdHelp(_ context.Context, args []string) error {
	if len(args) == 0 {
		a.usage(a.Stdout)
		return nil
	}
	if _, ok := helpTexts[args[0]]; !ok {
		return errorf(ExitUsage, "no help for %q", args[0])
	}
	a.commandHelp(a.Stdout, args[0])
	return nil
}
