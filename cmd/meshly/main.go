// Command meshly connects two Linux servers with kernel WireGuard and
// manages the tunnel, addresses, routes, nftables policy and systemd units.
package main

import (
	"os"

	"github.com/nikitakiselev/meshly/internal/cli"
)

func main() {
	os.Exit(cli.NewApp().Main(os.Args[1:]))
}
