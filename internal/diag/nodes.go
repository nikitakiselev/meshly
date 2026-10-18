package diag

import "time"

// Nodes is the machine readable list of the nodes of the network, as this
// node sees them.
type Nodes struct {
	Schema  string     `json:"schema"`
	Network string     `json:"network"`
	CIDR    string     `json:"cidr"`
	Nodes   []NodeInfo `json:"nodes"`
}

// NodeInfo is one node: this one first, then the peers.
type NodeInfo struct {
	Name          string `json:"name"`
	ThisNode      bool   `json:"this_node"`
	VPNAddress    string `json:"vpn_address"`
	PublicAddress string `json:"public_address,omitempty"`
	// Connection: "this-node"; for a peer "online" (a handshake within
	// HandshakeFresh), "offline" (only an older one although keepalive keeps
	// a working link handshaking), "idle" (only an older one, keepalive is
	// off: an unused link looks the same), "never-connected", "link-stopped"
	// (the link of this node is stopped) or "unknown" (not observable: no
	// root or no interface).
	Connection  string     `json:"connection"`
	LastSeen    *time.Time `json:"last_seen,omitempty"`
	LastSeenAgo *int64     `json:"last_seen_seconds_ago,omitempty"`
	// MayUseHere lists the services of this node the peer may use.
	MayUseHere []string `json:"may_use_here"`
}

// NodesOf lists the nodes of an initialized status.
func NodesOf(st *Status) *Nodes {
	c := st.Config
	out := &Nodes{Schema: "meshly.nodes/v1", Network: c.NetworkName, CIDR: c.CIDR}
	out.Nodes = append(out.Nodes, NodeInfo{
		Name: c.Name, ThisNode: true, VPNAddress: c.Address, PublicAddress: c.Endpoint,
		Connection: "this-node", MayUseHere: []string{},
	})
	for _, p := range st.Peers {
		n := NodeInfo{
			Name: p.Name, VPNAddress: p.Address, PublicAddress: p.CurrentEndpoint,
			LastSeen: p.LastHandshake, LastSeenAgo: p.HandshakeAge, MayUseHere: p.AllowedFrom,
		}
		if n.PublicAddress == "" {
			n.PublicAddress = p.ConfiguredEndpoint
		}
		switch {
		case c.AdminState != "up":
			n.Connection = "link-stopped"
		case p.Connectivity == "handshake-recent":
			n.Connection = "online"
		case p.Connectivity == "handshake-stale" && p.Keepalive == 0:
			n.Connection = "idle"
		case p.Connectivity == "handshake-stale":
			n.Connection = "offline"
		case p.Connectivity == "no-handshake":
			n.Connection = "never-connected"
		default:
			n.Connection = "unknown"
		}
		out.Nodes = append(out.Nodes, n)
	}
	return out
}
