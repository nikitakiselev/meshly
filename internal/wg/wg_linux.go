//go:build linux

package wg

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Kernel talks to kernel WireGuard.
type Kernel struct{}

// Observe returns the device state, or nil if name is not a WireGuard
// device. The private key returned by the kernel is wiped immediately.
func (Kernel) Observe(name string) (*Device, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("open wireguard netlink: %w", err)
	}
	defer c.Close()
	d, err := c.Device(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read wireguard device %s: %w", name, err)
	}
	for i := range d.PrivateKey {
		d.PrivateKey[i] = 0
	}
	out := &Device{PublicKey: d.PublicKey.String(), ListenPort: d.ListenPort, FwMark: d.FirewallMark}
	for _, p := range d.Peers {
		for i := range p.PresharedKey {
			p.PresharedKey[i] = 0
		}
		ps := PeerState{
			PublicKey:     p.PublicKey.String(),
			Keepalive:     int(p.PersistentKeepaliveInterval / time.Second),
			LastHandshake: p.LastHandshakeTime,
			RxBytes:       p.ReceiveBytes,
			TxBytes:       p.TransmitBytes,
		}
		if p.Endpoint != nil {
			ps.Endpoint = p.Endpoint.AddrPort()
			ps.Endpoint = netip.AddrPortFrom(ps.Endpoint.Addr().Unmap(), ps.Endpoint.Port())
		}
		for _, a := range p.AllowedIPs {
			ip, ok := netip.AddrFromSlice(a.IP)
			if !ok {
				continue
			}
			ones, _ := a.Mask.Size()
			ps.AllowedIPs = append(ps.AllowedIPs, netip.PrefixFrom(ip.Unmap(), ones))
		}
		out.Peers = append(out.Peers, ps)
	}
	return out, nil
}

// Configure sets the private key, listen port and the exact peer list.
// Peers not in want are removed; existing peers are updated in place so
// established sessions survive unrelated changes.
func (Kernel) Configure(name string, priv wgtypes.Key, listenPort int, want []DesiredPeer, current *Device) error {
	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("open wireguard netlink: %w", err)
	}
	defer c.Close()
	cfg := wgtypes.Config{PrivateKey: &priv, ListenPort: &listenPort, ReplacePeers: false}
	defer func() {
		for i := range priv {
			priv[i] = 0
		}
	}()
	wanted := map[string]bool{}
	for _, p := range want {
		key, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			return fmt.Errorf("peer key: %w", err)
		}
		wanted[p.PublicKey] = true
		ka := time.Duration(p.Keepalive) * time.Second
		// Always set: the zero key clears the PSK of a peer updated in place.
		psk := p.PresharedKey
		pc := wgtypes.PeerConfig{
			PublicKey:                   key,
			ReplaceAllowedIPs:           true,
			AllowedIPs:                  []net.IPNet{{IP: p.AllowedIP.Addr().AsSlice(), Mask: net.CIDRMask(p.AllowedIP.Bits(), 32)}},
			PersistentKeepaliveInterval: &ka,
			PresharedKey:                &psk,
		}
		if p.Endpoint.IsValid() {
			pc.Endpoint = net.UDPAddrFromAddrPort(p.Endpoint)
		}
		cfg.Peers = append(cfg.Peers, pc)
	}
	if current != nil {
		for _, p := range current.Peers {
			if wanted[p.PublicKey] {
				continue
			}
			key, err := wgtypes.ParseKey(p.PublicKey)
			if err != nil {
				continue
			}
			cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{PublicKey: key, Remove: true})
		}
	}
	if err := c.ConfigureDevice(name, cfg); err != nil {
		return fmt.Errorf("configure wireguard %s: %w", name, err)
	}
	return nil
}

// RemoveAllPeers drops every peer (safe mode).
func (Kernel) RemoveAllPeers(name string) error {
	c, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer c.Close()
	return c.ConfigureDevice(name, wgtypes.Config{ReplacePeers: true})
}
