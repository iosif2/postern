// Package tunnel runs a WireGuard tunnel entirely in userspace.
//
// The tunnel's IP stack lives inside the process (gVisor netstack), so no
// tunnel device, route or administrator right is involved: the only thing the
// host sees is UDP to the peer. Connections into the tunnel are made with
// Tunnel.DialContext.
package tunnel

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/iosif2/postern/internal/device"
)

// DefaultMTU is the tunnel MTU used when Config.MTU is zero: WireGuard's
// usual 1420, which fits inside a 1500-byte path over IPv4 or IPv6.
const DefaultMTU = 1420

// KeySize is the size in bytes of WireGuard keys.
const KeySize = device.NoisePublicKeySize

// Config describes a tunnel to a single peer.
type Config struct {
	// Addresses are this end's addresses inside the tunnel.
	Addresses []netip.Addr
	// DNS are resolvers reached through the tunnel. Without any, only
	// literal IP addresses can be dialled.
	DNS []netip.Addr
	// MTU of the tunnel; DefaultMTU if zero.
	MTU int
	// ListenPort is the local UDP port; zero picks a free one.
	ListenPort uint16

	// PeerPublicKey is the peer's static public key.
	PeerPublicKey [KeySize]byte
	// PresharedKey is the optional preshared key shared with the peer.
	PresharedKey *[KeySize]byte
	// Endpoint is where the peer is reached. It may be left unset for a
	// side that only waits to be contacted.
	Endpoint netip.AddrPort
	// AllowedIPs are the destinations sent to the peer and the sources
	// accepted from it.
	AllowedIPs []netip.Prefix
	// Keepalive is the persistent keepalive interval, rounded down to
	// whole seconds; zero disables it. Behind NAT it keeps the mapping
	// open, and it makes the tunnel handshake as soon as it comes up
	// instead of at the first connection.
	Keepalive time.Duration
}

// Tunnel is a running tunnel.
type Tunnel struct {
	dev  *device.Device
	net  *netstack.Net
	peer [KeySize]byte
}

// Up starts a tunnel with key as its static key. The key is used for one key
// agreement before Up returns and one per handshake afterwards. logger may
// be nil.
func Up(key device.StaticKey, cfg Config, logger *device.Logger) (*Tunnel, error) {
	if key == nil {
		return nil, errors.New("tunnel: no static key")
	}
	if len(cfg.Addresses) == 0 {
		return nil, errors.New("tunnel: no tunnel address configured")
	}
	if cfg.PeerPublicKey == key.PublicKey() {
		return nil, errors.New("tunnel: the peer's public key is this side's own public key")
	}
	if cfg.PeerPublicKey == ([KeySize]byte{}) {
		return nil, errors.New("tunnel: no peer public key configured")
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = DefaultMTU
	}
	if logger == nil {
		logger = device.NewLogger(device.LogLevelSilent, "")
	}

	tun, tnet, err := netstack.CreateNetTUN(cfg.Addresses, cfg.DNS, mtu)
	if err != nil {
		return nil, fmt.Errorf("tunnel: creating userspace network stack: %w", err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), logger)
	t := &Tunnel{dev: dev, net: tnet, peer: cfg.PeerPublicKey}

	// The key goes in before the peer. The userspace stack reports itself
	// up as soon as it exists and the device follows on its own, so by the
	// time the peer is added it may already be sending; it must not do
	// that with a placeholder key.
	if err := dev.SetStaticKey(key); err != nil {
		dev.Close()
		return nil, fmt.Errorf("tunnel: setting static key: %w", err)
	}
	if err := dev.IpcSet(cfg.uapi()); err != nil {
		dev.Close()
		return nil, fmt.Errorf("tunnel: configuring: %w", err)
	}
	// Adding a peer does not report a failed key agreement, and without
	// its result no handshake can succeed. Setting the key again redoes
	// it and says why it failed.
	if !dev.StaticSecretReady(cfg.PeerPublicKey) {
		err := dev.SetStaticKey(key)
		if err == nil && !dev.StaticSecretReady(cfg.PeerPublicKey) {
			err = errors.New("no shared secret")
		}
		if err != nil {
			dev.Close()
			return nil, fmt.Errorf("tunnel: key agreement with the peer's public key: %w", err)
		}
	}
	// The device may have brought itself up already, in which case a
	// failure to open the UDP socket was only logged, and the device then
	// forgets the requested port: a later Up quietly takes a random one.
	// So check what it ended up with, and ask again to learn the reason.
	err = dev.Up()
	if err == nil {
		var st Status
		st, err = t.Status()
		switch {
		case err != nil:
		case cfg.ListenPort != 0 && st.ListenPort != cfg.ListenPort:
			err = dev.IpcSet(fmt.Sprintf("listen_port=%d\n", cfg.ListenPort))
		case st.ListenPort == 0:
			err = dev.BindUpdate()
		}
	}
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("tunnel: bringing up: %w", err)
	}
	return t, nil
}

// uapi renders the configuration in WireGuard's cross-platform
// configuration protocol. It never contains this side's private key.
func (cfg Config) uapi() string {
	var b strings.Builder
	fmt.Fprintf(&b, "listen_port=%d\n", cfg.ListenPort)
	fmt.Fprintf(&b, "replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(cfg.PeerPublicKey[:]))
	if cfg.PresharedKey != nil {
		fmt.Fprintf(&b, "preshared_key=%s\n", hex.EncodeToString(cfg.PresharedKey[:]))
	}
	if cfg.Endpoint.IsValid() {
		fmt.Fprintf(&b, "endpoint=%s\n", cfg.Endpoint)
	}
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", int(cfg.Keepalive/time.Second))
	fmt.Fprintf(&b, "replace_allowed_ips=true\n")
	for _, prefix := range cfg.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", prefix)
	}
	return b.String()
}

// DialContext connects to address through the tunnel. network is "tcp",
// "tcp4", "tcp6" or the udp equivalents. Host names are resolved with the
// tunnel's DNS servers, never the host's.
func (t *Tunnel) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return t.net.DialContext(ctx, network, address)
}

// LookupHost resolves host with the tunnel's DNS servers.
func (t *Tunnel) LookupHost(ctx context.Context, host string) ([]string, error) {
	return t.net.LookupContextHost(ctx, host)
}

// Net exposes the tunnel's network stack, for listening inside the tunnel.
func (t *Tunnel) Net() *netstack.Net { return t.net }

// Close tears the tunnel down, along with every connection through it.
func (t *Tunnel) Close() error {
	t.dev.Close()
	return nil
}

// Done is closed once the tunnel has shut down.
func (t *Tunnel) Done() <-chan struct{} { return t.dev.Wait() }

// Status is a snapshot of the tunnel.
type Status struct {
	// ListenPort is the local UDP port in use.
	ListenPort uint16
	// LastHandshake is when the latest handshake completed; zero if none
	// has.
	LastHandshake time.Time
	// Endpoint is the peer's current address, which follows the peer if
	// it roams. It is invalid while unknown.
	Endpoint netip.AddrPort
	// RxBytes and TxBytes count the tunnel traffic with the peer.
	RxBytes, TxBytes uint64
}

// Status reports the current state of the tunnel.
func (t *Tunnel) Status() (Status, error) {
	var st Status
	raw, err := t.dev.IpcGet()
	if err != nil {
		return st, fmt.Errorf("tunnel: reading status: %w", err)
	}
	var sec, nsec int64
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		key, value, _ := strings.Cut(sc.Text(), "=")
		switch key {
		case "listen_port":
			port, _ := strconv.ParseUint(value, 10, 16)
			st.ListenPort = uint16(port)
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(value, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(value, 10, 64)
		case "endpoint":
			st.Endpoint, _ = netip.ParseAddrPort(value)
		case "rx_bytes":
			st.RxBytes, _ = strconv.ParseUint(value, 10, 64)
		case "tx_bytes":
			st.TxBytes, _ = strconv.ParseUint(value, 10, 64)
		}
	}
	if sec != 0 || nsec != 0 {
		st.LastHandshake = time.Unix(sec, nsec)
	}
	return st, nil
}

// WaitHandshake blocks until a handshake newer than after has completed, or
// ctx is done. Pass the zero time to wait for the first one. A tunnel only
// handshakes when it has something to send, so without Keepalive this waits
// until a connection is attempted.
func (t *Tunnel) WaitHandshake(ctx context.Context, after time.Time) (time.Time, error) {
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		st, err := t.Status()
		if err != nil {
			return time.Time{}, err
		}
		if st.LastHandshake.After(after) {
			return st.LastHandshake, nil
		}
		select {
		case <-ctx.Done():
			return time.Time{}, ctx.Err()
		case <-t.Done():
			return time.Time{}, errors.New("tunnel: closed")
		case <-tick.C:
		}
	}
}
