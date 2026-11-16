package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xproxy "golang.org/x/net/proxy"

	"github.com/iosif2/postern/internal/identity"
	"github.com/iosif2/postern/internal/tunnel"
)

var homeAddr = netip.MustParseAddr("10.82.0.1")

// syncBuffer is a log sink that can be read while it is written.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// homeServer stands in for the router: a WireGuard peer with a TCP echo
// service on port 7 inside the tunnel. It returns the options a client
// needs to reach it, minus listeners.
func homeServer(t *testing.T, client identity.Identity) upOptions {
	t.Helper()
	key, err := identity.NewSoftware()
	if err != nil {
		t.Fatal(err)
	}
	clientAddr := netip.MustParseAddr("10.82.0.2")
	server, err := tunnel.Up(key, tunnel.Config{
		Addresses:     []netip.Addr{homeAddr},
		PeerPublicKey: client.PublicKey(),
		AllowedIPs:    []netip.Prefix{netip.PrefixFrom(clientAddr, 32)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })

	ln, err := server.Net().ListenTCPAddrPort(netip.AddrPortFrom(homeAddr, 7))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()

	st, err := server.Status()
	if err != nil {
		t.Fatal(err)
	}
	return upOptions{tunnel: tunnel.Config{
		Addresses:     []netip.Addr{clientAddr},
		PeerPublicKey: key.PublicKey(),
		Endpoint:      netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), st.ListenPort),
		AllowedIPs:    []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		Keepalive:     25 * time.Second,
	}}
}

func echo(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != msg {
		t.Fatalf("echo returned %q, want %q", got, msg)
	}
}

// The whole path a user relies on: a program speaks SOCKS5 or connects to a
// forwarded port on loopback, and reaches a service on the home network.
func TestSessionEndToEnd(t *testing.T) {
	id, err := identity.NewSoftware()
	if err != nil {
		t.Fatal(err)
	}
	opts := homeServer(t, id)
	opts.socks = "127.0.0.1:0"
	opts.forwards = []forward{{listen: "127.0.0.1:0", target: "10.82.0.1:7"}}

	var log syncBuffer
	s, err := startSession(id, opts, &log)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()

	t.Run("forward", func(t *testing.T) {
		c, err := net.Dial("tcp", s.forwards[0])
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		echo(t, c, "via forward")
	})

	t.Run("socks5", func(t *testing.T) {
		d, err := xproxy.SOCKS5("tcp", s.socks, nil, &net.Dialer{Timeout: 10 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		c, err := d.Dial("tcp", "10.82.0.1:7")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		echo(t, c, "via socks")
	})

	if strings.Contains(log.String(), "warning") {
		t.Errorf("loopback listeners produced a warning:\n%s", log.String())
	}
}

func TestServeTunnelReportsConnectionAndStops(t *testing.T) {
	id, err := identity.NewSoftware()
	if err != nil {
		t.Fatal(err)
	}
	opts := homeServer(t, id)
	opts.socks = "127.0.0.1:0"

	var log syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveTunnel(ctx, id, opts, &log) }()

	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(log.String(), "connected to") {
		if time.Now().After(deadline) {
			t.Fatalf("never reported a connection; log:\n%s", log.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serveTunnel returned %v on cancellation", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serveTunnel did not stop on cancellation")
	}
}

func TestSessionListenerInUse(t *testing.T) {
	id, err := identity.NewSoftware()
	if err != nil {
		t.Fatal(err)
	}
	opts := homeServer(t, id)
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	opts.socks = taken.Addr().String()
	if s, err := startSession(id, opts, io.Discard); err == nil {
		s.close()
		t.Fatal("started with the SOCKS5 port already taken")
	}
}

func TestSessionWarnsWhenExposed(t *testing.T) {
	id, err := identity.NewSoftware()
	if err != nil {
		t.Fatal(err)
	}
	opts := homeServer(t, id)
	opts.socks = "0.0.0.0:0"
	var log syncBuffer
	s, err := startSession(id, opts, &log)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if !strings.Contains(log.String(), "warning") {
		t.Error("no warning for a listener on all interfaces")
	}
}

func TestParseUpFlags(t *testing.T) {
	peer := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	base := []string{"--peer", peer, "--endpoint", "203.0.113.5:51820", "--address", "10.82.0.2/32"}

	var tf tokenFlags
	opts, err := parseUpFlags(append(base[:len(base):len(base)],
		"--dns", "192.168.88.1", "--forward", "2222=192.168.88.10:22", "--forward", "[::1]:8443=nas.lan:443",
		"--allowed-ips", "192.168.88.7/24, 10.82.0.1"), &tf, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	cfg := opts.tunnel
	if cfg.PeerPublicKey != [32]byte(bytes.Repeat([]byte{7}, 32)) {
		t.Error("peer key not decoded")
	}
	if got := cfg.Endpoint.String(); got != "203.0.113.5:51820" {
		t.Errorf("endpoint %s", got)
	}
	if len(cfg.Addresses) != 1 || cfg.Addresses[0].String() != "10.82.0.2" {
		t.Errorf("addresses %v", cfg.Addresses)
	}
	if got := prefixes(cfg.AllowedIPs); got != "192.168.88.0/24 10.82.0.1/32" {
		t.Errorf("allowed IPs %q", got)
	}
	if len(cfg.DNS) != 1 || cfg.DNS[0].String() != "192.168.88.1" {
		t.Errorf("DNS %v", cfg.DNS)
	}
	if cfg.Keepalive != 25*time.Second || cfg.MTU != tunnel.DefaultMTU {
		t.Errorf("defaults: keepalive %v, MTU %d", cfg.Keepalive, cfg.MTU)
	}
	if opts.socks != "127.0.0.1:1080" {
		t.Errorf("socks %q", opts.socks)
	}
	want := []forward{{"127.0.0.1:2222", "192.168.88.10:22"}, {"[::1]:8443", "nas.lan:443"}}
	if len(opts.forwards) != 2 || opts.forwards[0] != want[0] || opts.forwards[1] != want[1] {
		t.Errorf("forwards %v", opts.forwards)
	}
	// No slot is assumed: the token is searched for its key.
	if tf.slot != "" {
		t.Errorf("slot %q", tf.slot)
	}

	// The defaults route everything, as a client behind one server wants.
	opts, err = parseUpFlags(base, &tf, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if got := prefixes(opts.tunnel.AllowedIPs); got != "0.0.0.0/0 ::/0" {
		t.Errorf("default allowed IPs %q", got)
	}

	bad := map[string][]string{
		"missing peer":       {"--endpoint", "203.0.113.5:51820", "--address", "10.82.0.2"},
		"short key":          {"--peer", "AAAA", "--endpoint", "203.0.113.5:51820", "--address", "10.82.0.2"},
		"endpoint no port":   {"--peer", peer, "--endpoint", "203.0.113.5", "--address", "10.82.0.2"},
		"bad address":        append(base[:4:4], "--address", "ten"),
		"bad forward":        append(base[:len(base):len(base)], "--forward", "2222"),
		"forward no port":    append(base[:len(base):len(base)], "--forward", "2222=nas.lan"),
		"nothing to serve":   append(base[:len(base):len(base)], "--socks", ""),
		"negative keepalive": append(base[:len(base):len(base)], "--keepalive", "-1"),
		"stray argument":     append(base[:len(base):len(base)], "extra"),
	}
	for name, args := range bad {
		if _, err := parseUpFlags(args, &tf, io.Discard); err == nil {
			t.Errorf("%s: accepted %v", name, args)
		}
	}
}

func prefixes(ps []netip.Prefix) string {
	var out []string
	for _, p := range ps {
		out = append(out, p.String())
	}
	return strings.Join(out, " ")
}

func TestListenAddrDefaultsToLoopback(t *testing.T) {
	for in, want := range map[string]string{
		"1080":           "127.0.0.1:1080",
		":1080":          "127.0.0.1:1080",
		"127.0.0.1:1080": "127.0.0.1:1080",
		"0.0.0.0:1080":   "0.0.0.0:1080",
		"[::1]:1080":     "[::1]:1080",
	} {
		got, err := listenAddr(in)
		if err != nil || got != want {
			t.Errorf("listenAddr(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for addr, want := range map[string]bool{
		"127.0.0.1:1080": true, "[::1]:1080": true, "localhost:1": true,
		"0.0.0.0:1080": false, "[::]:1080": false, "192.168.1.5:1080": false,
	} {
		if isLoopback(addr) != want {
			t.Errorf("isLoopback(%q) = %v", addr, !want)
		}
	}
}

// removable is an identity that can be made to disappear, like a token.
type removable struct {
	identity.Identity
	gone atomic.Bool
}

func (r *removable) Check() error {
	if r.gone.Load() {
		return errors.New("card removed")
	}
	return nil
}

func TestServeTunnelClosesWhenTokenIsRemoved(t *testing.T) {
	old := tokenCheckInterval
	tokenCheckInterval = 20 * time.Millisecond
	t.Cleanup(func() { tokenCheckInterval = old })

	sw, err := identity.NewSoftware()
	if err != nil {
		t.Fatal(err)
	}
	id := &removable{Identity: sw}
	opts := homeServer(t, id)
	opts.socks = "127.0.0.1:0"

	var log syncBuffer
	done := make(chan error, 1)
	go func() { done <- serveTunnel(context.Background(), id, opts, &log) }()

	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(log.String(), "connected to") {
		if time.Now().After(deadline) {
			t.Fatalf("never reported a connection; log:\n%s", log.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case err := <-done:
		t.Fatalf("serveTunnel stopped while the token was present: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	id.gone.Store(true)
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "token is gone") {
			t.Fatalf("serveTunnel returned %v, want it to say the token is gone", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveTunnel kept running after the token was removed")
	}
}
