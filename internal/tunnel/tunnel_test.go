package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/iosif2/postern/internal/identity"
)

var (
	serverAddr = netip.MustParseAddr("10.82.0.1")
	clientAddr = netip.MustParseAddr("10.82.0.2")
)

func newIdentity(t *testing.T) *identity.Software {
	t.Helper()
	id, err := identity.NewSoftware()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// newPair brings up two tunnels talking to each other over loopback UDP.
// The server only waits; the client knows the server's endpoint. edit may
// adjust the client's configuration before it comes up.
func newPair(t *testing.T, edit func(*Config)) (client, server *Tunnel) {
	t.Helper()
	serverKey, clientKey := newIdentity(t), newIdentity(t)

	server, err := Up(serverKey, Config{
		Addresses:     []netip.Addr{serverAddr},
		PeerPublicKey: clientKey.PublicKey(),
		AllowedIPs:    []netip.Prefix{netip.PrefixFrom(clientAddr, 32)},
	}, nil)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	t.Cleanup(func() { server.Close() })
	st, err := server.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.ListenPort == 0 {
		t.Fatal("server has no listen port")
	}

	cfg := Config{
		Addresses:     []netip.Addr{clientAddr},
		PeerPublicKey: serverKey.PublicKey(),
		Endpoint:      netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), st.ListenPort),
		AllowedIPs:    []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
	}
	if edit != nil {
		edit(&cfg)
	}
	client, err = Up(clientKey, cfg, nil)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client, server
}

// serveEcho runs a TCP echo service inside the server's tunnel.
func serveEcho(t *testing.T, server *Tunnel, port uint16) {
	t.Helper()
	ln, err := server.Net().ListenTCPAddrPort(netip.AddrPortFrom(serverAddr, port))
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
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func echoOnce(t *testing.T, c net.Conn, msg string) {
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

func TestDialThroughTunnel(t *testing.T) {
	client, server := newPair(t, nil)
	serveEcho(t, server, 7)

	c, err := client.DialContext(testContext(t), "tcp", "10.82.0.1:7")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	echoOnce(t, c, "through the postern")

	st, err := client.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.LastHandshake.IsZero() {
		t.Error("no handshake recorded after traffic crossed the tunnel")
	}
	if st.RxBytes == 0 || st.TxBytes == 0 {
		t.Errorf("traffic counters did not move: rx=%d tx=%d", st.RxBytes, st.TxBytes)
	}
}

func TestDialRefused(t *testing.T) {
	client, _ := newPair(t, nil)
	_, err := client.DialContext(testContext(t), "tcp", "10.82.0.1:9")
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("dialling a closed port: got %v, want connection refused", err)
	}
}

func TestKeepaliveHandshakesWithoutTraffic(t *testing.T) {
	client, _ := newPair(t, func(cfg *Config) { cfg.Keepalive = 25 * time.Second })
	when, err := client.WaitHandshake(testContext(t), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(when) > time.Minute {
		t.Errorf("handshake time %v is not recent", when)
	}
}

func TestWaitHandshakeGivesUp(t *testing.T) {
	// No keepalive and no traffic: nothing will ever handshake.
	client, _ := newPair(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := client.WaitHandshake(ctx, time.Time{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want deadline exceeded", err)
	}
}

func TestWrongPeerKeyDoesNotConnect(t *testing.T) {
	stranger := newIdentity(t)
	client, server := newPair(t, func(cfg *Config) {
		cfg.PeerPublicKey = stranger.PublicKey()
		cfg.Keepalive = 25 * time.Second
	})
	serveEcho(t, server, 7)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := client.WaitHandshake(ctx, time.Time{}); err == nil {
		t.Fatal("handshake completed with the wrong peer public key")
	}
}

// DNS names must be resolved by the resolver inside the tunnel.
func TestDialByName(t *testing.T) {
	client, server := newPair(t, func(cfg *Config) { cfg.DNS = []netip.Addr{serverAddr} })
	serveEcho(t, server, 7)
	serveDNS(t, server, map[string]netip.Addr{"nas.home.test.": serverAddr})

	c, err := client.DialContext(testContext(t), "tcp", "nas.home.test:7")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	echoOnce(t, c, "by name")

	addrs, err := client.LookupHost(testContext(t), "nas.home.test")
	if err != nil || len(addrs) != 1 || addrs[0] != serverAddr.String() {
		t.Fatalf("LookupHost = %v, %v; want %s", addrs, err, serverAddr)
	}

	_, err = client.DialContext(testContext(t), "tcp", "missing.home.test:7")
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		t.Fatalf("dialling an unknown name: got %v, want a DNS error", err)
	}
}

// serveDNS answers A queries for the given names from inside the server's
// tunnel, and NXDOMAIN for everything else.
func serveDNS(t *testing.T, server *Tunnel, records map[string]netip.Addr) {
	t.Helper()
	pc, err := server.Net().ListenUDPAddrPort(netip.AddrPortFrom(serverAddr, 53))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			hdr, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: hdr.ID, Response: true, RecursionAvailable: true})
			b.StartQuestions()
			b.Question(q)
			addr, ok := records[strings.ToLower(q.Name.String())]
			if !ok {
				b = dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: hdr.ID, Response: true, RCode: dnsmessage.RCodeNameError})
				b.StartQuestions()
				b.Question(q)
			} else if q.Type == dnsmessage.TypeA {
				b.StartAnswers()
				b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60},
					dnsmessage.AResource{A: addr.As4()})
			}
			out, err := b.Finish()
			if err != nil {
				continue
			}
			pc.WriteTo(out, from)
		}
	}()
}

func TestUpRejectsBadConfig(t *testing.T) {
	key, peer := newIdentity(t), newIdentity(t)
	good := Config{
		Addresses:     []netip.Addr{clientAddr},
		PeerPublicKey: peer.PublicKey(),
	}
	cases := map[string]func(*Config){
		"no address":       func(c *Config) { c.Addresses = nil },
		"no peer key":      func(c *Config) { c.PeerPublicKey = [KeySize]byte{} },
		"own key as peer":  func(c *Config) { c.PeerPublicKey = key.PublicKey() },
		"low-order peer":   func(c *Config) { c.PeerPublicKey = [KeySize]byte{1} },
		"listen port busy": nil, // filled in below
	}
	busy, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	// The WireGuard bind listens on both families; hold the v6 side too
	// where there is one, so the port is taken whichever it tries first.
	port := uint16(busy.LocalAddr().(*net.UDPAddr).Port)
	if busy6, err := net.ListenUDP("udp6", &net.UDPAddr{Port: int(port)}); err == nil {
		defer busy6.Close()
	}
	cases["listen port busy"] = func(c *Config) { c.ListenPort = port }

	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := good
			edit(&cfg)
			tun, err := Up(key, cfg, nil)
			if err == nil {
				tun.Close()
				t.Fatal("Up succeeded")
			}
		})
	}
	if _, err := Up(nil, good, nil); err == nil {
		t.Fatal("Up succeeded without a key")
	}
}

func TestCloseEndsConnections(t *testing.T) {
	client, server := newPair(t, nil)
	serveEcho(t, server, 7)
	c, err := client.DialContext(testContext(t), "tcp", "10.82.0.1:7")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	echoOnce(t, c, "before close")

	client.Close()
	select {
	case <-client.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done not closed after Close")
	}
	if _, err := client.DialContext(testContext(t), "tcp", "10.82.0.1:7"); err == nil {
		t.Fatal("dial succeeded on a closed tunnel")
	}
}
