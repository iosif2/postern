package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/things-go/go-socks5/statute"
	xproxy "golang.org/x/net/proxy"
)

// listen opens a loopback listener closed at the end of the test.
func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

// echoServer returns the address of a TCP echo service.
func echoServer(t *testing.T) string {
	t.Helper()
	ln := listen(t)
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
	return ln.Addr().String()
}

// recordingDial dials the host network and records what it was asked for.
type recordingDial struct {
	asked chan string
	// rewrite, if set, replaces the requested address.
	rewrite func(string) string
	err     error
}

func (d *recordingDial) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if d.asked != nil {
		d.asked <- address
	}
	if d.err != nil {
		return nil, d.err
	}
	if d.rewrite != nil {
		address = d.rewrite(address)
	}
	var nd net.Dialer
	return nd.DialContext(ctx, network, address)
}

// localResolve stands in for the DNS at the far end of the tunnel.
type localResolve struct {
	asked   chan string
	records map[string]string
}

func (r *localResolve) resolve(ctx context.Context, host string) ([]string, error) {
	if r.asked != nil {
		r.asked <- host
	}
	if addr, ok := r.records[host]; ok {
		return []string{addr}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func startSOCKS5(t *testing.T, dial DialFunc, resolve ResolveFunc) string {
	t.Helper()
	ln := listen(t)
	done := make(chan error, 1)
	go func() { done <- SOCKS5(ln, dial, resolve, t.Logf) }()
	t.Cleanup(func() {
		ln.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("SOCKS5 returned %v after its listener closed", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("SOCKS5 did not return after its listener closed")
		}
	})
	return ln.Addr().String()
}

// socksDial connects to target through the proxy with a stock client.
func socksDial(t *testing.T, proxyAddr, target string) (net.Conn, error) {
	t.Helper()
	d, err := xproxy.SOCKS5("tcp", proxyAddr, nil, &net.Dialer{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.Dial("tcp", target)
	if err == nil {
		t.Cleanup(func() { c.Close() })
		c.SetDeadline(time.Now().Add(10 * time.Second))
	}
	return c, err
}

func expectEcho(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	if _, err := io.WriteString(c, msg); err != nil {
		t.Fatal(err)
	}
	// Half-close: the echo must still come back in full afterwards.
	if err := c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != msg {
		t.Fatalf("echo returned %q, want %q", got, msg)
	}
}

func TestSOCKS5Connect(t *testing.T) {
	echo := echoServer(t)
	d := &recordingDial{asked: make(chan string, 1)}
	r := &localResolve{asked: make(chan string, 1)}
	proxy := startSOCKS5(t, d.dial, r.resolve)

	c, err := socksDial(t, proxy, echo)
	if err != nil {
		t.Fatal(err)
	}
	if got := <-d.asked; got != echo {
		t.Errorf("dialled %q, want %q", got, echo)
	}
	expectEcho(t, c, "hello through socks")
	select {
	case name := <-r.asked:
		t.Errorf("resolved %q for a literal address", name)
	default:
	}
}

// A host name must be looked up with the resolver for the far side of the
// tunnel. This name does not exist for the machine running the test, so the
// connection can only succeed if the host's DNS was not what answered.
func TestSOCKS5ResolvesNamesOnTheFarSide(t *testing.T) {
	echo := echoServer(t)
	_, port, _ := net.SplitHostPort(echo)
	d := &recordingDial{asked: make(chan string, 1)}
	r := &localResolve{asked: make(chan string, 1), records: map[string]string{"nas.home.test": "127.0.0.1"}}
	proxy := startSOCKS5(t, d.dial, r.resolve)

	c, err := socksDial(t, proxy, net.JoinHostPort("nas.home.test", port))
	if err != nil {
		t.Fatal(err)
	}
	if got := <-r.asked; got != "nas.home.test" {
		t.Errorf("resolved %q", got)
	}
	if got := <-d.asked; got != echo {
		t.Errorf("dialled %q, want %q", got, echo)
	}
	expectEcho(t, c, "by name")
}

func TestSOCKS5UnknownNameFails(t *testing.T) {
	d := &recordingDial{asked: make(chan string, 1)}
	proxy := startSOCKS5(t, d.dial, (&localResolve{}).resolve)
	if _, err := socksDial(t, proxy, "missing.home.test:80"); err == nil {
		t.Fatal("connected to a name that does not resolve")
	}
	select {
	case addr := <-d.asked:
		t.Errorf("dialled %s for an unresolvable name", addr)
	default:
	}
}

func TestSOCKS5DialFailureIsReported(t *testing.T) {
	d := &recordingDial{err: &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}}
	proxy := startSOCKS5(t, d.dial, (&localResolve{}).resolve)
	if _, err := socksDial(t, proxy, "192.0.2.1:80"); err == nil {
		t.Fatal("client was told the connection succeeded")
	}
}

// Only CONNECT is offered: BIND and UDP ASSOCIATE would open listeners and
// UDP relays, which nothing here is meant to provide.
func TestSOCKS5OnlyConnect(t *testing.T) {
	d := &recordingDial{asked: make(chan string, 1)}
	proxy := startSOCKS5(t, d.dial, (&localResolve{}).resolve)
	for _, cmd := range []byte{statute.CommandBind, statute.CommandAssociate} {
		c, err := net.Dial("tcp", proxy)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		// Greeting offering no authentication, then the request, as raw
		// bytes: stock clients cannot be made to send these commands.
		req := []byte{statute.VersionSocks5, 1, statute.MethodNoAuth}
		req = append(req, statute.VersionSocks5, cmd, 0, statute.ATYPIPv4, 192, 0, 2, 1, 0, 80)
		if _, err := c.Write(req); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, 2+4)
		if _, err := io.ReadFull(c, reply); err != nil {
			t.Fatal(err)
		}
		if reply[3] == statute.RepSuccess {
			t.Errorf("command %#x was accepted", cmd)
		}
	}
	select {
	case addr := <-d.asked:
		t.Errorf("an unsupported command dialled %s", addr)
	default:
	}
}

func TestForward(t *testing.T) {
	echo := echoServer(t)
	d := &recordingDial{asked: make(chan string, 1), rewrite: func(string) string { return echo }}
	ln := listen(t)
	done := make(chan error, 1)
	go func() { done <- Forward(ln, d.dial, "192.168.88.10:22", t.Logf) }()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if got := <-d.asked; got != "192.168.88.10:22" {
		t.Errorf("dialled %q, want the forward target", got)
	}
	expectEcho(t, c, "forwarded")

	ln.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Forward returned %v after its listener closed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Forward did not return after its listener closed")
	}
}

func TestForwardDialFailureClosesClient(t *testing.T) {
	ln := listen(t)
	go Forward(ln, (&recordingDial{err: errors.New("tunnel down")}).dial, "192.168.88.10:22", nil)
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if n, _ := c.Read(make([]byte, 1)); n != 0 {
		t.Fatal("got data from a forward whose target is unreachable")
	}
}

// Closing the listener must not wait for clients that are still connected.
func TestShutdownClosesOpenConnections(t *testing.T) {
	echo := echoServer(t)
	ln := listen(t)
	done := make(chan error, 1)
	go func() { done <- SOCKS5(ln, (&recordingDial{}).dial, (&localResolve{}).resolve, nil) }()

	c, err := socksDial(t, ln.Addr().String(), echo)
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("SOCKS5 did not return while a client was still connected")
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("client connection still open after shutdown")
	}
}
