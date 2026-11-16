// Package proxy carries local TCP connections into a tunnel: a SOCKS5 server
// and fixed port forwards. Both take the tunnel as a dial function, so they
// know nothing about WireGuard.
package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// DialFunc opens a connection to address on the far side.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// dialTimeout bounds how long a single outbound connection attempt may take.
const dialTimeout = 30 * time.Second

// Logf receives one line per noteworthy event. It may be nil.
type Logf func(format string, args ...any)

func (l Logf) printf(format string, args ...any) {
	if l != nil {
		l(format, args...)
	}
}

// serve accepts connections from ln until it is closed, running handle for
// each. It returns nil when ln was closed, and otherwise the accept error.
// It waits for the handlers that are still running before returning.
func serve(ln net.Listener, handle func(net.Conn)) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	// Closing the listener must also end connections in flight, or a
	// shutdown would wait on idle clients for ever.
	var mu sync.Mutex
	open := map[net.Conn]struct{}{}
	defer func() {
		mu.Lock()
		for c := range open {
			c.Close()
		}
		mu.Unlock()
	}()

	var delay time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			// Running out of file descriptors and the like passes;
			// back off rather than give up the listener.
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				delay = min(max(2*delay, 5*time.Millisecond), time.Second)
				time.Sleep(delay)
				continue
			}
			return err
		}
		delay = 0
		mu.Lock()
		open[c] = struct{}{}
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				c.Close()
				mu.Lock()
				delete(open, c)
				mu.Unlock()
			}()
			handle(c)
		}()
	}
}

// Forward accepts connections on ln and connects each one to target through
// dial. It returns when ln is closed.
func Forward(ln net.Listener, dial DialFunc, target string, logf Logf) error {
	return serve(ln, func(c net.Conn) {
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		remote, err := dial(ctx, "tcp", target)
		cancel()
		if err != nil {
			logf.printf("forward %s -> %s: %v", ln.Addr(), target, err)
			return
		}
		defer remote.Close()
		relay(c, remote)
	})
}

// relay copies in both directions until both are finished. When one side
// stops sending, that is passed on as a half-close so the other side can
// still finish its reply.
func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		copyHalf(a, b)
	}()
	go func() {
		defer wg.Done()
		copyHalf(b, a)
	}()
	wg.Wait()
}

func copyHalf(dst, src net.Conn) {
	_, err := io.Copy(dst, src)
	if err != nil {
		// A broken direction cannot be told apart from a finished one
		// by the far end; take the whole connection down.
		dst.Close()
		src.Close()
		return
	}
	if hc, ok := dst.(interface{ CloseWrite() error }); ok {
		hc.CloseWrite()
	} else {
		dst.Close()
	}
}
