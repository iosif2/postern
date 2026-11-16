package proxy

import (
	"context"
	"fmt"
	"net"

	"github.com/things-go/go-socks5"
)

// ResolveFunc looks a host name up on the far side and returns its
// addresses in textual form.
type ResolveFunc func(ctx context.Context, host string) ([]string, error)

// SOCKS5 serves the SOCKS5 protocol on ln, making the outbound connections
// through dial. It returns when ln is closed.
//
// The protocol itself is github.com/things-go/go-socks5. What is decided
// here is the policy: only CONNECT, no authentication (the listener is meant
// for loopback), and host names resolved with resolve, never by this
// machine. Clients should use socks5h:// so that they send names instead of
// resolving them locally first.
func SOCKS5(ln net.Listener, dial DialFunc, resolve ResolveFunc, logf Logf) error {
	srv := socks5.NewServer(
		socks5.WithDial(dial),
		socks5.WithResolver(resolver(resolve)),
		socks5.WithRule(&socks5.PermitCommand{EnableConnect: true}),
		socks5.WithLogger(logger(logf)),
	)
	return serve(ln, func(c net.Conn) {
		if err := srv.ServeConn(c); err != nil {
			logf.printf("socks5 %s: %v", c.RemoteAddr(), err)
		}
	})
}

// resolver adapts a ResolveFunc to the library. The library's default
// resolver asks the host's DNS, which would both leak the names being
// visited and fail to find names that only exist at home.
type resolver ResolveFunc

func (r resolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	addrs, err := r(ctx, name)
	if err != nil {
		return ctx, nil, err
	}
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil {
			return ctx, ip, nil
		}
	}
	return ctx, nil, &net.DNSError{Err: "no usable address", Name: name, IsNotFound: true}
}

type logger Logf

func (l logger) Errorf(format string, args ...any) {
	Logf(l).printf("socks5: %s", fmt.Sprintf(format, args...))
}
