package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/iosif2/postern/internal/device"
	"github.com/iosif2/postern/internal/identity"
	"github.com/iosif2/postern/internal/proxy"
	"github.com/iosif2/postern/internal/tunnel"
)

// upOptions is everything "postern up" needs besides the static key.
type upOptions struct {
	tunnel   tunnel.Config
	socks    string    // listen address of the SOCKS5 server; empty for none
	forwards []forward // fixed port forwards
	verbose  bool
}

// forward is one local listener connected to one address inside the tunnel.
type forward struct {
	listen string
	target string
}

const upLong = `Opens the tunnel with the token's key and serves a SOCKS5 proxy and port
forwards into it. Nothing on this machine is reconfigured and no
administrator rights are needed; only programs pointed at the proxy or at a
forwarded port use the tunnel.

With no settings given, the configuration stored on the token is used (see
"postern conf edit"). A --config file is a WireGuard configuration as wg and
wg-quick read it, without the PrivateKey line. Flags take precedence over
either.

Use socks5h:// with the proxy, so that names are resolved at home rather
than by the machine you are on.`

const upExample = `postern up
postern up --forward 2222=192.168.88.10:22
postern up --config home.conf
curl -x socks5h://127.0.0.1:1080 http://nas.lan/`

func upCmd() *cobra.Command {
	var tf tokenFlags
	cmd := &cobra.Command{
		Use:     "up",
		Short:   "Open the tunnel; serve SOCKS5 and port forwards into it",
		Long:    upLong,
		Example: upExample,
		Args:    cobra.NoArgs,
	}
	p := registerUp(cmd.Flags(), &tf, os.Stderr)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if err := p.check(&tf); err != nil {
			return err
		}
		return runUp(cmd.Context(), p, &tf)
	}
	return cmd
}

// upParse is a "postern up" command line being turned into options. The
// configuration may come from a file or from the token, and the token is
// only opened once the flags are known, hence the stages.
type upParse struct {
	fs     *pflag.FlagSet
	errOut io.Writer
	opts   upOptions

	config, peer, endpoint, address, allowed, dns *string
	keepalive, mtu                                *int
	forwards                                      []string
	// source names where the configuration came from, for messages.
	source string
}

// registerUp defines the flags of "postern up" on fs.
func registerUp(fs *pflag.FlagSet, tf *tokenFlags, errOut io.Writer) *upParse {
	p := &upParse{fs: fs, errOut: errOut}
	tf.register(fs)
	tf.registerConf(fs)
	p.config = fs.StringP("config", "c", "", "take the settings below from this WireGuard configuration file instead of the token")
	p.peer = fs.String("peer", "", "the server's public key, in base64 (PublicKey)")
	p.endpoint = fs.String("endpoint", "", "the server's host:port (Endpoint)")
	p.address = fs.String("address", "", "this side's tunnel addresses, comma separated (Address)")
	p.allowed = fs.String("allowed-ips", "0.0.0.0/0,::/0", "destinations reachable through the tunnel, comma separated (AllowedIPs)")
	p.dns = fs.String("dns", "", "resolvers reached through the tunnel, comma separated; needed to connect by name (DNS)")
	p.keepalive = fs.Int("keepalive", 25, "seconds between keepalives, 0 to send none (PersistentKeepalive)")
	p.mtu = fs.Int("mtu", tunnel.DefaultMTU, "size of the largest packet in the tunnel (MTU)")
	fs.StringVar(&p.opts.socks, "socks", "127.0.0.1:1080", "listen address of the SOCKS5 proxy; a bare port means loopback, \"\" disables")
	fs.StringArrayVar(&p.forwards, "forward", nil, "forward LOCAL=HOST:PORT, e.g. 2222=192.168.88.10:22; may be repeated")
	fs.BoolVarP(&p.opts.verbose, "verbose", "v", false, "log tunnel and connection events")
	return p
}

// check rejects combinations of flags that contradict each other.
func (p *upParse) check(tf *tokenFlags) error {
	if *p.config != "" && tf.confSlot != "" {
		return errors.New("--config and --conf-slot both name a configuration; give one")
	}
	return nil
}

// newUpParse parses a command line by itself, without the command tree.
func newUpParse(args []string, tf *tokenFlags, errOut io.Writer) (*upParse, error) {
	fs := pflag.NewFlagSet("up", pflag.ContinueOnError)
	fs.SetOutput(errOut)
	p := registerUp(fs, tf, errOut)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	return p, p.check(tf)
}

// needsConfig reports whether the flags alone do not say where to connect.
func (p *upParse) needsConfig() bool {
	return *p.peer == "" || *p.endpoint == "" || *p.address == ""
}

// apply takes from a configuration whatever was not given as a flag. source
// says where the configuration is from.
func (p *upParse) apply(data []byte, source string) error {
	file, err := parseWGConfig(data)
	if err != nil {
		return fmt.Errorf("%s: %w", source, err)
	}
	given := map[string]bool{}
	p.fs.Visit(func(f *pflag.Flag) { given[f.Name] = true })
	for name, value := range file.flags {
		if given[name] {
			continue
		}
		if err := p.fs.Set(name, value); err != nil {
			return fmt.Errorf("%s: %s: %w", source, name, err)
		}
	}
	p.opts.tunnel.PresharedKey = file.presharedKey
	p.opts.tunnel.ListenPort = file.listenPort
	for _, w := range file.warnings {
		fmt.Fprintf(p.errOut, "warning: %s: %s\n", source, w)
	}
	p.source = source
	return nil
}

// finish checks the settings and turns them into options. resolve finds the
// endpoint's address.
func (p *upParse) finish(resolve func(string) (netip.AddrPort, error)) (upOptions, error) {
	opts := p.opts
	var err error
	cfg := &opts.tunnel
	if p.needsConfig() {
		if p.source != "" {
			return opts, fmt.Errorf("%s: PublicKey, Endpoint and Address are all required", p.source)
		}
		return opts, errors.New("the server's public key, its endpoint and this side's address are required: give --config, or --peer, --endpoint and --address")
	}
	if cfg.PeerPublicKey, err = parseKey(*p.peer); err != nil {
		return opts, fmt.Errorf("peer public key: %w", err)
	}
	if cfg.Addresses, err = parseList(*p.address, parseTunnelAddr); err != nil {
		return opts, fmt.Errorf("address: %w", err)
	}
	if cfg.AllowedIPs, err = parseList(*p.allowed, parsePrefix); err != nil {
		return opts, fmt.Errorf("allowed IPs: %w", err)
	}
	if cfg.DNS, err = parseList(*p.dns, netip.ParseAddr); err != nil {
		return opts, fmt.Errorf("DNS: %w", err)
	}
	if *p.keepalive < 0 || *p.keepalive > 65535 {
		return opts, errors.New("keepalive: want 0 to 65535 seconds")
	}
	cfg.Keepalive = time.Duration(*p.keepalive) * time.Second
	if *p.mtu < 576 || *p.mtu > 65535 {
		return opts, errors.New("MTU: want 576 to 65535")
	}
	cfg.MTU = *p.mtu
	if cfg.Endpoint, err = resolve(*p.endpoint); err != nil {
		return opts, fmt.Errorf("endpoint: %w", err)
	}

	if opts.socks != "" {
		if opts.socks, err = listenAddr(opts.socks); err != nil {
			return opts, fmt.Errorf("--socks: %w", err)
		}
	}
	for _, f := range p.forwards {
		local, target, ok := strings.Cut(f, "=")
		if !ok {
			return opts, fmt.Errorf("--forward %q: want LOCAL=HOST:PORT", f)
		}
		if local, err = listenAddr(local); err != nil {
			return opts, fmt.Errorf("--forward %q: %w", f, err)
		}
		if err := checkHostPort(target); err != nil {
			return opts, fmt.Errorf("--forward %q: target: %w", f, err)
		}
		opts.forwards = append(opts.forwards, forward{listen: local, target: target})
	}
	if opts.socks == "" && len(opts.forwards) == 0 {
		return opts, errors.New("nothing to serve: --socks is disabled and there is no --forward")
	}
	return opts, nil
}

// applyFile applies the file named by -config, if any.
func (p *upParse) applyFile() error {
	if *p.config == "" {
		return nil
	}
	data, err := os.ReadFile(*p.config)
	if err != nil {
		return err
	}
	return p.apply(data, *p.config)
}

// parseUpFlags parses a command line that does not rely on the token for
// its configuration.
func parseUpFlags(args []string, tf *tokenFlags, errOut io.Writer) (upOptions, error) {
	p, err := newUpParse(args, tf, errOut)
	if err != nil {
		return upOptions{}, err
	}
	if err := p.applyFile(); err != nil {
		return upOptions{}, err
	}
	return p.finish(resolveEndpoint)
}

// parseKey decodes a WireGuard key in its usual base64 form.
func parseKey(s string) (key [tunnel.KeySize]byte, err error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return key, errors.New("not valid base64")
	}
	if len(raw) != len(key) {
		return key, fmt.Errorf("decodes to %d bytes, want %d", len(raw), len(key))
	}
	copy(key[:], raw)
	return key, nil
}

func parseList[T any](s string, parse func(string) (T, error)) ([]T, error) {
	var out []T
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		v, err := parse(item)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// parseTunnelAddr accepts an address with or without a prefix length, since
// WireGuard configurations usually write Address = 10.0.0.2/32.
func parseTunnelAddr(s string) (netip.Addr, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p.Addr(), err
	}
	return netip.ParseAddr(s)
}

// parsePrefix accepts a prefix, or a bare address meaning that one host.
func parsePrefix(s string) (netip.Prefix, error) {
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	return p.Masked(), err
}

// resolveEndpoint turns host:port into an address, using this machine's
// resolver: the endpoint is the one name that has to be found outside the
// tunnel.
func resolveEndpoint(s string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap, nil
	}
	if err := checkHostPort(s); err != nil {
		return netip.AddrPort{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	host, port, _ := net.SplitHostPort(s)
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if len(addrs) == 0 {
		return netip.AddrPort{}, fmt.Errorf("%s has no addresses", host)
	}
	p, _ := strconv.ParseUint(port, 10, 16)
	// Prefer IPv4: a network that hands out an IPv6 address does not
	// always carry it anywhere.
	pick := addrs[0]
	for _, a := range addrs {
		if a.Unmap().Is4() {
			pick = a
			break
		}
	}
	return netip.AddrPortFrom(pick.Unmap(), uint16(p)), nil
}

func checkHostPort(s string) error {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return errors.New("want host:port")
	}
	if host == "" {
		return errors.New("missing host")
	}
	if p, err := strconv.ParseUint(port, 10, 16); err != nil || p == 0 {
		return fmt.Errorf("bad port %q", port)
	}
	return nil
}

// listenAddr normalises a local listen address. A bare port listens on
// loopback only: what is served here is a door into the home network, and
// it must not be opened to whatever network this machine happens to be on
// unless that is asked for by writing out an address.
func listenAddr(s string) (string, error) {
	if p, err := strconv.ParseUint(s, 10, 16); err == nil {
		return net.JoinHostPort("127.0.0.1", strconv.FormatUint(p, 10)), nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", errors.New("want a port or host:port")
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return "", fmt.Errorf("bad port %q", port)
	}
	if host == "" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), nil
}

// isLoopback reports whether a listen address is only reachable from this
// machine.
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func runUp(ctx context.Context, p *upParse, tf *tokenFlags) error {
	if err := p.applyFile(); err != nil {
		return err
	}

	card, err := tf.resolve()
	if err != nil {
		return err
	}
	yk, err := identity.Open(card)
	if err != nil {
		return err
	}
	token, opts, err := openForUp(yk, tf, p)
	if err != nil {
		yk.Close()
		return err
	}
	defer token.Close()

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serveTunnel(ctx, token, opts, os.Stderr)
}

// openForUp completes the options, from the token's stored configuration if
// the command line left it to that, and then unlocks the key. The PIN is
// asked for last, once everything else is known to be in order.
func openForUp(yk *piv.YubiKey, tf *tokenFlags, p *upParse) (*identity.PIV, upOptions, error) {
	states, err := identity.Slots(yk)
	if err != nil {
		return nil, upOptions{}, err
	}
	var slot piv.Slot
	note := ""
	if tf.slot != "" {
		slot, err = identity.ParseSlot(tf.slot)
	} else {
		var marked bool
		if slot, marked, err = identity.PickKey(states); err == nil && !marked {
			note = " (not marked as postern's; it is the only X25519 key on the token)"
		}
	}
	if err != nil {
		return nil, upOptions{}, err
	}
	if tf.confSlot != "" || (*p.config == "" && p.needsConfig()) {
		st, err := pickConfig(states, &slot, tf.confSlot)
		if err != nil {
			return nil, upOptions{}, err
		}
		if err := p.apply(st.Config, fmt.Sprintf("configuration in slot %s", st.Slot)); err != nil {
			return nil, upOptions{}, err
		}
	}
	// Say what is about to be used before asking for the PIN, so that a
	// wrong guess can still be backed out of.
	from := p.source
	if from == "" {
		from = "settings from the command line"
	}
	fmt.Fprintf(p.errOut, "key in slot %s%s, %s\n", slot, note, from)
	opts, err := p.finish(resolveEndpoint)
	if err != nil {
		return nil, upOptions{}, err
	}
	token, err := identity.Unlock(yk, slot, promptPIN)
	return token, opts, err
}

// session is a running tunnel with its listeners.
type session struct {
	tun       *tunnel.Tunnel
	listeners []net.Listener
	errs      chan error
	// socks and forwards are the addresses actually listened on.
	socks    string
	forwards []string
}

// startSession opens the local listeners, brings the tunnel up and starts
// serving. Listeners come first so that an occupied port is reported before
// the token is asked to do anything.
func startSession(id identity.Identity, opts upOptions, log io.Writer) (*session, error) {
	s := &session{errs: make(chan error, 1+len(opts.forwards))}
	ok := false
	defer func() {
		if !ok {
			s.close()
		}
	}()

	listen := func(addr string) (net.Listener, error) {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		s.listeners = append(s.listeners, ln)
		if !isLoopback(addr) {
			fmt.Fprintf(log, "warning: %s is reachable from other machines, and it leads into the tunnel\n", ln.Addr())
		}
		return ln, nil
	}
	var socksLn net.Listener
	if opts.socks != "" {
		ln, err := listen(opts.socks)
		if err != nil {
			return nil, fmt.Errorf("SOCKS5 listener: %w", err)
		}
		socksLn = ln
		s.socks = ln.Addr().String()
	}
	forwardLns := make([]net.Listener, len(opts.forwards))
	for i, f := range opts.forwards {
		ln, err := listen(f.listen)
		if err != nil {
			return nil, fmt.Errorf("forward to %s: %w", f.target, err)
		}
		forwardLns[i] = ln
		s.forwards = append(s.forwards, ln.Addr().String())
	}

	var logf proxy.Logf
	if opts.verbose {
		logf = func(format string, args ...any) { fmt.Fprintf(log, format+"\n", args...) }
	}
	tun, err := tunnel.Up(id, opts.tunnel, &device.Logger{
		Verbosef: deviceLog(log, opts.verbose),
		Errorf:   deviceLog(log, true),
	})
	if err != nil {
		return nil, err
	}
	s.tun = tun

	if socksLn != nil {
		go func() { s.errs <- proxy.SOCKS5(socksLn, tun.DialContext, tun.LookupHost, logf) }()
	}
	for i, f := range opts.forwards {
		go func() { s.errs <- proxy.Forward(forwardLns[i], tun.DialContext, f.target, logf) }()
	}
	ok = true
	return s, nil
}

func deviceLog(w io.Writer, enabled bool) func(string, ...any) {
	if !enabled {
		return func(string, ...any) {}
	}
	return func(format string, args ...any) { fmt.Fprintf(w, "wireguard: "+format+"\n", args...) }
}

func (s *session) close() {
	for _, ln := range s.listeners {
		ln.Close()
	}
	if s.tun != nil {
		s.tun.Close()
	}
}

// firstHandshakeWait is how long to wait for the server before saying that
// something looks wrong. A handshake is retried every five seconds.
const firstHandshakeWait = 12 * time.Second

// tokenCheckInterval is how often the token is asked whether it is still
// there. Pulling the token is how the user shuts the door, so it has to be
// noticed well before the next rekey would stumble over it.
var tokenCheckInterval = 2 * time.Second

// checker is implemented by identities that can go away while in use.
type checker interface {
	Check() error
}

// watchToken returns a channel that reports the first failed check of id.
// Identities that cannot go away are not watched.
func watchToken(ctx context.Context, id identity.Identity) <-chan error {
	gone := make(chan error, 1)
	c, ok := id.(checker)
	if !ok {
		return gone
	}
	go func() {
		tick := time.NewTicker(tokenCheckInterval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if err := c.Check(); err != nil {
					gone <- err
					return
				}
			}
		}
	}()
	return gone
}

// serveTunnel runs a session until ctx is done, the token goes away or
// something fails.
//
// The tunnel is closed as soon as the token is gone, rather than left to run
// on its session keys until they expire a few minutes later: on a borrowed
// machine, taking the token out has to mean the way home is shut. Coming
// back means running postern again, which asks for the PIN again.
func serveTunnel(ctx context.Context, id identity.Identity, opts upOptions, log io.Writer) error {
	s, err := startSession(id, opts, log)
	if err != nil {
		return err
	}
	defer s.close()

	if s.socks != "" {
		fmt.Fprintf(log, "SOCKS5 proxy on %s (use socks5h:// so names resolve at home)\n", s.socks)
	}
	for i, f := range opts.forwards {
		fmt.Fprintf(log, "forwarding %s -> %s\n", s.forwards[i], f.target)
	}

	// Report whether the server answers. Without a keepalive the tunnel
	// stays silent until first used, so there is nothing to wait for.
	if opts.tunnel.Keepalive > 0 {
		go func() {
			hctx, cancel := context.WithTimeout(ctx, firstHandshakeWait)
			defer cancel()
			_, err := s.tun.WaitHandshake(hctx, time.Time{})
			switch {
			case err == nil:
				fmt.Fprintf(log, "connected to %s\n", opts.tunnel.Endpoint)
			case ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded):
				fmt.Fprintf(log, "no answer from %s yet; still trying. Check the endpoint, the server's public key, and that the server has this token's public key as a peer.\n", opts.tunnel.Endpoint)
			}
		}()
	}

	wctx, stopWatch := context.WithCancel(ctx)
	defer stopWatch()
	select {
	case <-ctx.Done():
		fmt.Fprintln(log, "closing")
		return nil
	case err := <-watchToken(wctx, id):
		return fmt.Errorf("tunnel closed, the token is gone: %w", err)
	case <-s.tun.Done():
		return errors.New("tunnel closed unexpectedly")
	case err := <-s.errs:
		if err == nil {
			err = errors.New("a listener closed unexpectedly")
		}
		return err
	}
}
