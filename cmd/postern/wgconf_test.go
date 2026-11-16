package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	testPeerKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	testPSK     = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
)

// A configuration as wg-quick would accept it, including things postern
// has no use for.
var sampleConf = `# home
[Interface]
PrivateKey = ` + testPSK + `
Address = 10.82.0.2/32
Address = fd00:48::2/128
DNS = 192.168.88.1, 192.168.88.2
MTU = 1380
ListenPort = 0
PostUp = iptables -A FORWARD -i %i -j ACCEPT

[Peer]
publickey = ` + testPeerKey + ` # the router
PresharedKey = ` + testPSK + `
Endpoint = 203.0.113.5:51820
AllowedIPs = 192.168.88.0/24
AllowedIPs = 10.82.0.0/24
PersistentKeepalive = 15
`

func writeConf(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "home.conf")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestUpFromConfigFile(t *testing.T) {
	var tf tokenFlags
	var warnings bytes.Buffer
	opts, err := parseUpFlags([]string{"--config", writeConf(t, sampleConf)}, &tf, &warnings)
	if err != nil {
		t.Fatal(err)
	}
	cfg := opts.tunnel
	if cfg.PeerPublicKey != [32]byte(bytes.Repeat([]byte{7}, 32)) {
		t.Error("PublicKey not taken from the file")
	}
	if cfg.PresharedKey == nil || *cfg.PresharedKey != [32]byte(bytes.Repeat([]byte{9}, 32)) {
		t.Error("PresharedKey not taken from the file")
	}
	if got := cfg.Endpoint.String(); got != "203.0.113.5:51820" {
		t.Errorf("endpoint %s", got)
	}
	if len(cfg.Addresses) != 2 || cfg.Addresses[0].String() != "10.82.0.2" || cfg.Addresses[1].String() != "fd00:48::2" {
		t.Errorf("addresses %v", cfg.Addresses)
	}
	if len(cfg.DNS) != 2 || cfg.DNS[1].String() != "192.168.88.2" {
		t.Errorf("DNS %v", cfg.DNS)
	}
	if got := prefixes(cfg.AllowedIPs); got != "192.168.88.0/24 10.82.0.0/24" {
		t.Errorf("allowed IPs %q", got)
	}
	if cfg.MTU != 1380 || cfg.Keepalive != 15*time.Second {
		t.Errorf("MTU %d, keepalive %v", cfg.MTU, cfg.Keepalive)
	}

	w := warnings.String()
	if !strings.Contains(w, "PrivateKey is ignored") {
		t.Errorf("no warning about the PrivateKey line:\n%s", w)
	}
	if !strings.Contains(w, "postup") {
		t.Errorf("no warning about the unused PostUp line:\n%s", w)
	}
	if strings.Contains(w, testPSK) {
		t.Error("a warning repeats key material from the file")
	}
}

func TestFlagsOverrideConfigFile(t *testing.T) {
	var tf tokenFlags
	opts, err := parseUpFlags([]string{
		"--endpoint", "198.51.100.9:51820", "--config", writeConf(t, sampleConf), "--keepalive", "0",
	}, &tf, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if got := opts.tunnel.Endpoint.String(); got != "198.51.100.9:51820" {
		t.Errorf("endpoint %s, want the flag's", got)
	}
	if opts.tunnel.Keepalive != 0 {
		t.Errorf("keepalive %v, want the flag's 0", opts.tunnel.Keepalive)
	}
	if opts.tunnel.MTU != 1380 {
		t.Errorf("MTU %d, want the file's", opts.tunnel.MTU)
	}
}

// What is left unsaid in the file keeps postern's defaults.
func TestMinimalConfigFile(t *testing.T) {
	conf := "[Interface]\nAddress = 10.82.0.2/32\n[Peer]\nPublicKey = " + testPeerKey + "\nEndpoint = 203.0.113.5:51820\nAllowedIPs = 0.0.0.0/0\n"
	var tf tokenFlags
	var warnings bytes.Buffer
	opts, err := parseUpFlags([]string{"--config", writeConf(t, conf)}, &tf, &warnings)
	if err != nil {
		t.Fatal(err)
	}
	if opts.tunnel.Keepalive != 25*time.Second || opts.tunnel.PresharedKey != nil || opts.socks != "127.0.0.1:1080" {
		t.Errorf("defaults not kept: %+v", opts)
	}
	if warnings.Len() != 0 {
		t.Errorf("unexpected warnings:\n%s", warnings.String())
	}
}

func TestBadConfigFiles(t *testing.T) {
	peer := "[Peer]\nPublicKey = " + testPeerKey + "\nEndpoint = 203.0.113.5:51820\n"
	iface := "[Interface]\nAddress = 10.82.0.2/32\n"
	bad := map[string]string{
		"no peer":       iface,
		"no interface":  peer,
		"two peers":     iface + peer + peer,
		"bad key":       iface + "[Peer]\nPublicKey = AAAA\nEndpoint = 203.0.113.5:51820\n",
		"bad psk":       iface + peer + "PresharedKey = nope\n",
		"bad address":   "[Interface]\nAddress = ten\n" + peer,
		"bad keepalive": iface + peer + "PersistentKeepalive = often\n",
		"no endpoint":   iface + "[Peer]\nPublicKey = " + testPeerKey + "\n",
	}
	var tf tokenFlags
	for name, conf := range bad {
		if _, err := parseUpFlags([]string{"--config", writeConf(t, conf)}, &tf, io.Discard); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := parseUpFlags([]string{"--config", filepath.Join(t.TempDir(), "missing.conf")}, &tf, io.Discard); err == nil {
		t.Error("accepted a missing file")
	}
}
