package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/ini.v1"

	"github.com/iosif2/postern/internal/tunnel"
)

// wgConfig is what postern takes from a WireGuard configuration file.
type wgConfig struct {
	// flags holds settings that have an equivalent "postern up" flag,
	// keyed by flag name and in the form the flag accepts.
	flags map[string]string
	// presharedKey and listenPort have no flag.
	presharedKey *[tunnel.KeySize]byte
	listenPort   uint16
	// hasPrivateKey says the file contains a PrivateKey, which is ignored.
	hasPrivateKey bool
	// warnings describe settings that were present but not used.
	warnings []string
}

// Settings of the standard format, by lower-cased name, mapped to the flag
// they feed. The names are those of wg(8) and wg-quick(8).
var (
	interfaceFlags = map[string]string{"address": "address", "dns": "dns", "mtu": "mtu"}
	peerFlags      = map[string]string{
		"publickey":           "peer",
		"endpoint":            "endpoint",
		"allowedips":          "allowed-ips",
		"persistentkeepalive": "keepalive",
	}
)

// parseWGConfig reads a configuration in the format of wg(8) and
// wg-quick(8): an [Interface] section and one [Peer] section.
//
// PrivateKey is never used, because the private key is the one on the token.
// Settings that only make sense for a real network interface (routing
// tables, hook commands, firewall marks) are reported as warnings.
func parseWGConfig(data []byte) (wgConfig, error) {
	cfg := wgConfig{flags: map[string]string{}}
	file, err := ini.LoadSources(ini.LoadOptions{
		Insensitive:              true, // wg accepts any capitalisation
		AllowShadows:             true, // Address, DNS, AllowedIPs may repeat
		AllowNonUniqueSections:   true, // so a second [Peer] can be noticed
		KeyValueDelimiters:       "=",
		IgnoreInlineComment:      false,
		SpaceBeforeInlineComment: true,
	}, data)
	if err != nil {
		return cfg, err
	}

	iface, _ := file.SectionsByName("interface")
	peers, _ := file.SectionsByName("peer")
	switch {
	case len(iface) != 1:
		return cfg, fmt.Errorf("want one [Interface] section, found %d", len(iface))
	case len(peers) == 0:
		return cfg, errors.New("no [Peer] section")
	case len(peers) > 1:
		return cfg, fmt.Errorf("found %d [Peer] sections; postern connects to a single peer", len(peers))
	}

	for _, key := range iface[0].Keys() {
		value := strings.Join(key.ValueWithShadows(), ",")
		switch name := key.Name(); name {
		case "privatekey":
			cfg.hasPrivateKey = true
			cfg.warnings = append(cfg.warnings, "PrivateKey is ignored: the key on the token is used, and a private key has no business in this file")
		case "listenport":
			port, err := strconv.ParseUint(value, 10, 16)
			if err != nil {
				return cfg, fmt.Errorf("ListenPort: bad port %q", value)
			}
			cfg.listenPort = uint16(port)
		default:
			if flagName, ok := interfaceFlags[name]; ok {
				cfg.flags[flagName] = value
			} else {
				cfg.warnings = append(cfg.warnings, fmt.Sprintf("[Interface] %s is not used", name))
			}
		}
	}
	for _, key := range peers[0].Keys() {
		value := strings.Join(key.ValueWithShadows(), ",")
		switch name := key.Name(); name {
		case "presharedkey":
			psk, err := parseKey(value)
			if err != nil {
				return cfg, fmt.Errorf("PresharedKey: %w", err)
			}
			cfg.presharedKey = &psk
		case "persistentkeepalive":
			if strings.EqualFold(value, "off") {
				value = "0"
			}
			cfg.flags["keepalive"] = value
		default:
			if flagName, ok := peerFlags[name]; ok {
				cfg.flags[flagName] = value
			} else {
				cfg.warnings = append(cfg.warnings, fmt.Sprintf("[Peer] %s is not used", name))
			}
		}
	}
	return cfg, nil
}
