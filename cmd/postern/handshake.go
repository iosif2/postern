package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/iosif2/postern/internal/device"
	"github.com/iosif2/postern/internal/identity"
)

func pivHandshakeCmd() *cobra.Command {
	var tf tokenFlags
	var rounds int
	cmd := &cobra.Command{
		Use:   "handshake",
		Short: "Run WireGuard handshakes in-process with the token's key",
		Long: `Runs both ends of a tunnel inside the process, one keyed by the token, and
reports how long each handshake took. It needs no server.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error { return pivHandshake(tf, rounds) },
	}
	tf.register(cmd.Flags())
	cmd.Flags().IntVarP(&rounds, "rounds", "n", 3, "number of handshakes to run")
	return cmd
}

func pivHandshake(tf tokenFlags, rounds int) error {
	card, err := tf.resolve()
	if err != nil {
		return err
	}
	token, err := identity.OpenPIV(card, tf.slot, promptPIN)
	if err != nil {
		return err
	}
	defer token.Close()

	times, err := loopbackHandshakes(token, rounds)
	for i, d := range times {
		fmt.Printf("handshake %d: ok (%s)\n", i+1, d.Round(time.Millisecond))
	}
	if err != nil {
		return err
	}
	fmt.Printf("all %d handshakes completed with the static key on the token\n", len(times))
	return nil
}

// handshakeTimeout is how long a packet may take to cross the loopback
// tunnel. It covers one retry of a lost handshake. Tests shorten it.
var handshakeTimeout = 10 * time.Second

// handshakeGap separates forced handshakes; see loopbackHandshakes.
const handshakeGap = 200 * time.Millisecond

// loopbackHandshakes runs a WireGuard tunnel inside this process between a
// device whose static key is id and a throwaway software peer, with no
// sockets or tunnel devices involved. It forces rounds handshakes, each
// initiated by id's side, and checks that a packet crosses in both
// directions under every one. It returns how long each handshake took to
// carry its first packet.
func loopbackHandshakes(id identity.Identity, rounds int) ([]time.Duration, error) {
	remote, err := identity.NewSoftware()
	if err != nil {
		return nil, err
	}
	keys := [2]identity.Identity{id, remote}
	addrs := [2]netip.Addr{netip.MustParseAddr("10.82.0.1"), netip.MustParseAddr("10.82.0.2")}
	binds := bindtest.NewChannelBinds()

	var (
		devs [2]*device.Device
		tuns [2]*tuntest.ChannelTUN
	)
	for i := range devs {
		tuns[i] = tuntest.NewChannelTUN()
		devs[i] = device.NewDevice(tuns[i].TUN(), binds[i], device.NewLogger(device.LogLevelSilent, ""))
		defer devs[i].Close()
		if err := devs[i].SetStaticKey(keys[i]); err != nil {
			return nil, fmt.Errorf("setting static key: %w", err)
		}
		if err := devs[i].IpcSet("listen_port=0\n"); err != nil {
			return nil, err
		}
		if err := devs[i].Up(); err != nil {
			return nil, err
		}
	}
	// The channel binds deliver to each other whatever the endpoint says,
	// but a peer needs one before it will send.
	for i := range devs {
		peerPub := keys[i^1].PublicKey()
		cfg := fmt.Sprintf("public_key=%s\nendpoint=127.0.0.1:1\nallowed_ip=%s/32\n",
			hex.EncodeToString(peerPub[:]), addrs[i^1])
		if err := devs[i].IpcSet(cfg); err != nil {
			return nil, fmt.Errorf("adding peer: %w", err)
		}
	}

	// send pushes one packet in at the from side and waits for it to come
	// out at the other.
	send := func(from int) error {
		to := from ^ 1
		msg := tuntest.Ping(addrs[to], addrs[from])
		tuns[from].Outbound <- msg
		select {
		case got := <-tuns[to].Inbound:
			if !bytes.Equal(got, msg) {
				return errors.New("packet was altered in transit")
			}
			return nil
		case <-time.After(handshakeTimeout):
			return errors.New("timed out waiting for the packet; the handshake did not complete")
		}
	}

	var times []time.Duration
	for round := 0; round < rounds; round++ {
		if round > 0 {
			// Throw away the session keys so the next packet needs a
			// fresh handshake, as a rekey would. The responder drops
			// initiations that follow each other too closely as a
			// flood, and the initiator would then wait out a five
			// second retry, so leave a gap first.
			time.Sleep(handshakeGap)
			devs[0].LookupPeer(remote.PublicKey()).ExpireCurrentKeypairs()
		}
		start := time.Now()
		if err := send(0); err != nil {
			return times, fmt.Errorf("handshake %d: %w", round+1, err)
		}
		elapsed := time.Since(start)
		if err := send(1); err != nil {
			return times, fmt.Errorf("handshake %d, return direction: %w", round+1, err)
		}
		times = append(times, elapsed)
	}
	return times, nil
}
