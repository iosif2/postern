/* SPDX-License-Identifier: MIT
 *
 * This file is not part of upstream wireguard-go. See UPSTREAM.md.
 */

package device

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/iosif2/postern/internal/identity"
)

// identity.Identity is what postern hands to the device.
var _ StaticKey = identity.Identity(nil)

// opaqueKey is a StaticKey the device cannot see inside, standing in for a
// hardware token. It counts key agreements and can be made to fail.
type opaqueKey struct {
	id    identity.Identity
	calls atomic.Int64
	fail  atomic.Bool
}

var errTokenGone = errors.New("token gone")

func newOpaqueKey(tb testing.TB) *opaqueKey {
	tb.Helper()
	id, err := identity.NewSoftware()
	if err != nil {
		tb.Fatal(err)
	}
	return &opaqueKey{id: id}
}

func (k *opaqueKey) PublicKey() [NoisePublicKeySize]byte { return k.id.PublicKey() }

func (k *opaqueKey) ECDH(peer [NoisePublicKeySize]byte) ([NoisePublicKeySize]byte, error) {
	k.calls.Add(1)
	if k.fail.Load() {
		// Return garbage alongside the error: the device must not use it.
		return [NoisePublicKeySize]byte{1, 2, 3}, errTokenGone
	}
	return k.id.ECDH(peer)
}

// genOpaquePair is genTestPair with both static keys behind StaticKey, and
// no private key ever given to either device.
func genOpaquePair(tb testing.TB) (pair testPair, keys [2]*opaqueKey) {
	tb.Helper()
	keys[0], keys[1] = newOpaqueKey(tb), newOpaqueKey(tb)
	binds := bindtest.NewChannelBinds()
	for i := range pair {
		p := &pair[i]
		p.tun = tuntest.NewChannelTUN()
		p.ip = netip.AddrFrom4([4]byte{1, 0, 0, byte(i + 1)})
		p.dev = NewDevice(p.tun.TUN(), binds[i], NewLogger(LogLevelError, fmt.Sprintf("dev%d: ", i)))
		tb.Cleanup(p.dev.Close)
		if err := p.dev.SetStaticKey(keys[i]); err != nil {
			tb.Fatalf("setting static key %d: %v", i, err)
		}
		peerPub := keys[i^1].PublicKey()
		cfg := uapiCfg(
			"listen_port", "0",
			"replace_peers", "true",
			"public_key", hex.EncodeToString(peerPub[:]),
			"protocol_version", "1",
			"replace_allowed_ips", "true",
			"allowed_ip", fmt.Sprintf("1.0.0.%d/32", (i^1)+1),
		)
		if err := p.dev.IpcSet(cfg); err != nil {
			tb.Fatalf("configuring device %d: %v", i, err)
		}
		if err := p.dev.Up(); err != nil {
			tb.Fatalf("bringing up device %d: %v", i, err)
		}
	}
	for i := range pair {
		peerPub := keys[i^1].PublicKey()
		cfg := uapiCfg(
			"public_key", hex.EncodeToString(peerPub[:]),
			"endpoint", fmt.Sprintf("127.0.0.1:%d", pair[i^1].dev.net.port),
		)
		if err := pair[i].dev.IpcSet(cfg); err != nil {
			tb.Fatalf("configuring endpoint %d: %v", i, err)
		}
	}
	return
}

func TestStaticKeyTunnel(t *testing.T) {
	goroutineLeakCheck(t)
	pair, keys := genOpaquePair(t)

	// Adding the peer precomputes the static-static secret: one call each.
	for i, k := range keys {
		if n := k.calls.Load(); n != 1 {
			t.Errorf("key %d: %d key agreements after setup, want 1", i, n)
		}
	}

	pair.Send(t, Ping, nil)
	pair.Send(t, Pong, nil)

	// One handshake has happened, costing each side exactly one more key
	// agreement, whichever side initiated. This is the per-handshake load
	// a token has to carry.
	for i, k := range keys {
		if n := k.calls.Load(); n != 2 {
			t.Errorf("key %d: %d key agreements after first handshake, want 2", i, n)
		}
	}

	for i := range pair {
		got, err := pair[i].dev.IpcGet()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(got, "private_key") {
			t.Errorf("device %d reports a private key over UAPI", i)
		}
	}
}

func TestStaticKeyFailure(t *testing.T) {
	key := newOpaqueKey(t)
	remote := newOpaqueKey(t)
	dev := NewDevice(tuntest.NewChannelTUN().TUN(), bindtest.NewChannelBinds()[0], NewLogger(LogLevelSilent, ""))
	defer dev.Close()

	if err := dev.SetStaticKey(nil); err == nil {
		t.Error("SetStaticKey(nil) succeeded")
	}

	// With the key failing, the peer is added but cannot handshake, and
	// whatever the failed call returned is not used as a secret.
	key.fail.Store(true)
	if err := dev.SetStaticKey(key); err != nil {
		t.Fatalf("SetStaticKey with no peers: %v", err)
	}
	peer, err := dev.NewPeer(remote.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if !isZero(peer.handshake.precomputedStaticStatic[:]) {
		t.Fatal("failed key agreement left a non-zero static-static secret")
	}
	if _, err := dev.CreateMessageInitiation(peer); err == nil {
		t.Fatal("created a handshake initiation without a static-static secret")
	}
	if err := dev.SetStaticKey(key); !errors.Is(err, errTokenGone) {
		t.Fatalf("SetStaticKey with a failing key: got %v, want %v", err, errTokenGone)
	}

	// Setting the key again once it works recovers the peer.
	key.fail.Store(false)
	if err := dev.SetStaticKey(key); err != nil {
		t.Fatalf("SetStaticKey after recovery: %v", err)
	}
	want, err := remote.id.ECDH(key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if peer.handshake.precomputedStaticStatic != want {
		t.Fatal("static-static secret does not match the peer's view")
	}
	if _, err := dev.CreateMessageInitiation(peer); err != nil {
		t.Fatalf("creating handshake initiation after recovery: %v", err)
	}
}

// A low-order peer point must not yield a usable secret even if the key
// implementation fails to reject it.
func TestStaticKeyZeroSecret(t *testing.T) {
	ss, err := staticKeySharedSecret(zeroKey{}, NoisePublicKey{})
	if err == nil || !isZero(ss[:]) {
		t.Fatalf("got secret %x, err %v; want an error", ss, err)
	}
	if _, err := staticKeySharedSecret(nil, NoisePublicKey{}); err == nil {
		t.Fatal("nil key produced a secret")
	}
}

type zeroKey struct{}

func (zeroKey) PublicKey() (pk [NoisePublicKeySize]byte) { return }
func (zeroKey) ECDH([NoisePublicKeySize]byte) (ss [NoisePublicKeySize]byte, err error) {
	return
}
