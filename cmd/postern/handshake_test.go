package main

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iosif2/postern/internal/identity"
)

// countingIdentity counts key agreements and can be made to fail, like a
// token that has been pulled.
type countingIdentity struct {
	identity.Identity
	calls atomic.Int64
	fail  atomic.Bool
}

func (c *countingIdentity) ECDH(peer [identity.KeySize]byte) ([identity.KeySize]byte, error) {
	c.calls.Add(1)
	if c.fail.Load() {
		return [identity.KeySize]byte{}, errors.New("token gone")
	}
	return c.Identity.ECDH(peer)
}

func TestLoopbackHandshakes(t *testing.T) {
	sw, err := identity.NewSoftware()
	if err != nil {
		t.Fatal(err)
	}
	id := &countingIdentity{Identity: sw}

	const rounds = 3
	times, err := loopbackHandshakes(id, rounds)
	if err != nil {
		t.Fatal(err)
	}
	if len(times) != rounds {
		t.Fatalf("got %d handshakes, want %d", len(times), rounds)
	}
	// One key agreement when the peer is added, then one per handshake.
	// If the forced rekeys were not real handshakes this would be lower.
	if got, want := id.calls.Load(), int64(1+rounds); got != want {
		t.Errorf("%d key agreements, want %d", got, want)
	}
}

func TestLoopbackHandshakesFailingIdentity(t *testing.T) {
	sw, err := identity.NewSoftware()
	if err != nil {
		t.Fatal(err)
	}
	id := &countingIdentity{Identity: sw}
	id.fail.Store(true)
	defer func(d time.Duration) { handshakeTimeout = d }(handshakeTimeout)
	handshakeTimeout = 500 * time.Millisecond
	if _, err := loopbackHandshakes(id, 1); err == nil {
		t.Fatal("handshake succeeded with an identity that cannot do key agreement")
	}
}
