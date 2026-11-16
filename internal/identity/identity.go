// Package identity abstracts the static Curve25519 key of a WireGuard peer.
//
// The WireGuard handshake only ever uses the static private key for X25519
// key agreement, so an Identity exposes that single operation. This lets the
// private key live somewhere it cannot be read from, such as a PIV token.
package identity

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
)

// KeySize is the size in bytes of Curve25519 keys and shared secrets.
const KeySize = 32

// ErrZeroSecret is returned when a key agreement yields the all-zero secret,
// which happens for low-order peer points and must be rejected.
var ErrZeroSecret = errors.New("identity: key agreement produced an all-zero shared secret")

// Identity is a static Curve25519 key that can perform key agreement.
type Identity interface {
	// PublicKey returns the public half, in WireGuard's wire format.
	PublicKey() [KeySize]byte
	// ECDH returns the X25519 shared secret with peer.
	ECDH(peer [KeySize]byte) ([KeySize]byte, error)
	// Close releases any resources held by the identity.
	Close() error
}

// Software is an Identity whose private key is held in process memory.
type Software struct {
	key *ecdh.PrivateKey
}

// NewSoftware generates a fresh in-memory identity.
func NewSoftware() (*Software, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating X25519 key: %w", err)
	}
	return &Software{key: key}, nil
}

// SoftwareFromBytes builds an in-memory identity from a raw private key.
func SoftwareFromBytes(private [KeySize]byte) (*Software, error) {
	key, err := ecdh.X25519().NewPrivateKey(private[:])
	if err != nil {
		return nil, fmt.Errorf("loading X25519 key: %w", err)
	}
	return &Software{key: key}, nil
}

// PublicKey implements Identity.
func (s *Software) PublicKey() [KeySize]byte {
	var out [KeySize]byte
	copy(out[:], s.key.PublicKey().Bytes())
	return out
}

// ECDH implements Identity.
func (s *Software) ECDH(peer [KeySize]byte) ([KeySize]byte, error) {
	var out [KeySize]byte
	pub, err := ecdh.X25519().NewPublicKey(peer[:])
	if err != nil {
		return out, fmt.Errorf("parsing peer public key: %w", err)
	}
	secret, err := s.key.ECDH(pub)
	if err != nil {
		// crypto/ecdh already rejects the all-zero output.
		return out, fmt.Errorf("%w: %v", ErrZeroSecret, err)
	}
	copy(out[:], secret)
	return out, nil
}

// Close implements Identity.
func (s *Software) Close() error { return nil }
