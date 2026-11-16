/* SPDX-License-Identifier: MIT
 *
 * This file is not part of upstream wireguard-go. It is postern's seam for
 * keeping the static private key outside the process. See UPSTREAM.md.
 */

package device

import "errors"

// StaticKey is the device's static Curve25519 key.
//
// The Noise IK handshake only uses the static private key for X25519 key
// agreement, so this is the only operation a key has to offer. An
// implementation may keep the private half somewhere it cannot be read from,
// such as a hardware token.
//
// ECDH is called once per peer when the peer or the key is set, and once per
// handshake after that. Calls are made with device locks held, so they must
// not call back into the device.
type StaticKey interface {
	// PublicKey returns the public half of the key.
	PublicKey() [NoisePublicKeySize]byte
	// ECDH returns the X25519 shared secret with peer.
	ECDH(peer [NoisePublicKeySize]byte) ([NoisePublicKeySize]byte, error)
}

var errNoStaticKey = errors.New("no static key set")

// softwareStaticKey is the StaticKey behind SetPrivateKey and the UAPI
// private_key setting: the upstream behaviour, with the key in memory.
type softwareStaticKey struct {
	sk NoisePrivateKey
}

func (k softwareStaticKey) PublicKey() [NoisePublicKeySize]byte {
	return k.sk.publicKey()
}

func (k softwareStaticKey) ECDH(peer [NoisePublicKeySize]byte) ([NoisePublicKeySize]byte, error) {
	return k.sk.sharedSecret(peer)
}

// staticSharedSecret performs key agreement between the device's static key
// and pk. The result is all zero whenever an error is returned, and an
// all-zero result is always an error. The caller must hold
// device.staticIdentity for reading or writing.
func (device *Device) staticSharedSecret(pk NoisePublicKey) (ss [NoisePublicKeySize]byte, err error) {
	return staticKeySharedSecret(device.staticIdentity.key, pk)
}

func staticKeySharedSecret(key StaticKey, pk NoisePublicKey) (ss [NoisePublicKeySize]byte, err error) {
	if key == nil {
		return ss, errNoStaticKey
	}
	ss, err = key.ECDH(pk)
	if err != nil {
		setZero(ss[:])
		return ss, err
	}
	if isZero(ss[:]) {
		return ss, errInvalidPublicKey
	}
	return ss, nil
}

// SetStaticKey sets the device's static key to key, which may keep its
// private half outside the process. It is the counterpart of SetPrivateKey
// for keys that cannot be exported.
//
// The static-static secret of every existing peer is recomputed, so setting
// the same key again is how to recover after its backing token went away.
// If key agreement fails for some peers, those peers cannot complete a
// handshake until it succeeds, and the first such error is returned.
func (device *Device) SetStaticKey(key StaticKey) error {
	if key == nil {
		return errNoStaticKey
	}
	return device.setStaticKey(key)
}

// StaticSecretReady reports whether the static-static secret with the peer
// pk has been computed, which a handshake with that peer requires. It is
// false if the peer is unknown or its key agreement failed.
func (device *Device) StaticSecretReady(pk NoisePublicKey) bool {
	peer := device.LookupPeer(pk)
	if peer == nil {
		return false
	}
	peer.handshake.mutex.RLock()
	defer peer.handshake.mutex.RUnlock()
	return !isZero(peer.handshake.precomputedStaticStatic[:])
}
