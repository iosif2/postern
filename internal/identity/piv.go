package identity

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/go-piv/piv-go/v2/piv"
)

// DefaultSlot is the PIV slot a new key goes to when none is given: the first
// of the retired key management slots (82 to 95), which have no assigned use.
// Other tools use these slots as well (age-plugin-yubikey fills them from 82
// up), so it may be taken; a key made elsewhere is found by ResolveSlot.
const DefaultSlot = "82"

// PIV is an Identity whose private key never leaves a PIV token.
//
// It holds the token exclusively until closed: with the PIN verified, a
// shared token would let any other program on the machine use the key.
type PIV struct {
	pub [KeySize]byte

	mu     sync.Mutex
	key    tokenKey
	probe  func() error
	close  func() error
	failed error // the first failure of the token itself; sticky
}

// tokenKey is the part of *piv.X25519PrivateKey that PIV uses.
type tokenKey interface {
	ECDH(peer *ecdh.PublicKey) ([]byte, error)
}

// ErrPINBlocked is returned when the token refuses further PIN attempts.
var ErrPINBlocked = errors.New("the token's PIN is blocked after too many wrong attempts; unblock it with the PUK (ykman piv access unblock-pin)")

// WrongPINError is returned when the token rejected the PIN.
type WrongPINError struct {
	// Retries is how many attempts remain before the PIN is blocked.
	Retries int
}

func (e *WrongPINError) Error() string {
	if e.Retries == 1 {
		return "wrong PIN; 1 attempt left before the PIN is blocked"
	}
	return fmt.Sprintf("wrong PIN; %d attempts left before the PIN is blocked", e.Retries)
}

// RetriesUnknown is what PINRetries returns when the token will not say how
// many attempts are left.
const RetriesUnknown = -1

// PINRetries returns how many PIN attempts the token still allows. It is
// ErrPINBlocked if there are none.
//
// A token whose PIN has already been verified does not answer the question,
// and that happens: the verification outlives the program that did it, until
// the token is unplugged or another of its applications is used. The count
// is then RetriesUnknown, and the PIN can be asked for as usual.
func PINRetries(yk *piv.YubiKey) (int, error) {
	retries, err := yk.Retries()
	return pinRetries(retries, err)
}

func pinRetries(retries int, err error) (int, error) {
	switch {
	case err == nil && retries == 0:
		return 0, ErrPINBlocked
	case err == nil:
		return retries, nil
	// piv-go reports "already verified" only as this text.
	case strings.Contains(err.Error(), "expected error code from empty pin"):
		return RetriesUnknown, nil
	}
	return 0, fmt.Errorf("reading PIN attempts left: %w", err)
}

// pinError turns the token's answer to a PIN into one of the errors above.
func pinError(err error) error {
	var auth piv.AuthErr
	if !errors.As(err, &auth) {
		return fmt.Errorf("verifying PIN: %w", err)
	}
	if auth.Retries == 0 {
		return ErrPINBlocked
	}
	return &WrongPINError{Retries: auth.Retries}
}

// openError explains a failure to connect to the token.
func openError(card string, err error) error {
	// piv-go does not export the PC/SC return code, only its description.
	if strings.Contains(err.Error(), "other connections outstanding") {
		return fmt.Errorf("%s is in use by another program (another postern, an agent or a management tool); close it and try again", card)
	}
	return fmt.Errorf("opening %s: %w", card, err)
}

// ParseSlot converts a slot name such as "9d" or "82" into a PIV slot.
func ParseSlot(name string) (piv.Slot, error) {
	switch strings.ToLower(strings.TrimPrefix(name, "0x")) {
	case "9a":
		return piv.SlotAuthentication, nil
	case "9c":
		return piv.SlotSignature, nil
	case "9d":
		return piv.SlotKeyManagement, nil
	case "9e":
		return piv.SlotCardAuthentication, nil
	}
	id, err := strconv.ParseUint(strings.TrimPrefix(name, "0x"), 16, 32)
	if err == nil {
		if slot, ok := piv.RetiredKeyManagementSlot(uint32(id)); ok {
			return slot, nil
		}
	}
	return piv.Slot{}, fmt.Errorf("unknown PIV slot %q (want 9a, 9c, 9d, 9e or 82-95)", name)
}

// FindCard returns the reader name of the token to use. An empty want picks
// the only connected YubiKey; otherwise want is matched as a substring.
func FindCard(want string) (string, error) {
	cards, err := piv.Cards()
	if err != nil {
		return "", fmt.Errorf("listing smart cards: %w", err)
	}
	var matches []string
	for _, card := range cards {
		name := strings.ToLower(card)
		if want == "" && strings.Contains(name, "yubikey") {
			matches = append(matches, card)
		}
		if want != "" && strings.Contains(name, strings.ToLower(want)) {
			matches = append(matches, card)
		}
	}
	switch len(matches) {
	case 0:
		return "", errors.New("no matching PIV token found")
	case 1:
		return matches[0], nil
	}
	return "", fmt.Errorf("several tokens match, pick one with --card: %s", strings.Join(matches, ", "))
}

// SlotPublicKey reads the X25519 public key stored in slot, without a PIN.
func SlotPublicKey(yk *piv.YubiKey, slot piv.Slot) (*ecdh.PublicKey, piv.KeyInfo, error) {
	info, err := yk.KeyInfo(slot)
	if errors.Is(err, piv.ErrNotFound) {
		return nil, info, fmt.Errorf("slot %s is empty; create a key with \"postern piv keygen\"", slot)
	}
	if err != nil {
		return nil, info, fmt.Errorf("reading slot %s: %w", slot, err)
	}
	pub, ok := info.PublicKey.(*ecdh.PublicKey)
	if !ok || pub.Curve() != ecdh.X25519() {
		return nil, info, fmt.Errorf("slot %s does not hold an X25519 key", slot)
	}
	return pub, info, nil
}

// Open connects to the token in the given reader, taking it for this
// process alone. Nothing that needs the PIN has happened yet.
func Open(card string) (*piv.YubiKey, error) {
	yk, err := piv.Open(card)
	if err != nil {
		return nil, openError(card, err)
	}
	return yk, nil
}

// OpenPIV opens the X25519 key on the given card. slotName names its slot; if
// empty, the token's only X25519 key is used (see ResolveSlot).
func OpenPIV(card, slotName string, pinPrompt func(retries int) (string, error)) (*PIV, error) {
	yk, err := Open(card)
	if err != nil {
		return nil, err
	}
	slot, err := ResolveSlot(yk, slotName)
	if err == nil {
		var id *PIV
		if id, err = Unlock(yk, slot, pinPrompt); err == nil {
			return id, nil
		}
	}
	yk.Close()
	return nil, err
}

// Unlock makes the X25519 key in slot usable. On success the returned PIV
// owns yk and closes it; on failure yk is left open for the caller.
//
// If the key's PIN policy asks for a PIN, pinPrompt is called once, with the
// number of attempts the token still allows, and the PIN is verified before
// Unlock returns. A wrong PIN is an error (*WrongPINError), never retried:
// every attempt is one the user made.
func Unlock(yk *piv.YubiKey, slot piv.Slot, pinPrompt func(retries int) (string, error)) (*PIV, error) {
	pub, info, err := SlotPublicKey(yk, slot)
	if err != nil {
		return nil, err
	}

	auth := piv.KeyAuth{PINPolicy: info.PINPolicy}
	if info.PINPolicy == piv.PINPolicyOnce || info.PINPolicy == piv.PINPolicyAlways {
		retries, err := PINRetries(yk)
		if err != nil {
			return nil, err
		}
		if pinPrompt == nil {
			return nil, errors.New("the key needs a PIN and there is no way to ask for it")
		}
		pin, err := pinPrompt(retries)
		if err != nil {
			return nil, err
		}
		// An empty or over-long PIN is refused before it reaches the
		// token, so it does not cost an attempt.
		if err := yk.VerifyPIN(pin); err != nil {
			return nil, pinError(err)
		}
		// A key that wants the PIN for every operation gets it from
		// memory; otherwise it is not kept.
		if info.PINPolicy == piv.PINPolicyAlways {
			auth.PIN = pin
		}
	}

	private, err := yk.PrivateKey(slot, pub, auth)
	if err != nil {
		return nil, fmt.Errorf("opening key in slot %s: %w", slot, err)
	}
	key, ok := private.(*piv.X25519PrivateKey)
	if !ok {
		return nil, fmt.Errorf("slot %s returned an unexpected key type %T", slot, private)
	}
	id := &PIV{
		key: key,
		// Reading the serial number is one harmless command on any token
		// able to hold an X25519 key, and leaves the PIN state alone.
		probe: func() error { _, err := yk.Serial(); return err },
		close: yk.Close,
	}
	copy(id.pub[:], pub.Bytes())
	return id, nil
}

// PublicKey implements Identity.
func (p *PIV) PublicKey() [KeySize]byte { return p.pub }

// ECDH implements Identity. The scalar multiplication runs on the token.
//
// Once the token has failed, every later call fails with the same error
// without touching it: a token that was pulled and put back has forgotten
// the PIN, and must be opened again.
func (p *PIV) ECDH(peer [KeySize]byte) ([KeySize]byte, error) {
	var out [KeySize]byte
	pub, err := ecdh.X25519().NewPublicKey(peer[:])
	if err != nil {
		return out, fmt.Errorf("parsing peer public key: %w", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failed != nil {
		return out, p.failed
	}
	secret, err := p.key.ECDH(pub)
	if err != nil {
		err = fmt.Errorf("key agreement on token: %w", err)
		// The token may have refused this one input, which a stranger can
		// provoke with a forged handshake message; that must not cost the
		// tunnel. Only a token that has stopped answering is given up on.
		if p.probe() != nil {
			p.failed = err
		}
		return out, err
	}
	if len(secret) != KeySize {
		return out, fmt.Errorf("token returned a %d-byte secret, want %d", len(secret), KeySize)
	}
	var acc byte
	for _, b := range secret {
		acc |= b
	}
	if acc == 0 {
		return out, ErrZeroSecret
	}
	copy(out[:], secret)
	return out, nil
}

// Check reports whether the token is still there and usable. It returns the
// error that made it unusable, from here or from an earlier ECDH.
func (p *PIV) Check() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failed == nil {
		if err := p.probe(); err != nil {
			p.failed = fmt.Errorf("the token no longer answers: %w", err)
		}
	}
	return p.failed
}

// Close implements Identity.
func (p *PIV) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.close()
}
