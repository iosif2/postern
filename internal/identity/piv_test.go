package identity

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"
)

// fakeToken stands in for the key on a token: software key agreement that
// can be made to fail, as when the token is pulled.
type fakeToken struct {
	key   *ecdh.PrivateKey
	gone  error
	calls int
}

func (f *fakeToken) ECDH(peer *ecdh.PublicKey) ([]byte, error) {
	f.calls++
	if f.gone != nil {
		return nil, f.gone
	}
	return f.key.ECDH(peer)
}

func newFakePIV(t *testing.T) (*PIV, *fakeToken, [KeySize]byte) {
	t.Helper()
	sw, err := NewSoftware()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := NewSoftware()
	if err != nil {
		t.Fatal(err)
	}
	tok := &fakeToken{key: sw.key}
	p := &PIV{
		key:   tok,
		probe: func() error { return tok.gone },
		close: func() error { return nil },
		pub:   sw.PublicKey(),
	}
	return p, tok, peer.PublicKey()
}

func TestPIVFailureIsSticky(t *testing.T) {
	p, tok, peer := newFakePIV(t)
	if _, err := p.ECDH(peer); err != nil {
		t.Fatal(err)
	}
	if err := p.Check(); err != nil {
		t.Fatalf("Check on a working token: %v", err)
	}

	removed := errors.New("card removed")
	tok.gone = removed
	if _, err := p.ECDH(peer); !errors.Is(err, removed) {
		t.Fatalf("ECDH after removal: got %v", err)
	}
	// Putting the token back does not bring the key back: it has
	// forgotten the PIN. The token must not even be asked.
	tok.gone = nil
	calls := tok.calls
	if _, err := p.ECDH(peer); !errors.Is(err, removed) {
		t.Fatalf("ECDH after the token came back: got %v, want the first failure", err)
	}
	if tok.calls != calls {
		t.Error("the token was used again after it had failed")
	}
	if err := p.Check(); !errors.Is(err, removed) {
		t.Fatalf("Check after a failed ECDH: got %v", err)
	}
}

func TestPIVCheckNoticesRemoval(t *testing.T) {
	p, tok, peer := newFakePIV(t)
	removed := errors.New("card removed")
	tok.gone = removed
	if err := p.Check(); !errors.Is(err, removed) {
		t.Fatalf("Check: got %v", err)
	}
	tok.gone = nil
	if _, err := p.ECDH(peer); !errors.Is(err, removed) {
		t.Fatalf("ECDH after a failed Check: got %v", err)
	}
}

// An input the token refuses must not mark the token itself as failed.
func TestPIVRefusedInputIsNotATokenFailure(t *testing.T) {
	p, _, peer := newFakePIV(t)
	if _, err := p.ECDH([KeySize]byte{}); err == nil {
		t.Fatal("key agreement with a low-order point succeeded")
	}
	if err := p.Check(); err != nil {
		t.Fatalf("Check after a refused input: %v", err)
	}
	if _, err := p.ECDH(peer); err != nil {
		t.Fatalf("ECDH after a refused input: %v", err)
	}
}

func TestPINError(t *testing.T) {
	wrap := func(err error) error { return fmt.Errorf("verify pin: %w", err) }

	var wrong *WrongPINError
	err := pinError(wrap(piv.AuthErr{Retries: 2}))
	if !errors.As(err, &wrong) || wrong.Retries != 2 {
		t.Fatalf("got %v, want a wrong PIN with 2 attempts left", err)
	}
	if !strings.Contains(err.Error(), "2 attempts left") {
		t.Errorf("message does not say what is left: %q", err)
	}
	if err := pinError(wrap(piv.AuthErr{Retries: 0})); !errors.Is(err, ErrPINBlocked) {
		t.Fatalf("got %v, want ErrPINBlocked", err)
	}
	other := errors.New("card removed")
	if err := pinError(other); !errors.Is(err, other) || errors.As(err, &wrong) {
		t.Fatalf("an unrelated error was turned into %v", err)
	}
}

func TestOpenErrorNamesABusyToken(t *testing.T) {
	busy := errors.New("connecting to smart card: the smart card cannot be accessed because of other connections outstanding")
	if err := openError("YubiKey", busy); !strings.Contains(err.Error(), "in use by another program") {
		t.Errorf("busy token: %q", err)
	}
	other := errors.New("no such reader")
	if err := openError("YubiKey", other); !errors.Is(err, other) {
		t.Errorf("other failure lost its cause: %q", err)
	}
}

func TestPINRetries(t *testing.T) {
	if n, err := pinRetries(3, nil); n != 3 || err != nil {
		t.Errorf("3 left: got %d, %v", n, err)
	}
	if _, err := pinRetries(0, nil); !errors.Is(err, ErrPINBlocked) {
		t.Errorf("none left: got %v, want ErrPINBlocked", err)
	}
	// What piv-go returns when the PIN was verified by an earlier run.
	verified := errors.New("expected error code from empty pin")
	if n, err := pinRetries(0, verified); n != RetriesUnknown || err != nil {
		t.Errorf("already verified: got %d, %v; want unknown and no error", n, err)
	}
	other := errors.New("card removed")
	if _, err := pinRetries(0, other); !errors.Is(err, other) {
		t.Errorf("a real failure: got %v", err)
	}
}
