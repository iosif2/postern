package identity

import (
	"encoding/hex"
	"errors"
	"testing"
)

func mustKey(t *testing.T, s string) [KeySize]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != KeySize {
		t.Fatalf("bad test key %q", s)
	}
	var out [KeySize]byte
	copy(out[:], b)
	return out
}

// Vectors from RFC 7748, section 6.1.
func TestSoftwareRFC7748(t *testing.T) {
	alice, err := SoftwareFromBytes(mustKey(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
	if err != nil {
		t.Fatal(err)
	}
	bob, err := SoftwareFromBytes(mustKey(t, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := alice.PublicKey(), mustKey(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"); got != want {
		t.Errorf("alice public key = %x, want %x", got, want)
	}
	want := mustKey(t, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
	ab, err := alice.ECDH(bob.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	ba, err := bob.ECDH(alice.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if ab != want || ba != want {
		t.Errorf("shared secrets = %x / %x, want %x", ab, ba, want)
	}
}

func TestSoftwareRejectsLowOrderPoint(t *testing.T) {
	id, err := NewSoftware()
	if err != nil {
		t.Fatal(err)
	}
	var zero [KeySize]byte
	if _, err := id.ECDH(zero); !errors.Is(err, ErrZeroSecret) {
		t.Errorf("ECDH with the zero point: err = %v, want ErrZeroSecret", err)
	}
}

func TestParseSlot(t *testing.T) {
	for _, name := range []string{"9a", "9C", "9d", "9e", "82", "0x95"} {
		if _, err := ParseSlot(name); err != nil {
			t.Errorf("ParseSlot(%q): %v", name, err)
		}
	}
	for _, name := range []string{"", "81", "96", "f9", "zz"} {
		if _, err := ParseSlot(name); err == nil {
			t.Errorf("ParseSlot(%q) succeeded, want an error", name)
		}
	}
}
