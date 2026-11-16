package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
)

// A PIV key slot holds a key and nothing else, but every slot comes with a
// certificate object, and that is where the tunnel configuration is kept: as
// the comment of a certificate. The certificate certifies nothing. It is
// signed with a key that is thrown away, and exists because a certificate is
// what the token, and every tool that inspects it, expects to find there.
//
// Certificate objects can be read without the PIN, so the configuration is
// as public as the token is: nothing secret may be put in it.

// The common names that mark a certificate, and with it the slot, as
// postern's: one carries a configuration, the other only says that the key
// in the slot was made for postern. A key cannot be labelled itself, and
// without the mark an X25519 key of some other program's would look the
// same.
const (
	configCommonName = "postern configuration"
	keyCommonName    = "postern key"
)

// oidComment is the Netscape certificate comment extension: free text, which
// "openssl x509 -text" and similar tools print as it is.
var oidComment = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 13}

// maxConfigCert is the largest certificate stored. A YubiKey takes objects
// of up to 3052 bytes, including a few bytes of wrapping.
const maxConfigCert = 3000

// ErrNoConfig is returned when a slot holds no configuration.
var ErrNoConfig = errors.New("no configuration stored there")

// configCertificate wraps a configuration in a certificate.
func configCertificate(data []byte) (*x509.Certificate, error) {
	// The extension is an IA5String by definition; fall back to UTF-8 for
	// text that is not ASCII, such as comments in other scripts.
	comment, err := asn1.MarshalWithParams(string(data), "ia5")
	if err != nil {
		if comment, err = asn1.MarshalWithParams(string(data), "utf8"); err != nil {
			return nil, fmt.Errorf("the configuration is not valid text: %w", err)
		}
	}
	cert, err := markCertificate(configCommonName, pkix.Extension{Id: oidComment, Value: comment})
	if err != nil {
		return nil, fmt.Errorf("wrapping the configuration: %w", err)
	}
	if len(cert.Raw) > maxConfigCert {
		return nil, fmt.Errorf("the configuration is %d bytes too large to fit on the token", len(cert.Raw)-maxConfigCert)
	}
	return cert, nil
}

// markCertificate makes a certificate that certifies nothing: it is signed
// with a key that is thrown away, and only its name and extensions matter.
func markCertificate(commonName string, extensions ...pkix.Extension) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber:    serial,
		Subject:         pkix.Name{CommonName: commonName},
		NotBefore:       now,
		NotAfter:        now.AddDate(100, 0, 0),
		ExtraExtensions: extensions,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// isMark reports whether a certificate is one of postern's.
func isMark(cert *x509.Certificate) bool {
	return cert.Subject.CommonName == configCommonName || cert.Subject.CommonName == keyCommonName
}

// ErrOtherCertificate is returned instead of replacing a certificate that
// is not postern's.
var ErrOtherCertificate = errors.New("the slot holds another program's certificate")

// MarkKey records that the key in slot is postern's, by storing a marking
// certificate with it. A slot that already carries one of postern's
// certificates, such as a configuration, is marked already and left alone;
// another program's certificate is never replaced.
func MarkKey(yk *piv.YubiKey, managementKey []byte, slot piv.Slot) error {
	cert, err := yk.Certificate(slot)
	switch {
	case err == nil && isMark(cert):
		return nil
	case err == nil:
		return ErrOtherCertificate
	case !errors.Is(err, piv.ErrNotFound):
		// Something is there, even if it cannot be read as a certificate.
		return ErrOtherCertificate
	}
	mark, err := markCertificate(keyCommonName)
	if err != nil {
		return err
	}
	if err := yk.SetCertificate(managementKey, slot, mark); err != nil {
		return fmt.Errorf("marking slot %s: %w", slot, err)
	}
	return nil
}

// certificateConfig returns the configuration a certificate carries, or
// ErrNoConfig if it is some other certificate.
func certificateConfig(cert *x509.Certificate) ([]byte, error) {
	if cert.Subject.CommonName != configCommonName {
		return nil, ErrNoConfig
	}
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidComment) {
			continue
		}
		var text string
		if _, err := asn1.Unmarshal(ext.Value, &text); err != nil {
			return nil, fmt.Errorf("reading the stored configuration: %w", err)
		}
		return []byte(text), nil
	}
	return nil, ErrNoConfig
}

// ReadConfig returns the configuration stored with slot. It needs no PIN.
func ReadConfig(yk *piv.YubiKey, slot piv.Slot) ([]byte, error) {
	cert, err := yk.Certificate(slot)
	if errors.Is(err, piv.ErrNotFound) {
		return nil, ErrNoConfig
	}
	if err != nil {
		return nil, fmt.Errorf("reading the certificate of slot %s: %w", slot, err)
	}
	return certificateConfig(cert)
}

// WriteConfig stores data as the configuration of slot, replacing whatever
// certificate was there, and reads it back to make sure it arrived.
func WriteConfig(yk *piv.YubiKey, managementKey []byte, slot piv.Slot, data []byte) error {
	cert, err := configCertificate(data)
	if err != nil {
		return err
	}
	if err := yk.SetCertificate(managementKey, slot, cert); err != nil {
		return fmt.Errorf("writing to slot %s: %w", slot, err)
	}
	back, err := ReadConfig(yk, slot)
	if err != nil {
		return fmt.Errorf("reading back what was written to slot %s: %w", slot, err)
	}
	if string(back) != string(data) {
		return fmt.Errorf("slot %s does not hold what was written to it", slot)
	}
	return nil
}

// SlotState is what one slot of a token holds.
type SlotState struct {
	Slot piv.Slot
	// HasKey says whether there is a key; X25519 whether it is one postern
	// can use, and then PublicKey is its public half.
	HasKey    bool
	X25519    bool
	Algorithm piv.Algorithm
	PublicKey [KeySize]byte
	// Marked says that the slot carries one of postern's certificates, and
	// so that a key in it is postern's.
	Marked bool
	// Config is the stored configuration, nil if there is none.
	Config []byte
	// OtherCert says that the slot holds a certificate that is not a
	// configuration, and so belongs to something else.
	OtherCert bool
}

// Slots reports the state of every slot postern looks at: 82 to 95, then
// the four slots with an assigned use.
func Slots(yk *piv.YubiKey) ([]SlotState, error) {
	var out []SlotState
	for _, slot := range searchedSlots() {
		st := SlotState{Slot: slot}
		info, err := yk.KeyInfo(slot)
		switch {
		case errors.Is(err, piv.ErrNotFound):
		case err != nil:
			return nil, fmt.Errorf("reading slot %s: %w", slot, err)
		default:
			st.HasKey = true
			st.Algorithm = info.Algorithm
			if isX25519(info) {
				st.X25519 = true
				copy(st.PublicKey[:], publicKeyBytes(info))
			}
		}
		cert, err := yk.Certificate(slot)
		switch {
		case errors.Is(err, piv.ErrNotFound):
		case err != nil:
			// Whatever cannot be read as a certificate is not ours.
			st.OtherCert = true
		case isMark(cert):
			st.Marked = true
			if cfg, err := certificateConfig(cert); err == nil {
				st.Config = cfg
			}
		default:
			st.OtherCert = true
		}
		out = append(out, st)
	}
	return out, nil
}

func publicKeyBytes(info piv.KeyInfo) []byte {
	if pub, ok := info.PublicKey.(interface{ Bytes() []byte }); ok {
		return pub.Bytes()
	}
	return nil
}

// IsRetired reports whether slot is one of the slots 82 to 95, the ones
// postern writes to.
func IsRetired(slot piv.Slot) bool {
	return slot.Key >= 0x82 && slot.Key <= 0x95
}
