package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

const sampleConfig = `[Interface]
Address = 10.0.0.2/32
DNS = 192.168.88.1

[Peer]
PublicKey = 61UMFtbnkh9pGApTaocFfbtTGQPIEnpqSDN1pkcnpQw=
Endpoint = home.example.org:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`

func TestConfigCertificateRoundTrip(t *testing.T) {
	for name, text := range map[string]string{
		"ascii":     sampleConfig,
		"non-ascii": "# 집 네트워크\n" + sampleConfig,
	} {
		t.Run(name, func(t *testing.T) {
			cert, err := configCertificate([]byte(text))
			if err != nil {
				t.Fatal(err)
			}
			// What goes to the token is the encoded form; decode that.
			parsed, err := x509.ParseCertificate(cert.Raw)
			if err != nil {
				t.Fatal(err)
			}
			got, err := certificateConfig(parsed)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != text {
				t.Fatalf("got back %q, want %q", got, text)
			}
			if len(cert.Raw) > maxConfigCert {
				t.Errorf("certificate is %d bytes", len(cert.Raw))
			}
		})
	}
}

func TestConfigCertificateTooLarge(t *testing.T) {
	big := sampleConfig + strings.Repeat("# padding padding padding\n", 200)
	if _, err := configCertificate([]byte(big)); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("got %v, want it refused as too large", err)
	}
}

// A certificate somebody else put in a slot must not be taken for a
// configuration.
func TestCertificateConfigIgnoresOtherCertificates(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "SSH key"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := certificateConfig(cert); !errors.Is(err, ErrNoConfig) {
		t.Fatalf("got %v, want ErrNoConfig", err)
	}
}

func TestMarkCertificate(t *testing.T) {
	mark, err := markCertificate(keyCommonName)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(mark.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if !isMark(parsed) {
		t.Error("the key mark is not recognised as postern's")
	}
	// It marks the key; it is not a configuration.
	if _, err := certificateConfig(parsed); !errors.Is(err, ErrNoConfig) {
		t.Errorf("the key mark was read as a configuration: %v", err)
	}
	conf, err := configCertificate([]byte(sampleConfig))
	if err != nil {
		t.Fatal(err)
	}
	if !isMark(conf) {
		t.Error("a configuration is not recognised as postern's mark")
	}
}
