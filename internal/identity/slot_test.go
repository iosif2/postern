package identity

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"
)

// token is a fake set of slots: slot name to what it holds.
type token map[string]piv.KeyInfo

func (tk token) lookup(slot piv.Slot) (piv.KeyInfo, error) {
	info, ok := tk[slot.String()]
	if !ok {
		return piv.KeyInfo{}, piv.ErrNotFound
	}
	return info, nil
}

func x25519Info(t *testing.T) piv.KeyInfo {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return piv.KeyInfo{Algorithm: piv.AlgorithmX25519, PublicKey: key.PublicKey()}
}

// p256Info is the kind of key other tools keep in the same slots.
func p256Info(t *testing.T) piv.KeyInfo {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return piv.KeyInfo{Algorithm: piv.AlgorithmEC256, PublicKey: &key.PublicKey}
}

func states(t *testing.T, set map[string]SlotState) []SlotState {
	t.Helper()
	var out []SlotState
	for _, slot := range searchedSlots() {
		st := set[slot.String()]
		st.Slot = slot
		out = append(out, st)
	}
	return out
}

var (
	posternKey  = SlotState{HasKey: true, X25519: true, Marked: true}
	unmarkedKey = SlotState{HasKey: true, X25519: true}
	foreignKey  = SlotState{HasKey: true}
)

func TestPickKey(t *testing.T) {
	cases := []struct {
		name   string
		set    map[string]SlotState
		slot   string // "" for an error
		marked bool
		errHas string
	}{
		// Slot 82 was another tool's when the key was made, so it went to
		// 84; nothing should have to remember that.
		{"found wherever it is", map[string]SlotState{"82": foreignKey, "84": posternKey, "9a": foreignKey}, "84", true, ""},
		// Another program's X25519 key must not be taken for postern's.
		{"marked wins over unmarked", map[string]SlotState{"82": unmarkedKey, "85": posternKey}, "85", true, ""},
		{"an unmarked key alone is used", map[string]SlotState{"83": unmarkedKey}, "83", false, ""},
		{"several marked", map[string]SlotState{"82": posternKey, "85": posternKey}, "", false, "82, 85"},
		{"several unmarked", map[string]SlotState{"82": unmarkedKey, "85": unmarkedKey}, "", false, "none marked"},
		{"none", map[string]SlotState{"82": foreignKey}, "", false, "keygen"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			slot, marked, err := PickKey(states(t, c.set))
			if c.slot == "" {
				if err == nil || !strings.Contains(err.Error(), c.errHas) {
					t.Fatalf("got slot %s, err %v; want an error mentioning %q", slot, err, c.errHas)
				}
				return
			}
			if err != nil || slot.String() != c.slot || marked != c.marked {
				t.Fatalf("got slot %s, marked %v, err %v; want %s, %v", slot, marked, err, c.slot, c.marked)
			}
		})
	}
}

func TestFreeSlot(t *testing.T) {
	tk := token{"82": p256Info(t), "83": x25519Info(t)}
	slot, err := freeSlot(tk.lookup)
	if err != nil || slot.String() != "84" {
		t.Fatalf("got %v, %v; want 84", slot, err)
	}

	full := token{}
	for _, s := range retiredSlots() {
		full[s.String()] = p256Info(t)
	}
	if len(full) != 20 {
		t.Fatalf("%d retired slots, want 20", len(full))
	}
	if _, err := freeSlot(full.lookup); err == nil {
		t.Fatal("found a free slot on a full token")
	}
}
