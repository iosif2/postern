package identity

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"strings"

	"github.com/go-piv/piv-go/v2/piv"
)

// slotLookup reads what a slot holds; it is (*piv.YubiKey).KeyInfo.
type slotLookup func(piv.Slot) (piv.KeyInfo, error)

// retiredSlots are the twenty retired key management slots, 82 to 95.
func retiredSlots() []piv.Slot {
	var slots []piv.Slot
	for id := uint32(0x82); id <= 0x95; id++ {
		if slot, ok := piv.RetiredKeyManagementSlot(id); ok {
			slots = append(slots, slot)
		}
	}
	return slots
}

// searchedSlots are all the slots a key may be in, in the order they are
// looked at.
func searchedSlots() []piv.Slot {
	return append(retiredSlots(),
		piv.SlotAuthentication, piv.SlotSignature, piv.SlotKeyManagement, piv.SlotCardAuthentication)
}

func isX25519(info piv.KeyInfo) bool {
	pub, ok := info.PublicKey.(*ecdh.PublicKey)
	return ok && pub.Curve() == ecdh.X25519()
}

// ResolveSlot returns the slot of the key to use on yk. A name such as "83"
// is taken as given. With an empty name the token is searched (see PickKey),
// so that the slot chosen when the key was made does not have to be
// remembered on every machine the token is later used from.
func ResolveSlot(yk *piv.YubiKey, name string) (piv.Slot, error) {
	if name != "" {
		return ParseSlot(name)
	}
	states, err := Slots(yk)
	if err != nil {
		return piv.Slot{}, err
	}
	slot, _, err := PickKey(states)
	return slot, err
}

// PickKey finds postern's key among the slots. That is the X25519 key in a
// slot marked as postern's. Only if no key is marked is an unmarked X25519
// key taken, since it may have been made with another tool for this use;
// marked then comes back false. Several candidates of the same standing are
// an error, never a guess.
func PickKey(states []SlotState) (slot piv.Slot, marked bool, err error) {
	var ours, others []piv.Slot
	for _, st := range states {
		switch {
		case st.X25519 && st.Marked:
			ours = append(ours, st.Slot)
		case st.X25519:
			others = append(others, st.Slot)
		}
	}
	list := func(slots []piv.Slot) string {
		names := make([]string, len(slots))
		for i, s := range slots {
			names[i] = s.String()
		}
		return strings.Join(names, ", ")
	}
	switch {
	case len(ours) == 1:
		return ours[0], true, nil
	case len(ours) > 1:
		return piv.Slot{}, false, fmt.Errorf("the token holds postern keys in slots %s; pick one with --slot", list(ours))
	case len(others) == 1:
		return others[0], false, nil
	case len(others) > 1:
		return piv.Slot{}, false, fmt.Errorf("the token holds X25519 keys in slots %s, none marked as postern's; pick one with --slot", list(others))
	}
	return piv.Slot{}, false, errors.New(`no X25519 key on the token; create one with "postern piv keygen"`)
}

// FreeSlot returns the first empty retired key management slot on yk.
func FreeSlot(yk *piv.YubiKey) (piv.Slot, error) {
	return freeSlot(yk.KeyInfo)
}

func freeSlot(lookup slotLookup) (piv.Slot, error) {
	for _, slot := range retiredSlots() {
		_, err := lookup(slot)
		if errors.Is(err, piv.ErrNotFound) {
			return slot, nil
		}
		if err != nil {
			return piv.Slot{}, fmt.Errorf("reading slot %s: %w", slot, err)
		}
	}
	return piv.Slot{}, errors.New("slots 82 to 95 are all occupied")
}
