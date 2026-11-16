package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/term"

	"github.com/iosif2/postern/internal/identity"
)

// interactive reports whether there is somebody at a terminal to ask.
func interactive() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd()))
}

// slotChoice is one slot offered in a selection.
type slotChoice struct {
	slot  piv.Slot
	label string
}

// keyDescription says what key a slot holds, for a person choosing a slot.
func keyDescription(st identity.SlotState) string {
	switch {
	case st.X25519 && st.Marked:
		return "postern key"
	case st.X25519:
		return "X25519 key, not marked as postern's"
	case st.HasKey:
		return "another program's key"
	}
	return ""
}

// configDescription says what configuration a slot holds: where it leads.
func configDescription(st identity.SlotState) string {
	switch {
	case st.Config != nil:
		if cfg, err := parseWGConfig(st.Config); err == nil && cfg.flags["endpoint"] != "" {
			return "configuration for " + cfg.flags["endpoint"]
		}
		return "configuration"
	case st.OtherCert:
		return "another program's certificate"
	}
	return ""
}

func describe(st identity.SlotState) string {
	var parts []string
	for _, d := range []string{keyDescription(st), configDescription(st)} {
		if d != "" {
			parts = append(parts, d)
		}
	}
	if len(parts) == 0 {
		return "empty"
	}
	return strings.Join(parts, ", ")
}

// slotLines describes every slot that holds something, one line each. A
// slot with a usable key also shows the public key, which is what the
// server needs.
func slotLines(states []identity.SlotState) []string {
	var lines []string
	for _, st := range states {
		d := describe(st)
		if d == "empty" {
			continue
		}
		line := fmt.Sprintf("%s  %s", st.Slot, d)
		if st.X25519 {
			line += "  " + base64.StdEncoding.EncodeToString(st.PublicKey[:])
		}
		lines = append(lines, line)
	}
	return lines
}

// keygenChoices returns the slots a new key may go to, which are the empty
// ones among 82 to 95, the one to offer first, and a line about the rest.
func keygenChoices(states []identity.SlotState) (choices []slotChoice, def piv.Slot, inUse string, err error) {
	var taken []string
	for _, st := range states {
		if !identity.IsRetired(st.Slot) {
			continue
		}
		// A slot with another program's certificate is in use even
		// without a key: the new key could not be marked there.
		if st.HasKey || st.OtherCert {
			taken = append(taken, fmt.Sprintf("%s (%s)", st.Slot, describe(st)))
			continue
		}
		label := st.Slot.String() + "  empty"
		if d := configDescription(st); d != "" {
			label = st.Slot.String() + "  no key; " + d
		}
		choices = append(choices, slotChoice{st.Slot, label})
	}
	if len(choices) == 0 {
		return nil, piv.Slot{}, "", errors.New("slots 82 to 95 are all in use")
	}
	// The lowest empty slot is the default slot whenever that one is free.
	def = choices[0].slot
	if len(taken) > 0 {
		inUse = "In use: " + strings.Join(taken, ", ")
	}
	return choices, def, inUse, nil
}

// confChoices returns the slots a configuration may be stored with: those
// among 82 to 95 whose certificate is not somebody else's. The one offered
// first is the slot of the token's X25519 key, so that key and configuration
// travel together.
func confChoices(states []identity.SlotState) (choices []slotChoice, def piv.Slot, inUse string, err error) {
	var taken []string
	offered := map[piv.Slot]bool{}
	for _, st := range states {
		if !identity.IsRetired(st.Slot) {
			continue
		}
		if st.OtherCert {
			taken = append(taken, fmt.Sprintf("%s (%s)", st.Slot, configDescription(st)))
			continue
		}
		offered[st.Slot] = true
		choices = append(choices, slotChoice{st.Slot, st.Slot.String() + "  " + describe(st)})
	}
	if len(choices) == 0 {
		return nil, piv.Slot{}, "", errors.New("slots 82 to 95 all hold another program's certificate")
	}
	def = choices[0].slot
	if key, _, err := identity.PickKey(states); err == nil && offered[key] {
		def = key
	}
	if len(taken) > 0 {
		inUse = "In use: " + strings.Join(taken, ", ")
	}
	return choices, def, inUse, nil
}

// chooseSlot asks which slot to use. Enter accepts def.
func chooseSlot(title, description string, choices []slotChoice, def piv.Slot) (piv.Slot, error) {
	options := make([]huh.Option[piv.Slot], len(choices))
	for i, c := range choices {
		label := c.label
		if c.slot == def {
			label += "  (default)"
		}
		options[i] = huh.NewOption(label, c.slot)
	}
	chosen := def
	sel := huh.NewSelect[piv.Slot]().Title(title).Options(options...).Value(&chosen)
	if description != "" {
		sel = sel.Description(description)
	}
	if err := sel.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return piv.Slot{}, errors.New("cancelled")
		}
		return piv.Slot{}, err
	}
	return chosen, nil
}

// pickConfig finds the stored configuration to connect with. A slot name is
// taken as given. Otherwise it is the one stored with the key in use, or
// else the only one on the token.
func pickConfig(states []identity.SlotState, keySlot *piv.Slot, name string) (identity.SlotState, error) {
	if name != "" {
		slot, err := identity.ParseSlot(name)
		if err != nil {
			return identity.SlotState{}, err
		}
		for _, st := range states {
			if st.Slot == slot && st.Config != nil {
				return st, nil
			}
		}
		return identity.SlotState{}, fmt.Errorf(`slot %s holds no configuration; store one with "postern conf edit --conf-slot %s"`, slot, slot)
	}
	var found []identity.SlotState
	for _, st := range states {
		if st.Config == nil {
			continue
		}
		if keySlot != nil && st.Slot == *keySlot {
			return st, nil
		}
		found = append(found, st)
	}
	switch len(found) {
	case 0:
		return identity.SlotState{}, errors.New(`no configuration on the token: store one with "postern conf edit", or pass --config FILE`)
	case 1:
		return found[0], nil
	}
	names := make([]string, len(found))
	for i, st := range found {
		names[i] = fmt.Sprintf("%s (%s)", st.Slot, configDescription(st))
	}
	return identity.SlotState{}, fmt.Errorf("the token holds several configurations: %s; pick one with --conf-slot", strings.Join(names, ", "))
}
