package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/go-piv/piv-go/v2/piv"
	"github.com/spf13/cobra"

	"github.com/iosif2/postern/internal/identity"
)

const confLong = `The configuration is a WireGuard configuration as wg and wg-quick read it,
without the PrivateKey line. It is stored in the certificate object of a
slot, by default the slot of the key, and "postern up" uses it when it is
given no other.

It can be read from the token without the PIN, so nothing secret may be in
it: a PrivateKey or a PresharedKey is refused.`

func confCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "conf",
		Short: "Manage the configuration stored on the token",
		Long:  confLong,
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(confEditCmd(), confShowCmd())
	return cmd
}

func confShowCmd() *cobra.Command {
	var tf tokenFlags
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Print the configuration stored on the token",
		Args:  cobra.NoArgs,
		RunE:  func(*cobra.Command, []string) error { return confShow(tf) },
	}
	tf.registerCard(cmd.Flags())
	tf.registerConf(cmd.Flags())
	return cmd
}

func confShow(tf tokenFlags) error {
	card, err := tf.resolve()
	if err != nil {
		return err
	}
	yk, err := identity.Open(card)
	if err != nil {
		return err
	}
	defer yk.Close()
	states, err := identity.Slots(yk)
	if err != nil {
		return err
	}
	st, err := pickConfig(states, keySlot(states), tf.confSlot)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "configuration in slot %s:\n", st.Slot)
	_, err = os.Stdout.Write(st.Config)
	return err
}

// keySlot returns the slot of postern's key on the token, or nil if there
// is none or it is not clear which it is. A configuration is presumed to go
// with that key.
func keySlot(states []identity.SlotState) *piv.Slot {
	slot, _, err := identity.PickKey(states)
	if err != nil {
		return nil
	}
	return &slot
}

func confEditCmd() *cobra.Command {
	var tf tokenFlags
	var from string
	var force bool
	cmd := &cobra.Command{
		Use:   "edit",
		Short: "Write or change the configuration stored on the token",
		Long: `Opens the stored configuration, or a template for a new one, in your editor
($VISUAL, then $EDITOR, then vi, or notepad on Windows), checks what you
save, and stores it on the token. If it does not check out you are sent back
to the editor.

At a terminal the slots it can be stored with are offered to choose from;
Enter takes the slot of the key.

` + confLong,
		Example: `postern conf edit
postern conf edit --from home.conf`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error { return confEdit(tf, from, force) },
	}
	tf.registerCard(cmd.Flags())
	tf.registerConf(cmd.Flags())
	cmd.Flags().StringVar(&from, "from", "", "start from this file instead of what is stored; without a terminal it is stored as it is")
	cmd.Flags().BoolVar(&force, "force", false, "replace a certificate in the slot that is not a postern configuration")
	return cmd
}

func confEdit(tf tokenFlags, from string, force bool) error {
	card, err := tf.resolve()
	if err != nil {
		return err
	}
	yk, err := identity.Open(card)
	if err != nil {
		return err
	}
	defer yk.Close()
	states, err := identity.Slots(yk)
	if err != nil {
		return err
	}

	st, err := confTarget(states, tf.confSlot, force)
	if err != nil {
		return err
	}

	initial := st.Config
	if from != "" {
		if initial, err = os.ReadFile(from); err != nil {
			return err
		}
	}
	if initial == nil {
		initial = confTemplate(states, st.Slot)
	}

	var edited []byte
	if interactive() {
		edited, err = editLoop(initial, runEditor, askEditAgain, os.Stderr)
	} else {
		if from == "" {
			return errors.New("no terminal to edit in: give the configuration with --from FILE")
		}
		edited = initial
		err = checkTokenConfig(edited, os.Stderr)
	}
	if err != nil {
		return err
	}
	if bytes.Equal(edited, st.Config) {
		fmt.Fprintf(os.Stderr, "no changes; the configuration in slot %s is as it was\n", st.Slot)
		return nil
	}

	mgmt, err := managementKey(yk)
	if err != nil {
		return err
	}
	if err := identity.WriteConfig(yk, mgmt, st.Slot, edited); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "stored and read back: the configuration is in slot %s\n", st.Slot)
	return nil
}

// confTarget decides which slot a configuration is written to: the one
// named, the one chosen at the terminal, or the default.
func confTarget(states []identity.SlotState, name string, force bool) (identity.SlotState, error) {
	find := func(slot piv.Slot) identity.SlotState {
		for _, st := range states {
			if st.Slot == slot {
				return st
			}
		}
		return identity.SlotState{Slot: slot}
	}
	if name != "" {
		slot, err := identity.ParseSlot(name)
		if err != nil {
			return identity.SlotState{}, err
		}
		if !identity.IsRetired(slot) {
			return identity.SlotState{}, fmt.Errorf("slot %s has an assigned use; a configuration goes with one of the slots 82 to 95", slot)
		}
		st := find(slot)
		if st.OtherCert && !force {
			return identity.SlotState{}, fmt.Errorf("slot %s holds a certificate that is not a postern configuration; pass --force to replace it", slot)
		}
		return st, nil
	}
	choices, def, inUse, err := confChoices(states)
	if err != nil {
		return identity.SlotState{}, err
	}
	if !interactive() {
		return find(def), nil
	}
	slot, err := chooseSlot("Slot to store the configuration with", inUse, choices, def)
	if err != nil {
		return identity.SlotState{}, err
	}
	return find(slot), nil
}

// confTemplate is what a new configuration starts as. It names the public
// key of the key it will be used with, since that is what the server needs.
func confTemplate(states []identity.SlotState, slot piv.Slot) []byte {
	var b strings.Builder
	b.WriteString("# postern configuration, stored on the token.\n")
	b.WriteString("# It can be read from the token without the PIN: keep secrets out of it.\n")
	key := keySlot(states)
	for _, st := range states {
		if st.X25519 && (st.Slot == slot || (key != nil && st.Slot == *key)) {
			fmt.Fprintf(&b, "# This token's public key (slot %s), to add as a peer on the server:\n#   %s\n",
				st.Slot, base64.StdEncoding.EncodeToString(st.PublicKey[:]))
			break
		}
	}
	b.WriteString(`
[Interface]
# This side's address inside the tunnel, as set for the peer on the server.
Address =
# Resolvers reached through the tunnel; needed to connect by name.
DNS =

[Peer]
# The server's public key and where to reach it.
PublicKey =
Endpoint =
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`)
	return []byte(b.String())
}

// checkTokenConfig reports whether data may be stored on the token: it has
// to be a configuration "postern up" accepts, and free of secrets, because
// what is stored there can be read without the PIN. Warnings go to warn.
func checkTokenConfig(data []byte, warn io.Writer) error {
	cfg, err := parseWGConfig(data)
	if err != nil {
		return err
	}
	if cfg.hasPrivateKey {
		return errors.New("PrivateKey must not be stored on the token: remove the line (the key in the slot is the private key)")
	}
	if cfg.presharedKey != nil {
		return errors.New("PresharedKey is a secret and what is stored here can be read without the PIN: remove the line")
	}
	p, err := newUpParse(nil, &tokenFlags{}, warn)
	if err != nil {
		return err
	}
	if err := p.apply(data, "configuration"); err != nil {
		return err
	}
	// The endpoint's name is checked for form only: this may well be run
	// somewhere it does not resolve.
	_, err = p.finish(func(s string) (netip.AddrPort, error) {
		if ap, err := netip.ParseAddrPort(s); err == nil {
			return ap, nil
		}
		return netip.AddrPort{}, checkHostPort(s)
	})
	return err
}

// editLoop has the configuration edited until it can be stored. edit opens
// it for editing and returns the result; again is asked, after a result that
// cannot be stored, whether to go back to it.
func editLoop(initial []byte, edit func([]byte) ([]byte, error), again func(error) (bool, error), warn io.Writer) ([]byte, error) {
	text := initial
	for {
		edited, err := edit(text)
		if err != nil {
			return nil, err
		}
		if len(bytes.TrimSpace(edited)) == 0 {
			return nil, errors.New("the configuration was left empty; nothing stored")
		}
		problem := checkTokenConfig(edited, warn)
		if problem == nil {
			return edited, nil
		}
		ok, err := again(problem)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("nothing stored: %w", problem)
		}
		text = edited
	}
}

func askEditAgain(problem error) (bool, error) {
	again := true
	err := huh.NewConfirm().
		Title("This configuration cannot be stored").
		Description(problem.Error()).
		Affirmative("Edit again").
		Negative("Give up").
		Value(&again).
		Run()
	if errors.Is(err, huh.ErrUserAborted) {
		return false, nil
	}
	return again, err
}

// editorCommand returns the editor to run: $VISUAL, then $EDITOR, then the
// editor every system of that kind has. The variables may carry arguments,
// as in "code --wait".
func editorCommand(getenv func(string) string, goos string) []string {
	for _, name := range []string{"VISUAL", "EDITOR"} {
		if cmd := strings.Fields(getenv(name)); len(cmd) > 0 {
			return cmd
		}
	}
	if goos == "windows" {
		return []string{"notepad"}
	}
	return []string{"vi"}
}

// runEditor opens text in the user's editor and returns what was saved.
func runEditor(text []byte) ([]byte, error) {
	dir, err := os.MkdirTemp("", "postern-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "postern.conf")
	if err := os.WriteFile(path, text, 0o600); err != nil {
		return nil, err
	}
	argv := append(editorCommand(os.Getenv, runtime.GOOS), path)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("running the editor %q (set VISUAL or EDITOR to use another): %w", argv[0], err)
	}
	return os.ReadFile(path)
}
