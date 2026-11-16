// Command postern is a WireGuard client whose static key lives on a PIV token.
package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/fang"
	"github.com/go-piv/piv-go/v2/piv"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/term"

	"github.com/iosif2/postern/internal/identity"
)

// version is set at release builds with -ldflags; otherwise the build's own
// module information is shown.
var version = ""

func main() {
	var opts []fang.Option
	if version != "" {
		opts = append(opts, fang.WithVersion(version))
	}
	if err := fang.Execute(context.Background(), rootCmd(), opts...); err != nil {
		os.Exit(1)
	}
}

// rootCmd builds the command tree. The commands themselves are in the files
// named after them.
func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "postern",
		Short: "WireGuard with the static key on a PIV token",
		Long: `postern is a WireGuard client whose private key lives on a PIV token, such as
a YubiKey, and cannot be copied off it. Carry the token, run postern on
whatever machine is at hand, and reach your own network; take the token out
and the way in is shut.`,
		Example: `# once: make the key, then store where it connects to
postern piv keygen
postern conf edit

# anywhere, afterwards
postern up`,
	}
	root.AddCommand(upCmd(), confCmd(), pivCmd())
	return root
}

func pivCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "piv",
		Short: "Manage and check the key on the token",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(pivListCmd(), pivSlotsCmd(), pivInfoCmd(), pivKeygenCmd(), pivSelftestCmd(), pivHandshakeCmd())
	return cmd
}

// tokenFlags are the flags shared by every command that talks to a token.
type tokenFlags struct {
	card string
	slot string
	// confSlot is where the stored configuration is; only some commands
	// have it.
	confSlot string
}

func (t *tokenFlags) registerConf(fs *pflag.FlagSet) {
	fs.StringVar(&t.confSlot, "conf-slot", "", "slot holding the stored configuration, 82-95 (default: the key's slot, else the only one on the token)")
}

func (t *tokenFlags) registerCard(fs *pflag.FlagSet) {
	fs.StringVar(&t.card, "card", "", "substring of the smart card reader name (default: the only YubiKey)")
}

func (t *tokenFlags) register(fs *pflag.FlagSet) {
	t.registerCard(fs)
	fs.StringVar(&t.slot, "slot", "", "slot of the key: 9a, 9c, 9d, 9e or 82-95 (default: wherever the token's X25519 key is)")
}

// resolve returns the card to use. The slot stays a name, possibly empty,
// until the token is open and can be searched.
func (t *tokenFlags) resolve() (card string, err error) {
	for _, name := range []string{t.slot, t.confSlot} {
		if name == "" {
			continue
		}
		if _, err := identity.ParseSlot(name); err != nil {
			return "", err
		}
	}
	return identity.FindCard(t.card)
}

// errCancelled is returned when the user backs out of a prompt.
var errCancelled = errors.New("cancelled; nothing was sent to the token")

// promptPIN asks for the PIN on the terminal. retries is how many attempts
// the token still allows; it is shown once it matters.
//
// Nothing reaches the token until a PIN has been typed and Enter pressed, so
// backing out with Ctrl-C costs no attempt, and the prompt says that it can
// be done.
func promptPIN(retries int) (string, error) {
	switch retries {
	case 1:
		fmt.Fprintln(os.Stderr, "warning: this is the last attempt; a wrong PIN now blocks it")
		fmt.Fprint(os.Stderr, "PIV PIN (Ctrl-C to cancel): ")
	case 2:
		fmt.Fprint(os.Stderr, "PIV PIN (2 attempts left; Ctrl-C to cancel): ")
	default:
		fmt.Fprint(os.Stderr, "PIV PIN (Ctrl-C to cancel): ")
	}

	// Reading a password turns the terminal's echo off. Left to itself,
	// Ctrl-C would end the program with the echo still off, so the signal
	// is taken here and the terminal put back.
	fd := int(os.Stdin.Fd())
	state, _ := term.GetState(fd)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)

	type result struct {
		pin []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		pin, err := term.ReadPassword(fd)
		done <- result{pin, err}
	}()
	select {
	case r := <-done:
		fmt.Fprintln(os.Stderr)
		if r.err != nil {
			return "", r.err
		}
		if len(r.pin) == 0 {
			return "", errCancelled
		}
		return string(r.pin), nil
	case <-sig:
		if state != nil {
			term.Restore(fd, state)
		}
		fmt.Fprintln(os.Stderr)
		return "", errCancelled
	}
}

func pivListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List connected smart cards",
		Args:  cobra.NoArgs,
		RunE:  func(*cobra.Command, []string) error { return pivList() },
	}
}

func pivList() error {
	cards, err := piv.Cards()
	if err != nil {
		return fmt.Errorf("listing smart cards: %w", err)
	}
	if len(cards) == 0 {
		return errors.New("no smart cards connected")
	}
	for _, card := range cards {
		fmt.Println(card)
	}
	return nil
}

func pivSlotsCmd() *cobra.Command {
	var tf tokenFlags
	cmd := &cobra.Command{
		Use:   "slots",
		Short: "Show what each slot of the token holds",
		Long: `Lists the slots that hold something: a key postern can use, a stored
configuration, or something of another program's. Slots not listed are
empty. Nothing is written and no PIN is needed.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error { return pivSlots(tf) },
	}
	tf.registerCard(cmd.Flags())
	return cmd
}

func pivSlots(tf tokenFlags) error {
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
	lines := slotLines(states)
	if len(lines) == 0 {
		fmt.Println("every slot is empty")
		return nil
	}
	for _, line := range lines {
		fmt.Println(line)
	}
	return nil
}

func pivInfoCmd() *cobra.Command {
	var tf tokenFlags
	cmd := &cobra.Command{
		Use:   "info",
		Short: "Show the key in a slot: its policies and WireGuard public key",
		Args:  cobra.NoArgs,
		RunE:  func(*cobra.Command, []string) error { return pivInfo(tf) },
	}
	tf.register(cmd.Flags())
	return cmd
}

func pivInfo(tf tokenFlags) error {
	card, err := tf.resolve()
	if err != nil {
		return err
	}
	yk, err := piv.Open(card)
	if err != nil {
		return fmt.Errorf("opening %s: %w", card, err)
	}
	defer yk.Close()

	slot, err := identity.ResolveSlot(yk, tf.slot)
	if err != nil {
		return err
	}
	pub, info, err := identity.SlotPublicKey(yk, slot)
	if err != nil {
		return err
	}
	fmt.Printf("card:         %s\n", card)
	fmt.Printf("firmware:     %d.%d.%d\n", yk.Version().Major, yk.Version().Minor, yk.Version().Patch)
	fmt.Printf("slot:         %s\n", slot)
	fmt.Printf("pin policy:   %s\n", pinPolicyName(info.PINPolicy))
	fmt.Printf("touch policy: %s\n", touchPolicyName(info.TouchPolicy))
	fmt.Printf("origin:       %s\n", originName(info.Origin))
	fmt.Printf("public key:   %s\n", base64.StdEncoding.EncodeToString(pub.Bytes()))
	return nil
}

func pivKeygenCmd() *cobra.Command {
	var tf tokenFlags
	var pinPolicy, touchPolicy string
	var force bool
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an X25519 key on the token",
		Long: `Generates an X25519 key in a slot of the token and prints its public key, to
add as a peer on the server. The key cannot be read back out.

At a terminal the empty slots among 82 to 95 are offered to choose from;
Enter takes the default. Otherwise --slot names the slot, or slot 82 is used.
An occupied slot is never overwritten without --force.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error { return pivKeygen(tf, pinPolicy, touchPolicy, force) },
	}
	tf.register(cmd.Flags())
	cmd.Flags().StringVar(&pinPolicy, "pin-policy", "once", "when the PIN is required: once, always or never")
	cmd.Flags().StringVar(&touchPolicy, "touch-policy", "never", "when a touch is required: never, cached or always")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite a key that is already in the slot")
	return cmd
}

func pivKeygen(tf tokenFlags, pinPolicy, touchPolicy string, force bool) error {
	key := piv.Key{Algorithm: piv.AlgorithmX25519}
	switch pinPolicy {
	case "once":
		key.PINPolicy = piv.PINPolicyOnce
	case "always":
		key.PINPolicy = piv.PINPolicyAlways
	case "never":
		key.PINPolicy = piv.PINPolicyNever
	default:
		return fmt.Errorf("unknown --pin-policy %q", pinPolicy)
	}
	switch touchPolicy {
	case "never":
		key.TouchPolicy = piv.TouchPolicyNever
	case "cached":
		key.TouchPolicy = piv.TouchPolicyCached
	case "always":
		key.TouchPolicy = piv.TouchPolicyAlways
	default:
		return fmt.Errorf("unknown --touch-policy %q", touchPolicy)
	}

	card, err := tf.resolve()
	if err != nil {
		return err
	}
	yk, err := identity.Open(card)
	if err != nil {
		return err
	}
	defer yk.Close()

	// A new key goes where it is told: asked at the terminal, named with
	// --slot, or else the default slot. Where to write on a token is not
	// something to guess.
	if tf.slot == "" && interactive() {
		states, err := identity.Slots(yk)
		if err != nil {
			return err
		}
		choices, def, inUse, err := keygenChoices(states)
		if err != nil {
			return err
		}
		chosen, err := chooseSlot("Slot for the new key", inUse, choices, def)
		if err != nil {
			return err
		}
		tf.slot = chosen.String()
	}
	if tf.slot == "" {
		tf.slot = identity.DefaultSlot
	}
	slot, err := identity.ParseSlot(tf.slot)
	if err != nil {
		return err
	}

	if _, err := yk.KeyInfo(slot); err == nil && !force {
		free, ferr := identity.FreeSlot(yk)
		if ferr != nil {
			return fmt.Errorf("slot %s already holds a key, and no other slot can be suggested: %w", tf.slot, ferr)
		}
		return fmt.Errorf("slot %s already holds a key, possibly another program's. Slot %s is empty: run again with --slot %s. (--force would overwrite the key in %s.)", tf.slot, free, free, tf.slot)
	}

	mgmt, err := managementKey(yk)
	if err != nil {
		return err
	}
	pub, err := yk.GenerateKey(mgmt, slot, key)
	if err != nil {
		return fmt.Errorf("generating key in slot %s: %w", tf.slot, err)
	}
	x, ok := pub.(interface{ Bytes() []byte })
	if !ok {
		return fmt.Errorf("token returned an unexpected public key type %T", pub)
	}
	// Ask the token what the slot holds now, rather than trusting that the
	// command did what it said.
	stored, _, err := identity.SlotPublicKey(yk, slot)
	if err != nil {
		return fmt.Errorf("the key was generated, but checking slot %s failed: %w", tf.slot, err)
	}
	if !bytes.Equal(stored.Bytes(), x.Bytes()) {
		return fmt.Errorf("slot %s does not hold the key that was just generated", tf.slot)
	}
	fmt.Printf("generated X25519 key in slot %s, and read it back from the token\n", tf.slot)
	// Mark the slot, so that this key is later told apart from an X25519
	// key some other program may keep on the same token.
	switch err := identity.MarkKey(yk, mgmt, slot); {
	case errors.Is(err, identity.ErrOtherCertificate):
		fmt.Fprintf(os.Stderr, "warning: slot %s holds another program's certificate, so the key could not be marked as postern's; name it with --slot %s when it is not found\n", tf.slot, tf.slot)
	case err != nil:
		fmt.Fprintf(os.Stderr, "warning: the key could not be marked as postern's (%v); name it with --slot %s when it is not found\n", err, tf.slot)
	}
	fmt.Printf("public key: %s\n", base64.StdEncoding.EncodeToString(x.Bytes()))
	return nil
}

// managementKey returns the PIV management key: POSTERN_PIV_MANAGEMENT_KEY
// (hex) if set, else the one stored PIN-protected on the token, else the
// factory default.
func managementKey(yk *piv.YubiKey) ([]byte, error) {
	if v := strings.TrimSpace(os.Getenv("POSTERN_PIV_MANAGEMENT_KEY")); v != "" {
		key, err := hex.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("POSTERN_PIV_MANAGEMENT_KEY is not hex: %w", err)
		}
		return key, nil
	}
	retries, err := identity.PINRetries(yk)
	if err != nil {
		return nil, err
	}
	pin, err := promptPIN(retries)
	if err != nil {
		return nil, err
	}
	meta, err := yk.Metadata(pin)
	if err != nil {
		return nil, fmt.Errorf("reading token metadata: %w", err)
	}
	if meta.ManagementKey != nil {
		return *meta.ManagementKey, nil
	}
	return piv.DefaultManagementKey, nil
}

func pivSelftestCmd() *cobra.Command {
	var tf tokenFlags
	var rounds int
	cmd := &cobra.Command{
		Use:   "selftest",
		Short: "Check on-token key agreement against software",
		Args:  cobra.NoArgs,
		RunE:  func(*cobra.Command, []string) error { return pivSelftest(tf, rounds) },
	}
	tf.register(cmd.Flags())
	cmd.Flags().IntVarP(&rounds, "rounds", "n", 5, "number of key agreements to run")
	return cmd
}

func pivSelftest(tf tokenFlags, rounds int) error {
	card, err := tf.resolve()
	if err != nil {
		return err
	}
	token, err := identity.OpenPIV(card, tf.slot, promptPIN)
	if err != nil {
		return err
	}
	defer token.Close()

	var total time.Duration
	for i := 0; i < rounds; i++ {
		peer, err := identity.NewSoftware()
		if err != nil {
			return err
		}
		start := time.Now()
		onToken, err := token.ECDH(peer.PublicKey())
		elapsed := time.Since(start)
		if err != nil {
			return fmt.Errorf("round %d: %w", i+1, err)
		}
		inSoftware, err := peer.ECDH(token.PublicKey())
		if err != nil {
			return fmt.Errorf("round %d: %w", i+1, err)
		}
		if subtle.ConstantTimeCompare(onToken[:], inSoftware[:]) != 1 {
			return fmt.Errorf("round %d: token and software disagree on the shared secret", i+1)
		}
		total += elapsed
		fmt.Printf("round %d: ok (%s)\n", i+1, elapsed.Round(time.Millisecond))
	}
	if rounds > 0 {
		fmt.Printf("all %d rounds match; mean on-token time %s\n", rounds, (total / time.Duration(rounds)).Round(time.Millisecond))
	}
	return nil
}

func pinPolicyName(p piv.PINPolicy) string {
	switch p {
	case piv.PINPolicyNever:
		return "never"
	case piv.PINPolicyOnce:
		return "once"
	case piv.PINPolicyAlways:
		return "always"
	}
	return fmt.Sprintf("unknown (%d)", int(p))
}

func touchPolicyName(p piv.TouchPolicy) string {
	switch p {
	case piv.TouchPolicyNever:
		return "never"
	case piv.TouchPolicyAlways:
		return "always"
	case piv.TouchPolicyCached:
		return "cached"
	}
	return fmt.Sprintf("unknown (%d)", int(p))
}

func originName(o piv.Origin) string {
	switch o {
	case piv.OriginGenerated:
		return "generated on token"
	case piv.OriginImported:
		return "imported"
	}
	return fmt.Sprintf("unknown (%d)", int(o))
}
