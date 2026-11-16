package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"

	"github.com/iosif2/postern/internal/identity"
)

const goodConf = `[Interface]
Address = 10.0.0.2/32
DNS = 192.168.88.1

[Peer]
PublicKey = 61UMFtbnkh9pGApTaocFfbtTGQPIEnpqSDN1pkcnpQw=
Endpoint = home.example.org:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`

func slot(t *testing.T, name string) piv.Slot {
	t.Helper()
	s, err := identity.ParseSlot(name)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// tokenWith builds the state of a token: every slot empty except those
// given.
func tokenWith(t *testing.T, set map[string]identity.SlotState) []identity.SlotState {
	t.Helper()
	var states []identity.SlotState
	names := []string{"82", "83", "84", "85", "86", "87", "88", "89", "8a", "8b", "8c", "8d", "8e", "8f", "90", "91", "92", "93", "94", "95", "9a", "9c", "9d", "9e"}
	for _, name := range names {
		st := set[name]
		st.Slot = slot(t, name)
		states = append(states, st)
	}
	return states
}

var (
	ourKey   = identity.SlotState{HasKey: true, X25519: true, Marked: true, PublicKey: [32]byte{1}}
	otherKey = identity.SlotState{HasKey: true}
	withConf = identity.SlotState{Marked: true, Config: []byte(goodConf)}
)

func TestCheckTokenConfig(t *testing.T) {
	if err := checkTokenConfig([]byte(goodConf), io.Discard); err != nil {
		t.Fatalf("a good configuration was refused: %v", err)
	}
	cases := map[string]struct{ conf, want string }{
		"private key":   {strings.Replace(goodConf, "[Interface]\n", "[Interface]\nPrivateKey = 61UMFtbnkh9pGApTaocFfbtTGQPIEnpqSDN1pkcnpQw=\n", 1), "PrivateKey"},
		"preshared key": {goodConf + "PresharedKey = 61UMFtbnkh9pGApTaocFfbtTGQPIEnpqSDN1pkcnpQw=\n", "PresharedKey"},
		"no endpoint":   {strings.Replace(goodConf, "Endpoint = home.example.org:51820\n", "", 1), "required"},
		"empty address": {strings.Replace(goodConf, "Address = 10.0.0.2/32", "Address =", 1), "required"},
		"bad peer key":  {strings.Replace(goodConf, "61UMFtbnkh9pGApTaocFfbtTGQPIEnpqSDN1pkcnpQw=", "nonsense", 1), "peer public key"},
		"bad endpoint":  {strings.Replace(goodConf, "home.example.org:51820", "home.example.org", 1), "endpoint"},
		"not a config":  {"hello\n", ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := checkTokenConfig([]byte(c.conf), io.Discard)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error mentioning %q", err, c.want)
			}
		})
	}
}

// The endpoint's name must not be looked up when checking: the check has to
// work where the name does not resolve.
func TestCheckTokenConfigDoesNotResolve(t *testing.T) {
	conf := strings.Replace(goodConf, "home.example.org", "does-not-exist.invalid", 1)
	if err := checkTokenConfig([]byte(conf), io.Discard); err != nil {
		t.Fatalf("refused over a name that does not resolve: %v", err)
	}
}

func TestTemplateIsNotStorableAsItIs(t *testing.T) {
	states := tokenWith(t, map[string]identity.SlotState{"83": ourKey})
	tmpl := confTemplate(states, slot(t, "83"))
	if !strings.Contains(string(tmpl), "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") || !strings.Contains(string(tmpl), "slot 83") {
		t.Errorf("template does not name the token's public key:\n%s", tmpl)
	}
	if err := checkTokenConfig(tmpl, io.Discard); err == nil {
		t.Fatal("an unfilled template passed the check")
	}
}

func TestEditLoop(t *testing.T) {
	bad := strings.Replace(goodConf, "Endpoint = home.example.org:51820\n", "", 1)

	t.Run("fixed on the second try", func(t *testing.T) {
		var seen []string
		edits := []string{bad, goodConf}
		edit := func(text []byte) ([]byte, error) {
			seen = append(seen, string(text))
			next := edits[0]
			edits = edits[1:]
			return []byte(next), nil
		}
		asked := 0
		again := func(error) (bool, error) { asked++; return true, nil }
		got, err := editLoop([]byte("start"), edit, again, io.Discard)
		if err != nil || string(got) != goodConf {
			t.Fatalf("got %q, %v", got, err)
		}
		if asked != 1 {
			t.Errorf("asked %d times whether to edit again, want 1", asked)
		}
		// The second round must start from what was typed, not from scratch.
		if len(seen) != 2 || seen[0] != "start" || seen[1] != bad {
			t.Errorf("editor was opened with %q", seen)
		}
	})
	t.Run("given up", func(t *testing.T) {
		edit := func([]byte) ([]byte, error) { return []byte(bad), nil }
		_, err := editLoop(nil, edit, func(error) (bool, error) { return false, nil }, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "nothing stored") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("left empty", func(t *testing.T) {
		edit := func([]byte) ([]byte, error) { return []byte(" \n"), nil }
		_, err := editLoop(nil, edit, func(error) (bool, error) { t.Fatal("asked to edit again"); return false, nil }, io.Discard)
		if err == nil {
			t.Fatal("an empty configuration was accepted")
		}
	})
	t.Run("editor fails", func(t *testing.T) {
		broken := errors.New("no such editor")
		_, err := editLoop(nil, func([]byte) ([]byte, error) { return nil, broken }, nil, io.Discard)
		if !errors.Is(err, broken) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestEditorCommand(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	cases := []struct {
		env  map[string]string
		goos string
		want string
	}{
		{map[string]string{"VISUAL": "code --wait", "EDITOR": "nano"}, "linux", "code --wait"},
		{map[string]string{"EDITOR": "nano"}, "darwin", "nano"},
		{map[string]string{"VISUAL": "  "}, "linux", "vi"},
		{nil, "darwin", "vi"},
		{nil, "windows", "notepad"},
	}
	for _, c := range cases {
		if got := strings.Join(editorCommand(env(c.env), c.goos), " "); got != c.want {
			t.Errorf("env %v on %s: got %q, want %q", c.env, c.goos, got, c.want)
		}
	}
}

func TestKeygenChoices(t *testing.T) {
	// 82 is another program's, 83 is ours: the next key is offered 84.
	states := tokenWith(t, map[string]identity.SlotState{"82": otherKey, "83": ourKey, "9a": otherKey})
	choices, def, inUse, err := keygenChoices(states)
	if err != nil {
		t.Fatal(err)
	}
	if def != slot(t, "84") {
		t.Errorf("default is %s, want 84", def)
	}
	if len(choices) != 18 {
		t.Errorf("%d slots offered, want the 18 empty ones", len(choices))
	}
	for _, c := range choices {
		if c.slot == slot(t, "82") || c.slot == slot(t, "83") || c.slot == slot(t, "9a") {
			t.Errorf("occupied or assigned slot %s offered", c.slot)
		}
	}
	if !strings.Contains(inUse, "82") || !strings.Contains(inUse, "83 (postern key)") {
		t.Errorf("in-use line %q", inUse)
	}

	// On an untouched token the default is the default slot.
	_, def, inUse, err = keygenChoices(tokenWith(t, nil))
	if err != nil || def.String() != identity.DefaultSlot || inUse != "" {
		t.Errorf("empty token: default %s, in use %q, err %v", def, inUse, err)
	}

	full := map[string]identity.SlotState{}
	for _, st := range tokenWith(t, nil) {
		full[st.Slot.String()] = otherKey
	}
	if _, _, _, err := keygenChoices(tokenWith(t, full)); err == nil {
		t.Error("a full token still offered a slot")
	}
}

func TestConfChoices(t *testing.T) {
	states := tokenWith(t, map[string]identity.SlotState{
		"82": {HasKey: true, OtherCert: true},
		"84": ourKey,
		"85": withConf,
	})
	choices, def, inUse, err := confChoices(states)
	if err != nil {
		t.Fatal(err)
	}
	// The configuration goes with the key unless told otherwise.
	if def != slot(t, "84") {
		t.Errorf("default is %s, want the key's slot 84", def)
	}
	labels := map[string]string{}
	for _, c := range choices {
		labels[c.slot.String()] = c.label
	}
	if _, offered := labels["82"]; offered {
		t.Error("a slot with another program's certificate was offered")
	}
	if !strings.Contains(labels["84"], "postern key") || !strings.Contains(labels["85"], "home.example.org:51820") || !strings.Contains(labels["86"], "empty") {
		t.Errorf("labels do not say what the slots hold: %v", labels)
	}
	if !strings.Contains(inUse, "82") {
		t.Errorf("in-use line %q", inUse)
	}
}

func TestPickConfig(t *testing.T) {
	key84 := slot(t, "84")
	other := identity.SlotState{Config: []byte(strings.Replace(goodConf, "home.example.org", "office.example.org", 1))}

	t.Run("with the key", func(t *testing.T) {
		states := tokenWith(t, map[string]identity.SlotState{"84": {HasKey: true, X25519: true, Marked: true, Config: []byte(goodConf)}, "85": other})
		st, err := pickConfig(states, &key84, "")
		if err != nil || st.Slot != key84 {
			t.Fatalf("got slot %s, %v; want the key's", st.Slot, err)
		}
	})
	t.Run("the only one", func(t *testing.T) {
		states := tokenWith(t, map[string]identity.SlotState{"84": ourKey, "87": withConf})
		st, err := pickConfig(states, &key84, "")
		if err != nil || st.Slot != slot(t, "87") {
			t.Fatalf("got slot %s, %v; want 87", st.Slot, err)
		}
	})
	t.Run("named", func(t *testing.T) {
		states := tokenWith(t, map[string]identity.SlotState{"84": {HasKey: true, X25519: true, Marked: true, Config: []byte(goodConf)}, "85": other})
		st, err := pickConfig(states, &key84, "85")
		if err != nil || st.Slot != slot(t, "85") {
			t.Fatalf("got slot %s, %v; want 85", st.Slot, err)
		}
		if _, err := pickConfig(states, &key84, "86"); err == nil || !strings.Contains(err.Error(), "conf edit") {
			t.Fatalf("naming an empty slot: %v", err)
		}
	})
	t.Run("several and none with the key", func(t *testing.T) {
		states := tokenWith(t, map[string]identity.SlotState{"84": ourKey, "85": withConf, "86": other})
		_, err := pickConfig(states, &key84, "")
		if err == nil || !strings.Contains(err.Error(), "--conf-slot") || !strings.Contains(err.Error(), "office.example.org") {
			t.Fatalf("got %v, want the configurations listed", err)
		}
	})
	t.Run("none", func(t *testing.T) {
		_, err := pickConfig(tokenWith(t, map[string]identity.SlotState{"84": ourKey}), &key84, "")
		if err == nil || !strings.Contains(err.Error(), "conf edit") {
			t.Fatalf("got %v, want a pointer to conf edit", err)
		}
	})
}

func TestConfTargetNamed(t *testing.T) {
	states := tokenWith(t, map[string]identity.SlotState{"82": {HasKey: true, OtherCert: true}, "84": ourKey})
	if _, err := confTarget(states, "9a", false); err == nil {
		t.Error("a slot with an assigned use was accepted")
	}
	if _, err := confTarget(states, "82", false); err == nil || !strings.Contains(err.Error(), "-force") {
		t.Errorf("another program's certificate: %v", err)
	}
	if st, err := confTarget(states, "82", true); err != nil || st.Slot != slot(t, "82") {
		t.Errorf("with -force: %v, %v", st.Slot, err)
	}
	if st, err := confTarget(states, "84", false); err != nil || st.Slot != slot(t, "84") {
		t.Errorf("the key's slot: %v, %v", st.Slot, err)
	}
}

// With flags that say nothing about where to connect, the stored
// configuration fills in, and flags still win over it.
func TestUpTakesTheStoredConfiguration(t *testing.T) {
	var tf tokenFlags
	p, err := newUpParse([]string{"--dns", "10.9.9.9"}, &tf, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !p.needsConfig() {
		t.Fatal("flags without a peer were taken as complete")
	}
	conf := strings.Replace(goodConf, "home.example.org:51820", "192.0.2.7:51820", 1)
	if err := p.apply([]byte(conf), "configuration in slot 84"); err != nil {
		t.Fatal(err)
	}
	opts, err := p.finish(resolveEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	if opts.tunnel.Endpoint.String() != "192.0.2.7:51820" {
		t.Errorf("endpoint %s", opts.tunnel.Endpoint)
	}
	if len(opts.tunnel.DNS) != 1 || opts.tunnel.DNS[0].String() != "10.9.9.9" {
		t.Errorf("the -dns flag lost to the stored configuration: %v", opts.tunnel.DNS)
	}

	if _, err := newUpParse([]string{"--config", "x.conf", "--conf-slot", "84"}, &tokenFlags{}, io.Discard); err == nil {
		t.Error("-config together with -conf-slot was accepted")
	}
}

func TestRunEditor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a shell script as the editor")
	}
	script := filepath.Join(t.TempDir(), "editor.sh")
	if err := os.WriteFile(script, []byte("echo 'added by the editor' >> \"$1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "sh "+script)
	got, err := runEditor([]byte("first line\n"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "first line\nadded by the editor\n" {
		t.Fatalf("got %q", got)
	}

	t.Setenv("EDITOR", "postern-no-such-editor")
	if _, err := runEditor(nil); err == nil || !strings.Contains(err.Error(), "EDITOR") {
		t.Fatalf("a missing editor: %v", err)
	}
}

func TestSlotLines(t *testing.T) {
	states := tokenWith(t, map[string]identity.SlotState{
		"82": {HasKey: true, X25519: true, Marked: true, PublicKey: [32]byte{1}, Config: []byte(goodConf)},
		"83": otherKey,
	})
	lines := slotLines(states)
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want one per occupied slot: %q", len(lines), lines)
	}
	for _, want := range []string{"82", "postern key", "home.example.org:51820", "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("line %q does not mention %q", lines[0], want)
		}
	}
	if !strings.Contains(lines[1], "83") || !strings.Contains(lines[1], "another program") {
		t.Errorf("line %q", lines[1])
	}
	if len(slotLines(tokenWith(t, nil))) != 0 {
		t.Error("an empty token produced lines")
	}
}

// A key of another program's, or one not marked, must be told apart at a
// glance.
func TestSlotLinesTellKeysApart(t *testing.T) {
	states := tokenWith(t, map[string]identity.SlotState{
		"82": {HasKey: true, X25519: true},
		"83": ourKey,
	})
	lines := slotLines(states)
	if len(lines) != 2 || !strings.Contains(lines[0], "not marked") || !strings.Contains(lines[1], "postern key") {
		t.Fatalf("got %q", lines)
	}
}

// A slot holding only another program's certificate is not offered for a
// new key: the key could not be marked there.
func TestKeygenChoicesSkipForeignCertificates(t *testing.T) {
	states := tokenWith(t, map[string]identity.SlotState{"82": {OtherCert: true}})
	choices, def, inUse, err := keygenChoices(states)
	if err != nil {
		t.Fatal(err)
	}
	if def != slot(t, "83") || len(choices) != 19 || !strings.Contains(inUse, "82") {
		t.Fatalf("default %s, %d choices, in use %q", def, len(choices), inUse)
	}
}
