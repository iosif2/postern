<div align="center">

# postern

**A WireGuard client whose private key lives on a PIV token and never leaves it.**

Plug in your YubiKey on any machine, run one binary, reach your own network.<br>
Take the token out and the way in is shut.

[Usage](#usage) · [Requirements](#requirements) · [Development](#development) · [License](#license)

</div>

The WireGuard handshake uses the static private key for exactly one thing:
X25519 key agreement. postern sends those key agreements to the token, so the
host only ever holds short-lived session keys. Pull the token and the tunnel
closes within a couple of seconds.

The goal is a single binary you can download on a machine you do not own, plug
in your YubiKey, and reach your network through one silent UDP port, with no
admin rights and no long-term secret on that machine.

## Status

Early. What works today:

- `internal/identity`: the `Identity` interface (public key + ECDH), with an
  in-memory implementation and a PIV implementation.
- `postern piv` commands to create a key on the token and check that on-token
  key agreement matches software.
- `internal/device`: the `device` package of `wireguard-go`, patched to take
  its static key as an interface instead of private key bytes. The patch is
  small and listed in `internal/device/UPSTREAM.md`.
- `postern piv handshake`: full WireGuard handshakes, inside one process,
  with the token as one side's static key.
- `postern up`: the tunnel itself, on a userspace network stack, with a SOCKS5
  proxy and port forwards into it. No tunnel device or admin rights.
- `postern conf`: the configuration stored on the token, next to the key.


## Requirements

- A YubiKey with firmware 5.7 or newer (PIV X25519 keys).
- PC/SC: built in on macOS and Windows; `pcscd` on Linux.
- To build: the Go version in `go.mod`. On macOS and Linux the smart card
  library is reached through cgo, so those builds need a C toolchain and
  cannot be cross-compiled with `CGO_ENABLED=0`; Linux also needs the
  `libpcsclite` headers. Windows builds are pure Go.

## Usage

```sh
go build -o postern ./cmd/postern

postern piv keygen      # 1. make the key: pick an empty slot, Enter for the default
postern conf edit       # 2. write the configuration and store it on the token
postern up              # 3. connect, here or on any other machine
```

That is the whole setup, and after it the token is all you carry: `postern
up` finds the key and the configuration on it.

1. `keygen` lists the empty slots among 82 to 95 and generates an X25519 key
   in the one you choose, then reads the slot back to confirm it. It prints
   the public key to add as a peer on the server.
2. `conf edit` asks which slot to keep the configuration with (the key's own,
   unless you choose another), opens it in `$VISUAL`, `$EDITOR`, or else `vi`
   (`notepad` on Windows), checks what you saved, and stores it. If it does
   not check out you are sent back to the editor rather than losing it.
   `conf edit --from home.conf` starts from an existing file, and
   `conf show` prints what is stored.
3. `up` says which slots it is about to use before it asks for the PIN, and
   Ctrl-C at the PIN prompt backs out without costing an attempt. It takes
   `--slot` and `--conf-slot` when the token holds more than one
   key or configuration; otherwise it needs no arguments.

The configuration is an ordinary WireGuard configuration, as `wg` and
`wg-quick` read it, minus the `PrivateKey` line:

```ini
[Interface]
Address = 10.82.0.2/32
DNS = 192.168.88.1

[Peer]
PublicKey = <server public key>
Endpoint = home.example.net:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

It lives in the certificate object of the slot, wrapped in a certificate
that certifies nothing, because a key slot can hold only a key. **That
object can be read without the PIN**: whoever holds the token can see where
it connects, though not connect. So `conf edit` refuses a `PrivateKey` or a
`PresharedKey`; a configuration with a preshared key has to stay in a file.

A file works as well, and wins over the token: `postern up --config
home.conf --forward 2222=192.168.88.10:22`.

Other commands:

```sh
postern piv list        # connected smart cards
postern piv slots       # what each slot holds: keys, configurations
postern piv info        # show the slot's policies and WireGuard public key
postern piv selftest    # compare on-token ECDH with software ECDH
postern piv handshake   # WireGuard handshakes against a throwaway local peer
```

### Connecting

`postern up` asks for the PIN, opens the tunnel and serves, until interrupted:

- a SOCKS5 proxy on `127.0.0.1:1080` (`--socks` to move it, `--socks ""` to
  turn it off). Use `socks5h://`, as in
  `curl -x socks5h://127.0.0.1:1080 http://nas.lan/`, so that names are
  resolved at home rather than by the machine you are on;
- one local port per `--forward LOCAL=HOST:PORT`, so
  `ssh -p 2222 localhost` reaches `192.168.88.10:22`.

Nothing on the machine is reconfigured: only programs pointed at the proxy
or at a forwarded port use the tunnel. `Address` is this side's address
inside the tunnel, as configured for the peer on the server. `DNS` names
resolvers reached through the tunnel; without it only IP addresses work.

Every setting can also be given as a flag (`--peer`, `--endpoint`, `--address`,
`--dns`, ...), with or without a file; flags win. A `PrivateKey` in the file
is ignored with a warning, and so are settings that only apply to a real
network interface, such as `PostUp` or `Table`. One `[Peer]` is supported.
Listeners bind to loopback unless you write out another address, and
postern warns when you do. `postern up --help` lists the remaining flags.

Every command explains itself with `--help`, and `postern completion zsh`
(or `bash`, `fish`, `powershell`) prints a completion script for your shell.

### The token while connected

- **Pulling the token closes the tunnel**, within a couple of seconds, with
  every connection through it. postern does not coast on the session keys
  it already has. To come back, plug the token in and run `postern up`
  again; it asks for the PIN again, because the token has forgotten it.
- **A wrong PIN ends the command.** postern says how many attempts are left
  and never retries by itself, so each attempt is one you typed. It warns
  before the last one. A blocked PIN needs the PUK
  (`ykman piv access unblock-pin`).
- **postern holds the token to itself while it runs.** Other programs that
  want the token (`ykman`, a PIV or OpenPGP agent, a second postern) have to
  wait until it exits, and postern says so when it finds the token taken.
  This is what keeps other programs on the machine from using the unlocked
  key.

`handshake` needs no server: it runs both ends of a tunnel in the process,
one keyed by the token, and reports how long each handshake took.

`keygen` writes to the token. It refuses to overwrite an occupied slot unless
you pass `--force`, and names the next empty slot instead: slots 82 to 95 are
shared with other tools (`age-plugin-yubikey` fills them from 82 up).

Every other command finds the key by itself, so the slot does not have to be
remembered on the next machine. `keygen` marks the slot of a key it makes
(with a certificate named `postern key`; a stored configuration counts as
the mark too), and without `--slot` postern uses the marked X25519 key,
whichever slot it is in. An X25519 key that is not marked, say one made with
`ykman`, is used only when it is the only one on the token, and postern says
so. `--slot` is needed only when there are several to choose from.
`postern piv slots` shows which is which. It uses the management key from
`POSTERN_PIV_MANAGEMENT_KEY` (hex) if set, otherwise the PIN-protected one on
the token, otherwise the factory default.

The public key printed by `keygen` and `info` is in WireGuard's base64 format:
add it as a peer on the server.

### Policies

`keygen` defaults to `--pin-policy once --touch-policy never`. WireGuard rekeys
about every two minutes, and each rekey needs one key agreement on the token,
so `--touch-policy always` means a touch every two minutes. With the default,
the key answers without a touch for as long as postern runs; nothing can copy
it.

## Development

```sh
go test ./...
go vet ./...
```

The tests do not need a token. `postern piv selftest` and
`postern piv handshake` are the hardware checks.

## License

MIT; see [LICENSE](LICENSE). `internal/device` is a patched copy of part of
[wireguard-go](https://git.zx2c4.com/wireguard-go/), also MIT, with its own
licence file and a list of the changes in `internal/device/UPSTREAM.md`.

WireGuard is a registered trademark of Jason A. Donenfeld. postern is not
affiliated with or endorsed by the WireGuard project or by Yubico.
