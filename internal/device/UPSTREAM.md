# Vendored from wireguard-go

This directory is the `device` package of
[wireguard-go](https://git.zx2c4.com/wireguard-go), copied at commit
`b3bc704ef0ee21a36298601a9e1e5ff90377ac52` (2026-10-25) and patched so that
the static private key does not have to be in process memory. It is MIT
licensed; see `LICENSE` in this directory.

Only `device` is vendored. Everything else (`conn`, `tun`, `tun/netstack`,
`ipc`, ...) is used unmodified from the `golang.zx2c4.com/wireguard` module,
pinned to the same commit in `go.mod`.

## What is changed

The Noise IK handshake uses the static private key for X25519 key agreement
and nothing else. The patch routes those calls through an interface.

| File | Change |
| --- | --- |
| `statickey.go` | New. `StaticKey` interface, `SetStaticKey`, `StaticSecretReady`, the in-memory `softwareStaticKey`, and `staticSharedSecret`. |
| `device.go` | `staticIdentity.privateKey` becomes `staticIdentity.key StaticKey`. `SetPrivateKey` wraps the key and calls the shared `setStaticKey`. |
| `peer.go` | Static-static precomputation goes through `staticSharedSecret`. |
| `noise-protocol.go` | The two static-ephemeral agreements go through `staticSharedSecret`. |
| `uapi.go` | `private_key` is only reported for an in-memory key. |
| `statickey_test.go` | New. |
| `device_test.go`, `noise_test.go` | Three references to the removed `privateKey` field. |
| `pools_test.go` | `max` → `max.Load()` in one `Errorf`, so `go vet` passes. |

`SetPrivateKey` and the UAPI `private_key` setting behave as upstream, so the
upstream tests run unchanged apart from the field references above.

## Updating

1. Check out the new upstream commit and compare its `device/` with the old
   one to see what moved.
2. Copy the new `device/*.go` over this directory, keeping `statickey.go`,
   `statickey_test.go` and this file.
3. Reapply the changes in the table. `grep -n privateKey *.go` finds every
   place that needs it.
4. `go get golang.zx2c4.com/wireguard@<commit>`, then `go vet ./...` and
   `go test -race ./internal/device/`.
