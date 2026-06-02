# newt-rust

A minimal Rust reimplementation of the Pangolin `newt` connector. It opens a
userspace WireGuard tunnel to a Pangolin server and proxies server-initiated TCP
connections to local targets. It needs no kernel WireGuard, no TUN device, and no
root: the data plane runs entirely in userspace (boringtun for WireGuard, smoltcp
for the IP stack) over a single UDP socket.

## How it works

The binary fetches a token over HTTPS, opens a WebSocket control channel, pings the
advertised exit nodes, registers a freshly generated WireGuard public key, and brings
up the tunnel from the `wg/connect` payload. Pangolin then initiates TCP connections
into the tunnel to `tunnelIP:listenPort`; newt terminates each in smoltcp and forwards
it to the configured local target over an OS socket.

## Status

- TCP target proxying: implemented.
- UDP target proxying: not implemented.
- Provisioning and mTLS enrollment: not implemented. The `provisioning` Cargo feature
  is declared but empty.

## Build

The toolchain is pinned to nightly with the `rust-src` component
(`rust-toolchain.toml`), and `.cargo/config.toml` enables `build-std` so the release
build recompiles `std` from source with size-optimized settings:

    cargo build --release -p newt

The binary is written to `target/x86_64-unknown-linux-gnu/release/newt`. The default
target lives in `.cargo/config.toml`; change that triple for a different host.

### Absolute-minimum build

Disabling debug formatting and using an immediate-abort panic strategy shrinks the
binary further. `panic=immediate-abort` aborts instead of unwinding, which `cargo test`
relies on, so this is an opt-in command rather than the default:

    RUSTFLAGS="-Zlocation-detail=none -Zfmt-debug=none -Zunstable-options -Cpanic=immediate-abort" \
      cargo build --release -p newt

For the smallest on-disk artifact, the result can be packed with
[UPX](https://github.com/upx/upx) (`upx --best --lzma`). Packing roughly halves the
file but decompresses into memory at startup, raising RSS, so it is not used by default.

The `x86_64-unknown-linux-musl` target does not currently build under the default
`build-std` configuration.

## Configuration

Inputs come from environment variables, overridden by CLI flags. `endpoint`, `id`,
and `secret` are required.

| Environment | Flag | Default | Meaning |
|-------------|------|---------|---------|
| `PANGOLIN_ENDPOINT` | `--endpoint` | (required) | Pangolin base URL, e.g. `https://app.example.com` |
| `NEWT_ID` | `--id` | (required) | Newt client id |
| `NEWT_SECRET` | `--secret` | (required) | Newt client secret |
| `MTU` | `--mtu` | `1280` | Tunnel MTU |
| `LOG_LEVEL` | `--log-level` | `INFO` | `DEBUG`, `INFO`, `WARN`, or `ERROR` |
| `SKIP_TLS_VERIFY` | `--skip-tls-verify` | `false` | Accept any server certificate |
| `DNS` | `--dns` | `9.9.9.9` | Parsed, not yet used |
| `PING_INTERVAL` | | `15s` | Parsed, not yet used |
| `NEWT_UDP_PROXY_IDLE_TIMEOUT` | | `90s` | Parsed, not yet used |

Example:

    NEWT_ID=... NEWT_SECRET=... PANGOLIN_ENDPOINT=https://app.example.com \
      LOG_LEVEL=DEBUG cargo run --release -p newt

## Release profile

`[profile.release]` sets `opt-level = "z"`, `lto = true`, `codegen-units = 1`,
`panic = "abort"`, and `strip = true`. The tokio runtime is current-thread only.

## Measured size

x86_64 glibc, stripped, measured 2026-06-01:

    default release                  1,505,400 bytes
    absolute-minimum                 1,352,296 bytes
    absolute-minimum + UPX           657,820 bytes

Idle RSS has not been measured; it requires running against a live Pangolin instance.

## Layout

- `crates/newt-core`: `no_std` + `alloc` protocol types, target parser, and the
  connection state machine.
- `crates/newt`: the `std` binary (config, logging, TLS/token/WebSocket transport,
  WireGuard pump, smoltcp netstack, TCP proxy, and the tunnel event loop).

## License

MIT
