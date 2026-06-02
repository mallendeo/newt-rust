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

A stable toolchain is pinned in `rust-toolchain.toml`.

    cargo build --release -p newt

The binary is written to `target/release/newt`.

### Minimum-size build (nightly)

Recompiling `std` from source with size-optimized settings and an immediate-abort
panic strategy produces a smaller binary. It requires the nightly toolchain and the
`rust-src` component:

    rustup toolchain install nightly
    rustup component add rust-src --toolchain nightly

    RUSTFLAGS="-Zlocation-detail=none -Zfmt-debug=none -Zunstable-options -Cpanic=immediate-abort" \
      cargo +nightly build -Z build-std=std,panic_abort \
      -Z build-std-features="optimize_for_size" \
      --target x86_64-unknown-linux-gnu --release -p newt

The binary is written to `target/x86_64-unknown-linux-gnu/release/newt`; substitute your
host triple (`rustc -vV`) for other targets. This is an opt-in release path:
`build-std` requires an explicit `--target`, and `panic=immediate-abort` makes panics
abort rather than unwind, which `cargo test` relies on, so it is not the default build.

Static musl build:

    rustup target add x86_64-unknown-linux-musl
    cargo build --release -p newt --target x86_64-unknown-linux-musl

The musl build needs a musl-targeting C toolchain (`x86_64-linux-musl-gcc`, e.g. from
`musl-tools`) because the `ring` dependency compiles C.

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

x86_64, stripped, measured 2026-06-01:

    target/release/newt                                  1,864,144 bytes   (stable, glibc, dynamic)
    target/x86_64-unknown-linux-gnu/release/newt         1,352,296 bytes   (nightly build-std, glibc)
    target/x86_64-unknown-linux-musl/release/newt        1,991,456 bytes   (stable musl, static-pie)

Idle RSS has not been measured; it requires running against a live Pangolin instance.

## Layout

- `crates/newt-core`: `no_std` + `alloc` protocol types, target parser, and the
  connection state machine.
- `crates/newt`: the `std` binary (config, logging, TLS/token/WebSocket transport,
  WireGuard pump, smoltcp netstack, TCP proxy, and the tunnel event loop).

## License

MIT
