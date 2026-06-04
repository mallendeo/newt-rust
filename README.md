# newt-rust

A minimal Rust reimplementation of the Pangolin `newt` connector and `olm` client in
one binary. It runs the site role (share local resources), the client role (reach
remote resources), or both, selected by which credentials are present.

The site role opens a userspace WireGuard tunnel to a Pangolin server and proxies
server-initiated TCP connections to local targets, needing no kernel WireGuard, no TUN
device, and no root: the data plane runs entirely in userspace (boringtun for
WireGuard, smoltcp for the IP stack) over a single UDP socket.

The client role brings up a multi-peer WireGuard data plane to the sites it may reach
and exposes those resources to the host, either transparently through a kernel TUN with
OS routes (Linux) or in pure userspace through local TCP forwards (any platform).

## How it works

The binary fetches a token over HTTPS, opens a WebSocket control channel, pings the
advertised exit nodes, registers a freshly generated WireGuard public key, and brings
up the tunnel from the `wg/connect` payload. Pangolin then initiates TCP connections
into the tunnel to `tunnelIP:listenPort`; newt terminates each in smoltcp and forwards
it to the configured local target over an OS socket.

## Status

- Site role (newt) TCP target proxying: implemented.
- Client role (olm): implemented, with kernel-TUN and userspace-forward backends.
  Sites are reached through the exit-node relay; direct peer-to-peer hole punching to
  sites, userspace SOCKS5, and kernel route pruning are not implemented.
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

### Static build (no runtime dependencies)

For a self-contained binary with no shared-library dependencies, build for musl. Add
the target and provide a musl-targeting C compiler (the `ring` dependency compiles C):

    rustup target add x86_64-unknown-linux-musl
    cargo build --release -p newt --target x86_64-unknown-linux-musl

The result at `target/x86_64-unknown-linux-musl/release/newt` reports `statically
linked` under `ldd`. The absolute-minimum `RUSTFLAGS` above can be combined with the
`--target` flag for the smallest static binary.

The default build target is glibc so day-to-day `cargo build`/`cargo test` need no extra
C toolchain; the static musl build is the distribution artifact.

## Container

The `Dockerfile` builds the static musl binary and copies it into a `scratch` image.
The TLS roots are compiled into the binary and nothing is shelled out, so the image
carries no base OS, certificate bundle, or shell:

    docker build -t newt-rust .
    docker run --rm \
      -e NEWT_ID=... -e NEWT_SECRET=... -e PANGOLIN_ENDPOINT=https://app.example.com \
      newt-rust

The client role runs from the same image. Userspace mode needs no privileges; kernel
mode needs the TUN device, `CAP_NET_ADMIN`, and host networking to program the host's
routes:

    # userspace client (host networking so the local forward is reachable on the host)
    docker run --rm --network host \
      -e OLM_ID=... -e OLM_SECRET=... -e PANGOLIN_ENDPOINT=https://app.example.com \
      -e OLM_ACCESS_MODE=userspace -e OLM_FORWARDS=8080:10.0.0.5:80 \
      newt-rust

    # kernel client (transparent routing)
    docker run --rm --network host --cap-add NET_ADMIN --device /dev/net/tun \
      -e OLM_ID=... -e OLM_SECRET=... -e PANGOLIN_ENDPOINT=https://app.example.com \
      -e OLM_ACCESS_MODE=kernel \
      newt-rust

The image holds a single file: the binary.

## Configuration

Inputs come from environment variables, overridden by CLI flags. `PANGOLIN_ENDPOINT`
is always required; supply the credentials for at least one role: a site
(`NEWT_ID`/`NEWT_SECRET`), a client (`OLM_ID`/`OLM_SECRET`), or both.

Shared options:

| Environment | Flag | Default | Meaning |
|-------------|------|---------|---------|
| `PANGOLIN_ENDPOINT` | `--endpoint` | (required) | Pangolin base URL, e.g. `https://app.example.com` |
| `MTU` | `--mtu` | `1280` | Tunnel MTU |
| `LOG_LEVEL` | `--log-level` | `INFO` | `DEBUG`, `INFO`, `WARN`, or `ERROR` |
| `SKIP_TLS_VERIFY` | `--skip-tls-verify` | `false` | Accept any server certificate |

### Site (newt) role

Shares local resources. Set `NEWT_ID`/`NEWT_SECRET` to enable it.

| Environment | Flag | Default | Meaning |
|-------------|------|---------|---------|
| `NEWT_ID` | `--id` | (site role) | Newt site id |
| `NEWT_SECRET` | `--secret` | (site role) | Newt site secret |
| `DNS` | `--dns` | `9.9.9.9` | Parsed, not yet used |
| `PING_INTERVAL` | | `15s` | Parsed, not yet used |
| `NEWT_UDP_PROXY_IDLE_TIMEOUT` | | `90s` | Parsed, not yet used |

Example:

    NEWT_ID=... NEWT_SECRET=... PANGOLIN_ENDPOINT=https://app.example.com \
      LOG_LEVEL=DEBUG cargo run --release -p newt

### Client (olm) role

Connects as a Pangolin client and makes the resources it is granted reachable on the
host. Set `OLM_ID`/`OLM_SECRET` to enable it.

| Environment | Flag | Default | Meaning |
|-------------|------|---------|---------|
| `OLM_ID` | `--olm-id` | (client role) | Olm client id |
| `OLM_SECRET` | `--olm-secret` | (client role) | Olm client secret |
| `OLM_ACCESS_MODE` | `--olm-access` | `kernel` on Linux, else `userspace` | `kernel`: TUN + OS routes; `userspace`: local TCP forwards |
| `OLM_INTERFACE` | `--olm-interface` | `olm` | TUN interface name (kernel mode) |
| `OLM_FORWARDS` | `--olm-forwards` | (none) | Userspace forwards, `listen:host:port` comma-separated |
| `OLM_USER_TOKEN` | `--olm-user-token` | (none) | Optional user token |
| `PANGOLIN_ORG_ID` / `ORG_ID` | `--org-id` | (none) | Optional organization id |

Two access modes:

- `userspace` (any platform, no privileges): each `OLM_FORWARDS` entry opens a TCP
  listener on `127.0.0.1:<listen>` that bridges to `<host>:<port>` through the tunnel.
  `OLM_FORWARDS=8080:10.0.0.5:80` makes `10.0.0.5:80` reachable at `localhost:8080`.
- `kernel` (Linux): creates a TUN interface, assigns the tunnel IP, and adds routes for
  the reachable subnets via netlink, so traffic to those subnets is carried
  transparently. Needs `/dev/net/tun` and `CAP_NET_ADMIN`.

Examples:

    # userspace: reach a remote service through a local port
    OLM_ID=... OLM_SECRET=... PANGOLIN_ENDPOINT=https://app.example.com \
      OLM_ACCESS_MODE=userspace OLM_FORWARDS=8080:10.0.0.5:80 \
      cargo run --release -p newt

    # both roles at once: a site that also reaches other sites
    NEWT_ID=... NEWT_SECRET=... OLM_ID=... OLM_SECRET=... \
      PANGOLIN_ENDPOINT=https://app.example.com cargo run --release -p newt

## Release profile

`[profile.release]` sets `opt-level = "z"`, `lto = true`, `codegen-units = 1`,
`panic = "abort"`, and `strip = true`. The tokio runtime is current-thread only.

## Measured size

x86_64, stripped, measured 2026-06-01:

    glibc (dynamic):
      default release          1,505,400 bytes
      absolute-minimum         1,352,296 bytes
    musl (static, no deps):
      default release          1,632,632 bytes
      absolute-minimum         1,411,416 bytes
      absolute-minimum + UPX     691,740 bytes

Idle RSS has not been measured; it requires running against a live Pangolin instance.

## Layout

- `crates/newt-core`: `no_std` + `alloc` protocol types, target parser, and the
  connection state machine.
- `crates/newt`: the `std` binary (config, logging, TLS/token/WebSocket transport,
  WireGuard pump, smoltcp netstack, TCP proxy, the site tunnel loop, and the client
  role under `olm/` with its multi-peer router and kernel-TUN/userspace backends).

## License

MIT
