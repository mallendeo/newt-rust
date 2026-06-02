FROM rust:slim AS builder

RUN apt-get update \
 && apt-get install -y --no-install-recommends musl-tools \
 && rm -rf /var/lib/apt/lists/*
RUN rustup toolchain install nightly --profile minimal --component rust-src \
 && rustup target add x86_64-unknown-linux-musl --toolchain nightly

WORKDIR /app
COPY . .

ENV CC_x86_64_unknown_linux_musl=musl-gcc \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
    RUSTFLAGS="-Zlocation-detail=none -Zfmt-debug=none -Zunstable-options -Cpanic=immediate-abort"
RUN cargo build --release -p newt --target x86_64-unknown-linux-musl \
 && cp target/x86_64-unknown-linux-musl/release/newt /newt

FROM scratch
COPY --from=builder /newt /newt
ENTRYPOINT ["/newt"]
