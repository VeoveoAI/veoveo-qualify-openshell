# syntax=docker/dockerfile:1.27@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# The probe image: the probe binary, the Go token probe, a Rust toolchain the sandbox
# user owns and the sample crate.

FROM rust:1.100.0-trixie@sha256:223cc32ddca8f3ee90c436dbc94b6b5f052ea7f9653c5201e9612f08ad7d21b8 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs rust-toolchain.toml ./
COPY proto proto
COPY src src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin probe && cp target/release/probe /probe

# Static, as buildctl is, so Go reads the system trust store itself.
FROM golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d AS go
WORKDIR /src
COPY image/token-probe ./
RUN CGO_ENABLED=0 go build -trimpath -o /token-probe .

FROM rust:1.100.0-trixie@sha256:223cc32ddca8f3ee90c436dbc94b6b5f052ea7f9653c5201e9612f08ad7d21b8
RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates curl git procps \
    && rm -rf /var/lib/apt/lists/* /var/log/apt /var/log/dpkg.log \
    && useradd --create-home --uid 1000 --shell /bin/bash sandbox \
    && chown -R sandbox:sandbox /usr/local/rustup /usr/local/cargo \
    && printf 'export RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo\nexport PATH=/usr/local/cargo/bin:$PATH\n' > /etc/profile.d/rust.sh
COPY --from=build /probe /usr/local/bin/probe
COPY --from=go /token-probe /usr/local/bin/token-probe
COPY image/sample /usr/local/share/probe/sample
USER sandbox
ARG VERSION
ARG REVISION
LABEL org.opencontainers.image.title="veoveo-qualify-openshell" \
      org.opencontainers.image.source="https://github.com/VeoveoAI/veoveo-qualify-openshell" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="Apache-2.0"
