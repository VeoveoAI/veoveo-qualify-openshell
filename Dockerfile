# syntax=docker/dockerfile:1.27@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# The probe image: the probe binary, a Rust toolchain the sandbox user owns, the sample
# crate and the Rerun 0.38.1 Python SDK for the Redap scenarios.

FROM rust:1.99.0-trixie@sha256:6ff07edce8775d0f64be7aba9197229407301bddf2054d62c27b541a6238a181 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs rust-toolchain.toml ./
COPY proto proto
COPY src src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin probe && cp target/release/probe /probe

FROM rust:1.99.0-trixie@sha256:6ff07edce8775d0f64be7aba9197229407301bddf2054d62c27b541a6238a181
RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates curl git procps python3 python3-venv \
    && rm -rf /var/lib/apt/lists/* /var/log/apt /var/log/dpkg.log \
    && python3 -m venv /usr/local/rerun \
    && /usr/local/rerun/bin/pip install --no-cache-dir 'rerun-sdk[catalog]==0.38.1' \
    && useradd --create-home --uid 1000 --shell /bin/bash sandbox \
    && chown -R sandbox:sandbox /usr/local/rustup /usr/local/cargo \
    && printf 'export RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo\nexport PATH=/usr/local/cargo/bin:$PATH\n' > /etc/profile.d/rust.sh
COPY --from=build /probe /usr/local/bin/probe
COPY image /usr/local/share/probe
USER sandbox
RUN /usr/local/rerun/bin/rerun analytics disable >/dev/null
ARG VERSION
ARG REVISION
LABEL org.opencontainers.image.title="veoveo-qualify-openshell" \
      org.opencontainers.image.source="https://github.com/VeoveoAI/veoveo-qualify-openshell" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="Apache-2.0"
