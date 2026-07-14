# Reproduction environment for the offline, deterministic results of the paper.
# Rust (simulator, golden vectors, unit tests) + Python 3 stdlib (fee analysis,
# gas report). No Foundry/Node/network: the live-chain measurements are excluded
# and their committed outputs are reproduced from here.
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl build-essential python3 ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
# Pinned Rust toolchain (any recent stable reproduces the deterministic vectors).
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.82.0
ENV PATH="/root/.cargo/bin:${PATH}"
