# Solo45 Core: built natively on x86 and ARM by GitHub Actions (.github/workflows/image.yml).
FROM rust:1.100-slim-trixie AS build
# the capnp compiler builds the IPC client for Bitcoin Core's mining interface
RUN apt-get update && apt-get install -y --no-install-recommends capnproto && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY web ./web
# the unit tests (hashing, job building, the status page's same-origin rule) must pass before the binary is kept
RUN cargo test --release --locked && cargo build --release --locked && strip target/release/solo45-core

FROM debian:trixie-slim
COPY --from=build /src/target/release/solo45-core /usr/local/bin/solo45-core
# MALLOC_ARENA_MAX: fewer glibc memory pools, so freed template memory is reused (Core also trims every minute)
ENV MALLOC_ARENA_MAX=2
USER 1000:1000
EXPOSE 3346 3386 8346
ENTRYPOINT ["solo45-core"]
CMD ["serve"]
