# syntax=docker/dockerfile:1.7

# Stage 1: Builder
FROM rust:1.95-slim-trixie AS builder

WORKDIR /src

COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked && rm -rf src

COPY src/ src/
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target \
    touch src/main.rs && cargo build --release --locked && cp target/release/mapae /usr/local/bin/mapae

# Stage 2: Runtime - Distroless
FROM gcr.io/distroless/cc-debian13:nonroot

WORKDIR /app

COPY --from=builder /usr/local/bin/mapae /app/mapae

EXPOSE 2525 8000

ENTRYPOINT ["/app/mapae"]
