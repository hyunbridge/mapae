# Stage 1: Builder
FROM rust:1.95-slim-trixie AS builder

WORKDIR /src

COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs
RUN cargo build --release --locked && rm -rf src

COPY src/ src/
RUN touch src/main.rs && cargo build --release --locked

# Stage 2: Runtime - Distroless
FROM gcr.io/distroless/cc-debian13:nonroot

WORKDIR /app

COPY --from=builder /src/target/release/mapae /app/mapae

EXPOSE 2525 8000

ENTRYPOINT ["/app/mapae"]
