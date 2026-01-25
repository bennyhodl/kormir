FROM rust:1.75 as builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY kormir-server ./kormir-server
COPY kormir-wasm ./kormir-wasm
RUN cargo build --release -p kormir-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libpq5 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/kormir-server .
ENV KORMIR_PORT=8082
EXPOSE 8082
CMD ["./kormir-server"]
