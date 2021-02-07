FROM rust:1.49.0 AS builder
WORKDIR /usr/src/
RUN mkdir /usr/src/certifika
COPY src /usr/src/certifika/src
COPY Cargo.toml /usr/src/certifika/
WORKDIR /usr/src/certifika
RUN cargo install --path .

FROM alpine:3.13
COPY --from=builder /usr/local/cargo/bin/certifika /usr/local/bin/certifika
ENTRYPOINT ["/usr/local/bin/certifika"]

