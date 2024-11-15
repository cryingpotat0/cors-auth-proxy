FROM rust:1.82.0-bullseye

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

EXPOSE 8080
CMD ["cargo", "run", "--release"]

