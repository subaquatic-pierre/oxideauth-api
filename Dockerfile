FROM rust:slim

WORKDIR /app

COPY . /app/

RUN apt-get update && \
    apt-get install \
    pkg-config libssl-dev -y

RUN cargo install cargo-watch

CMD cargo watch -x "run --bin oxideauth-server" 