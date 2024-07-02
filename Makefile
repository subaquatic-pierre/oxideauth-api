.PHONY: run watch clean

run:
	cargo run

build:
	cargo build --release
	cp ./target/release/oxideauth-server .
	chmod +x ./oxideauth-server

dev:
	cargo watch -x "run --bin oxideauth-server" 

fix:
	cargo fix --bin "raderbot"

test:
	cargo test

clean:
	cargo clean

rust-docs:
	cargo doc --no-deps

serve-rust-docs:
	python -m http.server --directory ./target/doc 3001

docs:
	scipts/build-docs.sh

serve-docs:
