all: vanity-address-generator

target/release/vanity-address-generator: src/main.rs
	cargo build --release --bin vanity-address-generator

vanity-address-generator: target/release/vanity-address-generator
	rm -f '$@'
	cp '$<' '$@'

clean:
	rm -f vanity-address-generator
	rm -rf target

distclean: clean

.PHONY: all clean distclean
