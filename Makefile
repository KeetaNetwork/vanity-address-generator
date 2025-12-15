all: vanity-address-generator

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all           - Builds the project"
	@echo "  help          - Shows this help"
	@echo "  test          - Runs the test suite"
	@echo "  clean         - Removes build artifacts"
	@echo "  distclean     - Removes all build artifacts and dependencies"

target/release/vanity-address-generator: src/main.rs
	cargo build --release --bin vanity-address-generator

vanity-address-generator: target/release/vanity-address-generator
	rm -f '$@'
	cp '$<' '$@'

test:
	cargo test

clean:
	rm -f vanity-address-generator
	rm -rf target

distclean: clean

.PHONY: all help test clean distclean
