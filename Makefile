RELEASE_BIN_TARGETS := \
	x86_64-unknown-linux-gnu \
	aarch64-unknown-linux-gnu \
	aarch64-apple-darwin

all: vanity-address-generator

do-release-bin: $(foreach target,$(RELEASE_BIN_TARGETS),target/$(target)/release/vanity-address-generator)
	for target in $(RELEASE_BIN_TARGETS); do \
		cp "target/$$target/release/vanity-address-generator" "vanity-address-generator-$$target" || exit 1; \
	done

target/%/release/vanity-address-generator: src/main.rs
	if [ -e Dockerfile.$* ]; then \
		docker build --build-arg 'TARGET=$*' --platform '$(shell echo $* | cut -f 1 -d - | sed 's@x86_64@linux/amd64@;s@aarch64@linux/arm64@')' --tag 'vanity-address-generator-$*' --file 'Dockerfile.$*' '$(shell pwd -P)' &&  \
		mkdir -p target/$*/release && \
		docker run --rm --volume "$(shell pwd -P)/target/$*/release:/output" 'vanity-address-generator-$*' cp /data/vanity-address-generator-$* /output/vanity-address-generator; \
	else \
		cargo build --target $* --release --bin vanity-address-generator; \
	fi

target/release/vanity-address-generator: src/main.rs
	cargo build --release --bin vanity-address-generator

vanity-address-generator: target/release/vanity-address-generator
	rm -f '$@'
	cp '$<' '$@'

vanity-address-generator-%: target/%/release/vanity-address-generator
	rm -f '$@'
	cp '$<' '$@'

clean:
	rm -f vanity-address-generator
	rm -f vanity-address-generator-*
	rm -rf target

distclean: clean

.PHONY: all do-release-bin clean distclean
