include ../../rules/sonic-nettools.mk

$(addprefix $(DEST)/, $(SONIC_NETTOOLS)): $(DEST)/% :
	mkdir -p bin
ifeq ($(CROSS_BUILD_ENVIRON), y)
	cargo build --release --target=$(RUST_CROSS_COMPILE_TARGET)
	mv target/$(RUST_CROSS_COMPILE_TARGET)/release/wol bin/
else
	cargo build --release
	mv target/release/wol bin/
endif

clean:
	rm -rf target
	rm -rf bin