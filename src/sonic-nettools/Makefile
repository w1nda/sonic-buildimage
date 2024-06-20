include ../../rules/sonic-nettools.mk

$(addprefix $(DEST)/, $(SONIC_NETTOOLS)): $(DEST)/% :
ifeq ($(CROSS_BUILD_ENVIRON), y)
	cargo build --release --target=$(RUST_CROSS_COMPILE_TARGET)
else
	cargo build --release
endif
