.PHONY: all build install clean

BUILD_DIR := target
INSTALL_DIR := ~/dotfiles/scripts/pwdgen

all: build install

build: native win

native:
	cargo build --release

win:
	cross build --release --target=x86_64-pc-windows-gnu

install: build
	mkdir -p $(INSTALL_DIR)
	cp $(BUILD_DIR)/release/pwdgen $(INSTALL_DIR)/pwdgen
	cp $(BUILD_DIR)/x86_64-pc-windows-gnu/release/pwdgen.exe $(INSTALL_DIR)/pwdgen.exe

clean:
	cargo clean

sqlx_prepare:
	DATABASE_URL="sqlite://passman.db" cargo sqlx prepare
