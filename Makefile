.PHONY: all server operator implant-linux implant-windows clean dev test install-toolchains dist implants

RELEASE_FLAGS = --release

all: server operator implant-linux

# Server binary
server:
	cargo build $(RELEASE_FLAGS) -p server

# Operator TUI
operator:
	cargo build $(RELEASE_FLAGS) -p operator

# Linux implant (musl - static)
implant-linux:
	cargo build $(RELEASE_FLAGS) --profile release-implant --target x86_64-unknown-linux-musl -p implant-core

# Windows implant (cross-compile)
implant-windows:
	cargo build $(RELEASE_FLAGS) --profile release-implant --target x86_64-pc-windows-gnu -p implant-core

# All implants
implants: implant-linux implant-windows

# Development build
dev:
	cargo build

# Run tests
test:
	cargo test --workspace

# Clean
clean:
	cargo clean

# Install cross-compilation toolchains (Linux)
install-toolchains:
	rustup target add x86_64-pc-windows-gnu
	rustup target add x86_64-unknown-linux-musl
	@echo "Also install system packages:"
	@echo "  Ubuntu/Debian: sudo apt-get install mingw-w64 musl-tools"
	@echo "  Fedora/RHEL:   sudo dnf install mingw-w64-gcc musl-libc-devel"
	@echo "  Arch:          sudo pacman -S mingw-w64-gcc musl"

# Build distribution package
dist: server operator implants
	mkdir -p dist
	cp target/release/server dist/
	cp target/release/operator dist/
	cp target/x86_64-unknown-linux-musl/release/implant-core dist/implant-linux
	cp target/x86_64-pc-windows-gnu/release/implant-core.exe dist/implant-windows.exe
	@echo "Distribution files in dist/"
