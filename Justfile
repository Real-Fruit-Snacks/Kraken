# Kraken C2 Framework - Build Commands

default:
    @just --list

# Check all crates compile
check:
    cargo check --workspace

# Run all tests
test:
    cargo test --workspace

# Run clippy lints
lint:
    cargo clippy --workspace -- -D warnings

# Format code
fmt:
    cargo fmt --all

# Generate protobuf code
proto:
    cargo build -p protocol

# Run database migrations
db-migrate:
    cargo run -p db --bin migrate

# Build and run server
server:
    cargo run -p server --release

# Build Windows implant
implant-windows-x64:
    cargo build --profile release-implant -p implant-core --target x86_64-pc-windows-gnu

# Build Linux implant
implant-linux-x64:
    cargo build --profile release-implant -p implant-core --target x86_64-unknown-linux-gnu

# Build operator TUI
operator:
    cargo build -p operator --release

# Run implant simulator
sim:
    cargo run -p implant-sim

# Module compilation targets

# Compile a specific module for all platforms
module-compile name:
    cargo build --profile release-implant -p {{name}} --target x86_64-pc-windows-gnu
    cargo build --profile release-implant -p {{name}} --target x86_64-unknown-linux-gnu

# Compile all modules
modules-compile-all:
    just module-compile mod-shell
    just module-compile mod-file

# List registered modules (requires running server)
modules-list:
    @echo "Module listing requires server connection"

# Full build
build:
    cargo build --workspace --release

# Clean build artifacts
clean:
    cargo clean

# Setup development environment
setup:
    rustup target add x86_64-pc-windows-gnu
    rustup target add x86_64-unknown-linux-gnu
    cargo install just

# Run code coverage with tarpaulin
coverage:
    cargo +nightly tarpaulin --engine Llvm --skip-clean

# Run code coverage for a specific crate
coverage-crate crate:
    cargo +nightly tarpaulin -p {{crate}} --engine Llvm --skip-clean

# Build fuzz targets
fuzz-build:
    cd fuzz && cargo +nightly fuzz build

# List available fuzz targets
fuzz-list:
    cd fuzz && cargo +nightly fuzz list

# Run a specific fuzz target (e.g., just fuzz-run protocol_frame)
fuzz-run target duration="60":
    cd fuzz && cargo +nightly fuzz run {{target}} -- -max_total_time={{duration}}
