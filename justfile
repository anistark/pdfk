set positional-arguments

default:
    @just --list

# Format code
format:
    cargo fmt

# Check formatting without modifying
format-check:
    cargo fmt -- --check

# Run clippy lints
lint:
    cargo clippy -- -D warnings

# Type-check without building
check:
    cargo check

# Build debug binary
build:
    cargo build

# Build release binary
build-release:
    cargo build --release

# Run all tests
test:
    cargo test

# Run with arguments (e.g. just run lock file.pdf --password test)
run *ARGS:
    cargo run -- "$@"

# Build and run in one step
dev *ARGS:
    cargo run -- "$@"

# Test Publish to crates.io (dry run)
publish-test:
    cargo publish --dry-run

# Publish to crates.io
publish:
    cargo publish

# Clean build artifacts
clean:
    cargo clean
