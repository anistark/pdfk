set positional-arguments := true

# Get version from Cargo.toml

version := `grep -m 1 'version = ' Cargo.toml | cut -d '"' -f 2`

# Repository information

repo := `if git remote -v >/dev/null 2>&1; then git remote get-url origin | sed -E 's/.*github.com[:/]([^/]+)\/([^/.]+).*/\1\/\2/'; else echo "anistark/pdfk"; fi`

default:
    @just --list
    @echo "\nCurrent version: {{ version }}"

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

# Test publish to crates.io (dry run)
publish-test:
    cargo publish --dry-run

# Create git tag for current version
tag-release:
    git tag v{{ version }}
    @echo "Created tag v{{ version }}"
    echo "Pushing tag v{{ version }} to remote..."
    git push origin "v{{ version }}"

# Create GitHub release with release binary
gh-release TITLE="":
    #!/usr/bin/env bash
    set -euo pipefail

    if ! command -v gh &> /dev/null; then
        echo "Error: GitHub CLI not installed. Install from https://cli.github.com/"
        exit 1
    fi

    if ! gh auth status &> /dev/null; then
        echo "Error: Not logged in to GitHub. Run 'gh auth login'"
        exit 1
    fi

    # Create tag if it doesn't exist
    if ! git rev-parse "v{{ version }}" >/dev/null 2>&1; then
        git tag -a "v{{ version }}" -m "Release v{{ version }}"
        echo "✓ Created tag v{{ version }}"
    else
        echo "✓ Tag v{{ version }} already exists"
    fi

    # Push tag
    git push origin "v{{ version }}"

    TITLE="{{ TITLE }}"
    if [ -z "$TITLE" ]; then
        DEFAULT="pdfk v{{ version }}"
        read -rp "Release title [$DEFAULT]: " TITLE
        TITLE="${TITLE:-$DEFAULT}"
    fi

    # Build release binary
    echo "Building release binary..."
    cargo build --release

    # Create GitHub release
    gh release create "v{{ version }}" \
        --title "$TITLE" \
        --generate-notes \
        "./target/release/pdfk"

    echo "✓ GitHub release created: $TITLE"
    echo "  https://github.com/{{ repo }}/releases/tag/v{{ version }}"

# Publish to crates.io + create GitHub release
publish TITLE="": build-release
    #!/usr/bin/env bash
    set -euo pipefail

    echo "Publishing pdfk v{{ version }}..."
    echo ""

    # Publish to crates.io
    echo "→ Publishing to crates.io..."
    cargo publish
    echo "✓ Published to crates.io"
    echo ""

    # Create GitHub release
    echo "→ Creating GitHub release..."
    just gh-release "{{ TITLE }}"
    echo ""

    echo "✓ Released v{{ version }} to crates.io and GitHub"

# Clean build artifacts
clean:
    cargo clean
