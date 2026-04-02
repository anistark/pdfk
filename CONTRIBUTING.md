# Contributing to pdfk

Thanks for your interest in contributing! This document covers everything you need to get set up and start working on pdfk.

## Prerequisites

- **Rust 1.85+** — Install via [rustup](https://rustup.rs/)
- **just** — Task runner. Install via `cargo install just` or `brew install just`


## Getting Started

```sh
git clone https://github.com/anistark/pdfk.git
cd pdfk
just build
just test
```

## Available Commands

Run `just` to see all available tasks:

```sh
just format        # Format code with rustfmt
just format-check  # Check formatting without modifying
just lint          # Run clippy lints (fails on warnings)
just check         # Type-check without building
just build         # Build debug binary
just build-release # Build release binary
just test          # Run all tests
just run <args>    # Run the CLI (e.g. just run lock file.pdf --password test)
just dev <args>    # Build and run in one step
just publish-test  # Dry-run publish to crates.io
just tag-release   # Create git tag for current version
just gh-release    # Create GitHub release with binary
just publish       # Publish to crates.io + GitHub release
just clean         # Clean build artifacts
```

## How It Works

The core flow for each command is:

1. **CLI parsing** — `clap` parses args into the `Command` enum (`src/cli/mod.rs`)
2. **Dispatch** — `commands/mod.rs` routes to the appropriate command handler
3. **PDF I/O** — `pdf/reader.rs` loads and parses encryption dicts; `pdf/writer.rs` handles encryption of objects and saving
4. **Crypto** — `core/encryption.rs` implements R3/R4/R5/R6 key derivation, password verification, and AES-256 stream encryption per the PDF spec
5. **Permissions** — `core/permissions.rs` encodes/decodes the P value permission bits (print, copy, edit)

## Testing

Tests are split into two categories:

### Unit tests

Located alongside the source code in `#[cfg(test)]` modules. Run with:

```sh
just test
```

Key unit tests cover:
- AES-256 and AES-128 encrypt/decrypt roundtrips
- R6 and R5 key derivation and password verification
- R3/R4 legacy password verification (user + owner)
- RC4 cipher roundtrips
- Per-object key derivation (RC4, AES-128)
- Password padding
- Permission flag encoding/decoding

### Integration tests

Located in `tests/integration_tests.rs`. These test the actual CLI binary using `assert_cmd`. Test fixtures are auto-generated via `tests/common/mod.rs` using `lopdf`.

Tests cover all five commands (lock, unlock, change-password, check, info), error paths (wrong password, missing file, already encrypted, etc.), stdin password input, JSON output validation, and full lock→check→unlock roundtrips.

## Adding a New Command

1. Add the subcommand variant to `Command` in `src/cli/mod.rs`
2. Create `src/commands/your_command.rs` with a public `execute` function
3. Register it in `src/commands/mod.rs` (add `pub mod` and match arm in `dispatch`)
4. Add integration tests in `tests/integration_tests.rs`

## Output Guidelines

All human-facing output must go through the centralized output module (`src/utils/output.rs`). Do not use raw `println!` or `eprintln!` in command handlers.

| Function | Stream | Quiet | Use for |
|---|---|---|---|
| `print_success(msg)` | stderr | suppressed | `✓` completion messages |
| `print_error(msg)` | stderr | always shows | `✗` error messages |
| `print_warning(msg)` | stderr | suppressed | `⚠` warnings |
| `print_verbose(msg)` | stderr | verbose only | `·` step-by-step details |
| `print_status(msg)` | stderr | suppressed | status lines (dry-run, tables, summaries) |
| `write_stdout(msg)` | stdout | never suppressed | primary data output (info display, JSON) |

Commands may use `colored::Colorize` for formatting strings passed to these helpers.

## Code Style

- **Minimal comments.** Use docstrings on public APIs, `TODO`/`FIXME` for known issues, and brief notes only where logic is non-obvious. Don't restate what the code does.
- **Run `just lint`** before submitting. Clippy must pass with zero warnings.
- **Run `just format`** to auto-format.

## Dependencies

All dependencies should be pinned to their latest **stable** version. Avoid release candidates. When adding a new crate, verify the version with `cargo search <crate>`.

## Submitting Changes

1. Fork the repo and create a feature branch
2. Make your changes
3. Ensure `just lint` and `just test` pass
4. Write a clear, concise commit message
5. Open a PR against `main`

Keep PRs focused — one feature or fix per PR.

## Changelog

Update [CHANGELOG.md](./CHANGELOG.md) when adding features or fixing bugs. Follow the [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format with `Added`, `Fixed`, `Changed`, `Dependencies` categories.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](./LICENSE).
