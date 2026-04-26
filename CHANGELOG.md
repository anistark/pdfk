# Changelog

All notable changes to pdfk will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased](https://github.com/anistark/pdfk/compare/v0.3.0...HEAD)

### Added
- **`--generate-password` flag on `lock`**: Generate a strong 24-character random password and copy it to the clipboard
  - Uses an unambiguous alphabet (no `0/O/I/l/1`) for share-friendliness
  - Cross-platform clipboard via `arboard` (macOS, Linux, Windows)
  - Prints the password once on stderr; falls back to a clear "save it manually" message if the clipboard is unavailable
  - Works with `--dry-run` (skips clipboard, still prints)
  - Mutually exclusive with `--password`, `--password-stdin`, `--password-env`, `--password-cmd`, `--user-password`, `--owner-password`
- **Homebrew support**: `brew install anistark/tools/pdfk` — available via the [anistark/tools](https://github.com/anistark/homebrew-tools) tap
  - Formula auto-updates on every release via GitHub Actions
- **`pdfk audit` command**: Scan PDFs and report encryption status
  - Human-readable table output with file, encryption, algorithm, revision, and permission columns
  - `--json` flag for machine-readable output
  - `--recursive` flag for nested folder traversal
  - Exit code 0 when all files are encrypted, non-zero if any are unencrypted or errored
- **`--password-env VAR`** flag on `lock`, `unlock`, `check` — read password from an environment variable
- **`--password-cmd "cmd"`** flag on `lock`, `unlock`, `check` — read password from a command's stdout
- **`--old-env` / `--new-env`** flags on `change-password` — read old/new passwords from environment variables
- **`--old-cmd` / `--new-cmd`** flags on `change-password` — read old/new passwords from command output
- Supports mixing sources (e.g. `--old-env VAR --new-cmd "echo pass"`)
- **Colored terminal output**: success messages in green, errors in red, warnings in yellow, verbose output dimmed. Respects the `NO_COLOR` environment variable.
- **`--quiet` / `-q` flag** (global): suppress all output except errors — useful for scripting and CI
- **`--verbose` / `-v` flag** (global): show step-by-step details (loading, encrypting, writing)
- **`--debug` flag** (global): show debug-level output — encryption dict fields, object counts, key lengths, permissions, crypt filters
- **Structured logging** via `log` + `env_logger`: `--verbose` maps to `info`, `--debug` maps to `debug`; warnings from dependencies (e.g. lopdf) route through `log::warn`
- 47 new integration tests (11 audit + 23 env/cmd + 13 quiet/verbose/debug)

### Changed
- All human-facing output now routes through a centralized output module (`src/utils/output.rs`) with consistent formatting and verbosity control

### Dependencies
- Added `colored` 3.0
- Added `log` 0.4
- Added `env_logger` 0.11



## [0.3.0](https://github.com/anistark/pdfk/compare/v0.2.0...v0.3.0) - 2026-03-20

### Added
- **Batch processing**: All commands now accept multiple files, folders, and glob patterns
  - Multiple file arguments: `pdfk unlock a.pdf b.pdf c.pdf`
  - Glob patterns: `pdfk unlock *.pdf`
  - Folder input: `pdfk lock folder/`
  - `--recursive` / `-R` flag for recursive folder processing
- **Progress bar** for batch operations using `indicatif`
- **Summary output** after batch operations: `X succeeded, Y failed, Z skipped`
- **`--dry-run` flag** on `lock`, `unlock`, and `change-password` — shows what would happen without modifying files
- **Static test fixtures** for legacy encryption formats:
  - RC4-128 (R3) encrypted PDF
  - AES-128 (R4) encrypted PDF
  - AES-256 R5 encrypted PDF
- 25 new integration tests (73 total: 18 unit + 55 integration)
  - 12 tests for static fixture info/check/unlock/JSON across all encryption formats
  - 13 tests for batch operations: multi-file, folder, recursive, dry-run, partial failure, output guard

### Changed
- CLI arguments changed from single `file` to `files` (one or more) for all commands
- `--output` is now restricted to single-file operations; errors with a helpful message when used with multiple files
- JSON output for `info` with multiple files returns a JSON array

### Fixed
- 7 clippy warnings: `clone_on_copy`, `too_many_arguments`, `collapsible_match`, `uninlined_format_args`

### Dependencies
- Added `glob` 0.3

## [0.2.0](https://github.com/anistark/pdfk/compare/v0.1.1...v0.2.0) - 2026-03-16

### Added
- **`pdfk info` command**: Display encryption details for any PDF without a password
  - Shows: encrypted status, algorithm, key length, revision, crypt filter, permission flags
  - Algorithm resolution from revision + crypt filter (AES-256, AES-128, RC4-128, RC4-40)
  - `--json` flag for machine-readable output (uses `serde`/`serde_json`)
  - Unencrypted files show `Encrypted: no` (or `{"encrypted": false}` in JSON)
- **Short flags** for common options across all commands
  - `-p` for `--password` (lock, unlock, check)
  - `-o` for `--output` (lock, unlock, change-password)
  - `-u` for `--user-password` (lock)
  - `-O` for `--owner-password` (lock)
- 6 new integration tests for info command (48 total: 18 unit + 30 integration)

### Fixed
- **Image corruption after lock→unlock roundtrip**: Encrypt stream content as-is instead of decompressing first, preserving `/Filter` entries (DCTDecode for JPEG, FlateDecode, etc.) per the PDF spec. Previously, `stream.decompress()` failed silently for JPEG streams but the filter was still removed, causing PDF viewers to misinterpret the image data.
- **Justfile paths with spaces**: Use `set positional-arguments` and `"$@"` so `just dev lock "path with spaces.pdf"` works correctly

### Changed
- README rewritten with use cases, secure input comparison table, encryption support matrix, and password manager integration examples

### Dependencies
- Added `serde` 1.0 with derive feature
- Added `serde_json` 1.0

## [0.1.1](https://github.com/anistark/pdfk/compare/v0.1.0...v0.1.1) - 2026-03-16

### Added
- **Interactive password prompts**: Bare `--password` (no value) triggers a hidden interactive prompt via `rpassword` — nothing in shell history or `ps` output
- **R3/R4 legacy decryption support**: Unlock and verify PDFs encrypted with older standards
  - MD5-based key derivation (Algorithm 2) for R3/R4
  - User and owner password verification for R2/R3/R4
  - RC4 cipher implementation for variable-length keys
  - AES-128-CBC decryption for R4 with AESV2 crypt filter
  - Per-object key derivation (Algorithm 1) for RC4 and AES-128
  - Crypt filter method parsing from encrypt dictionary
- Support for R3/R4 in `unlock`, `check`, and `change-password` commands
- Unit tests for RC4 roundtrip, password padding, legacy key derivation, AES-128 decrypt

### Fixed
- **Unlock producing empty/invalid PDFs**: Use `lopdf::Document::load_with_password()` for decryption instead of manual per-object decryption, which failed on encrypted PDFs with non-empty user passwords (doc.objects was empty). Unlocked PDFs now pass `qpdf --check` validation.
- Removed dead manual decryption code from writer.rs

## [0.1.0](https://github.com/anistark/pdfk/releases/tag/v0.1.0) - 2026-03-13

### Added
- Initial release of pdfk
- **`pdfk lock`** — Encrypt a PDF with AES-256 (R6, PDF 2.0)
  - `--password` to set both user & owner password
  - `--user-password` / `--owner-password` for separate passwords
  - `--password-stdin` for piped/scripted input
  - `--no-print`, `--no-copy`, `--no-edit` permission flags
  - `--output` / `--in-place` file output modes
- **`pdfk unlock`** — Decrypt a PDF by removing password protection
- **`pdfk change-password`** — Re-encrypt with a new password, preserving permissions
- **`pdfk check`** — Verify a password without modifying the file (exit code 0/1)
- AES-256 R6 encryption with proper key derivation (SHA-256/384/512 iterative hash)
- R5/R6 password verification (user + owner)
- PDF permission flags encoding/decoding per spec (Table 22/24)
- Secure password input from stdin for CI/CD pipelines
- Clear error messages for: wrong password, file not found, invalid PDF, not encrypted, already encrypted, unsupported revision
- 18 unit tests + 24 integration tests using `assert_cmd`
- Published to [crates.io](https://crates.io/crates/pdfk)
