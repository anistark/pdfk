# Changelog

All notable changes to pdfk will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-03-16

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

## [0.1.1] - 2026-03-16

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

## [0.1.0] - 2026-03-13

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

[0.2.0]: https://github.com/anistark/pdfk/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/anistark/pdfk/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/anistark/pdfk/releases/tag/v0.1.0
