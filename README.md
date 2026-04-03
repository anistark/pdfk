# `pdfk` — PDF Kit

[![Crates.io Version](https://img.shields.io/crates/v/pdfk)](https://crates.io/crates/pdfk) [![Crates.io Downloads](https://img.shields.io/crates/d/pdfk)](https://crates.io/crates/pdfk) [![Crates.io Downloads (latest version)](https://img.shields.io/crates/dv/pdfk)](https://crates.io/crates/pdfk) [![Open Source](https://img.shields.io/badge/open-source-brightgreen)](https://github.com/anistark/pdfk) ![maintenance-status](https://img.shields.io/badge/maintenance-actively--developed-brightgreen.svg) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A modern CLI for PDF password management.
Fast, offline, and secure — your files never leave your machine.

## Why pdfk?

- **Fully offline** — zero network calls, no telemetry, no file uploads
- **AES-256 encryption** — uses the strongest PDF encryption standard (PDF 2.0, R6)
- **Single binary** — no runtime dependencies, no Python/Java/Node required
- **Script-friendly** — stdin password input, exit codes, `--quiet`/`--verbose` modes for CI/CD pipelines
- **Preserves fidelity** — images, fonts, and all PDF content survive lock/unlock roundtrips intact

## Install

### From crates.io

```sh
cargo install pdfk
```

### From source

```sh
git clone https://github.com/anistark/pdfk.git
cd pdfk
cargo install --path .
```

### Homebrew

```sh
brew install anistark/tools/pdfk
```

Or tap first, then install:

```sh
brew tap anistark/tools
brew install pdfk
```

## Commands

### `lock` — Encrypt a PDF

```sh
pdfk lock document.pdf --password mypassword
```

Creates `document_locked.pdf` with AES-256 encryption.

```sh
# Interactive password prompt (hidden input, nothing in shell history)
pdfk lock document.pdf --password

# Write to a specific file
pdfk lock document.pdf --password mypassword --output encrypted.pdf

# Modify in place (overwrites the original)
pdfk lock document.pdf --password mypassword --in-place

# Set separate user and owner passwords
pdfk lock document.pdf --user-password viewpass --owner-password adminpass

# Restrict permissions
pdfk lock document.pdf --password mypassword --no-print --no-copy --no-edit

# Read password from stdin (for scripts and CI)
echo "mypassword" | pdfk lock document.pdf --password-stdin
```

### `unlock` — Decrypt a PDF

```sh
pdfk unlock encrypted.pdf --password mypassword
```

Creates `encrypted_unlocked.pdf` with all encryption removed.

```sh
# Interactive prompt
pdfk unlock encrypted.pdf --password

# Write to a specific file
pdfk unlock encrypted.pdf --password mypassword --output decrypted.pdf

# Modify in place
pdfk unlock encrypted.pdf --password mypassword --in-place

# Password from stdin
echo "mypassword" | pdfk unlock encrypted.pdf --password-stdin
```

### `change-password` — Change the password

```sh
pdfk change-password encrypted.pdf --old oldpass --new newpass
```

```sh
# Interactive prompts for both passwords
pdfk change-password encrypted.pdf --old --new

# Passwords from stdin (one per line: old, then new)
printf "oldpass\nnewpass" | pdfk change-password encrypted.pdf --password-stdin
```

### `info` — Display encryption details

```sh
pdfk info document.pdf
```

```
File:         document.pdf
Encrypted:    yes
Algorithm:    AES-256
Key length:   256 bits
Revision:     R6
Crypt filter: AESV3
Permissions:
  Print: allowed
  Copy:  allowed
  Edit:  denied
```

```sh
# Machine-readable JSON output (for scripts and CI)
pdfk info document.pdf --json
```

```json
{
  "file": "document.pdf",
  "encrypted": true,
  "algorithm": "AES-256",
  "key_length": 256,
  "revision": "R6",
  "crypt_filter": "AESV3",
  "permissions": {
    "print": true,
    "copy": true,
    "edit": false
  }
}
```

### `audit` — Scan encryption status

```sh
pdfk audit folder/
```

```
FILE                       ENCRYPTED  ALGORITHM  REVISION  PRINT  COPY   EDIT
folder/contract.pdf           yes      AES-256      R6       ✓      ✓      ✓
folder/invoice.pdf            no          —         —        —      —      —
folder/report.pdf             yes      AES-128      R4       ✓      ✓      ✗

Audit: 2 encrypted, 1 unencrypted, 0 errors (out of 3 files)
```

Exits `0` if all files are encrypted, non-zero if any are unencrypted or errored.

```sh
# Recursive scan
pdfk audit folder/ --recursive

# JSON output for scripting
pdfk audit folder/ --json

# Use in CI to enforce encryption policy
if ! pdfk audit sensitive-docs/ --recursive 2>/dev/null; then
    echo "POLICY VIOLATION: unencrypted PDFs found" >&2
    exit 1
fi
```

### `check` — Verify a password

```sh
pdfk check encrypted.pdf --password mypassword
```

Exits `0` if the password is correct, non-zero otherwise. Useful in scripts:

```sh
if pdfk check file.pdf --password "$PASS" 2>/dev/null; then
    echo "Password is correct"
fi
```

## Use Cases

### Protect sensitive documents before sharing

Lock a contract, invoice, or report before emailing it or uploading to a shared drive:

```sh
pdfk lock contract.pdf --password clientSecret123 --output contract_protected.pdf
```

### Restrict what recipients can do

Allow viewing but prevent printing or copying text (e.g., exam papers, proprietary reports):

```sh
pdfk lock exam.pdf --password teacherpass --no-print --no-copy
```

### Batch-encrypt files in a CI/CD pipeline

Automate PDF protection in build pipelines, document generation workflows, or release processes:

```sh
for pdf in reports/*.pdf; do
    echo "$SECRET" | pdfk lock "$pdf" --password-stdin --in-place
done
```

### Remove encryption for downstream processing

Unlock PDFs to feed into other tools (OCR, merge, split, text extraction):

```sh
pdfk unlock scanned.pdf --password mypass --output scanned_open.pdf
# now pass to your OCR / merge / split tool
```

### Rotate passwords on archived documents

Change passwords periodically on encrypted archives without decrypting to disk:

```sh
printf "oldpass\nnewpass" | pdfk change-password archive.pdf --password-stdin --in-place
```

### Audit encryption compliance across a folder

Scan a directory to find unencrypted PDFs — useful for security audits and compliance checks:

```sh
pdfk audit sensitive-docs/ --recursive

# Enforce in CI: fail if any PDF is unencrypted
pdfk audit release-artifacts/ --recursive || exit 1

# JSON output for reporting
pdfk audit archive/ --json | jq '[.[] | select(.encrypted == false)] | length'
```

### Inspect encryption details before processing

Check what encryption a PDF uses and what permissions are set — no password needed:

```sh
pdfk info document.pdf

# Pipe JSON into jq for scripting
pdfk info document.pdf --json | jq '.permissions'
```

### Verify passwords in scripts before proceeding

Gate a workflow on password correctness without modifying the file:

```sh
if ! pdfk check file.pdf --password "$PASS" 2>/dev/null; then
    echo "Wrong password, aborting" >&2
    exit 1
fi
```

### Integrate with password managers

Pipe secrets directly from your vault — nothing touches the shell history:

```sh
# 1Password
op read "op://vault/pdf-password" | pdfk lock report.pdf --password-stdin

# Bitwarden
bw get password pdf-secret | pdfk unlock report.pdf --password-stdin

# macOS Keychain
security find-generic-password -s "pdf-pass" -w | pdfk lock doc.pdf --password-stdin
```

## Password Types

PDF supports two password levels:

| Password | Purpose |
|---|---|
| **User password** | Required to open and view the document |
| **Owner password** | Controls permissions (print, copy, edit) — viewer apps enforce these |

Use `--password` to set both to the same value, or set them independently:

```sh
# Anyone with "reader" can view; only "admin" can change permissions
pdfk lock file.pdf --user-password reader --owner-password admin
```

## Secure Password Input

Five ways to provide passwords, from most to least secure:

| Method | Shell history | Visible in `ps` | Works in scripts |
|---|---|---|---|
| `--password` (bare, no value) | ✗ | ✗ | ✗ (needs TTY) |
| `--password-stdin` | ✗ | ✗ | ✓ |
| `--password-env VAR` | ✗ | ✗ | ✓ |
| `--password-cmd "cmd"` | ✗ | ✗ | ✓ |
| `--password mypass` | ✓ | ✓ | ✓ |

For interactive use, prefer the bare `--password` flag. For automation, use `--password-stdin`.

## Output Control

All commands support global `--quiet` and `--verbose` flags:

```sh
# Suppress all output except errors (useful in scripts and CI)
pdfk lock document.pdf --password mypass --in-place --quiet

# Show step-by-step details
pdfk lock document.pdf --password mypass --verbose
# · Loading document.pdf
# · Encrypting with AES-256 R6
# · Writing to document_locked.pdf
# ✓ Encrypted document.pdf → document_locked.pdf
```

Output is colored by default (green for success, red for errors). Set the `NO_COLOR` environment variable to disable colors:

```sh
NO_COLOR=1 pdfk info document.pdf
```

## Encryption Support

pdfk encrypts using the strongest available standard and can decrypt all common PDF encryption formats:

| Revision | Cipher  | Key Size | PDF Spec                | Encrypt | Decrypt |
|----------|---------|----------|-------------------------|---------|---------|
| R6       | AES-256 | 256-bit  | PDF 2.0                 | ✅       | ✅       |
| R5       | AES-256 | 256-bit  | Adobe Extension Level 3 | —       | ✅       |
| R4       | AES-128 | 128-bit  | PDF 1.5–1.7             | —       | ✅       |
| R4       | RC4     | 128-bit  | PDF 1.5–1.7             | —       | ✅       |
| R3       | RC4     | 128-bit  | PDF 1.4                 | —       | ✅       |

All encryption is performed locally. No data is ever sent over the network.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for development setup, architecture, and guidelines.

## License

[MIT](./LICENSE)
