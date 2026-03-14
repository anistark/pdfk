# `pdfk` - PDF Kit

[![Crates.io Version](https://img.shields.io/crates/v/pdfk)](https://crates.io/crates/pdfk) [![Crates.io Downloads](https://img.shields.io/crates/d/pdfk)](https://crates.io/crates/pdfk) [![Crates.io Downloads (latest version)](https://img.shields.io/crates/dv/pdfk)](https://crates.io/crates/pdfk) [![Open Source](https://img.shields.io/badge/open-source-brightgreen)](https://github.com/anistark/pdfk) ![maintenance-status](https://img.shields.io/badge/maintenance-actively--developed-brightgreen.svg) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Modern PDF CLI tool. 
Fast, offline, secure.

## Install

### From source

```sh
cargo install pdfk
```

### Homebrew (coming soon)

```sh
brew install pdfk
```

## Usage

### Lock — Encrypt a PDF

```sh
pdfk lock document.pdf --password mypassword
```

This creates `document_locked.pdf` with AES-256 encryption.

**Options:**

```sh
# Write to a specific file
pdfk lock document.pdf --password mypassword --output encrypted.pdf

# Modify in place
pdfk lock document.pdf --password mypassword --in-place

# Set separate user and owner passwords
pdfk lock document.pdf --user-password viewpass --owner-password adminpass

# Restrict permissions
pdfk lock document.pdf --password mypassword --no-print --no-copy --no-edit

# Read password from stdin (avoids shell history)
echo "mypassword" | pdfk lock document.pdf --password-stdin
```

### Unlock — Decrypt a PDF

```sh
pdfk unlock encrypted.pdf --password mypassword
```

Creates `encrypted_unlocked.pdf` with encryption removed.

```sh
# Write to a specific file
pdfk unlock encrypted.pdf --password mypassword --output decrypted.pdf

# Modify in place
pdfk unlock encrypted.pdf --password mypassword --in-place

# Password from stdin
echo "mypassword" | pdfk unlock encrypted.pdf --password-stdin
```

### Change Password

```sh
pdfk change-password encrypted.pdf --old oldpass --new newpass
```

```sh
# Passwords from stdin (one per line: old, then new)
printf "oldpass\nnewpass" | pdfk change-password encrypted.pdf --password-stdin
```

### Check — Verify a Password

```sh
pdfk check encrypted.pdf --password mypassword
```

Exits with code `0` if the password is correct, non-zero otherwise. Useful in scripts:

```sh
if pdfk check file.pdf --password "$PASS" 2>/dev/null; then
    echo "Password is correct"
fi
```

## Password Types

PDF supports two password types:

- **User password** — required to open and view the document
- **Owner password** — controls what actions are allowed (print, copy, edit)

Use `--password` to set both to the same value, or set them independently:

```sh
pdfk lock file.pdf --user-password viewonly --owner-password fullaccess
```

## Secure Password Input

Avoid exposing passwords in shell history:

```sh
# Pipe from stdin
echo "$PDF_PASS" | pdfk unlock file.pdf --password-stdin

# Pipe from a password manager
op read "op://vault/pdf-password" | pdfk unlock file.pdf --password-stdin
```

## Encryption

pdfk uses **AES-256 (Revision 6)** encryption by default — the strongest encryption defined in the PDF 2.0 specification.

Decryption supports:
- AES-256 R6 (PDF 2.0)
- AES-256 R5 (Adobe Extension Level 3)

Legacy encryption formats (RC4, AES-128) are planned for future versions.

### [MIT](./LICENSE) License
