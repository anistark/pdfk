mod common;

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn pdfk() -> Command {
    Command::cargo_bin("pdfk").unwrap()
}

fn sample_pdf() -> String {
    common::ensure_sample_pdf();
    "tests/fixtures/sample.pdf".to_string()
}

/// Copy the sample PDF to a temp dir and return (temp_dir, path_to_copy).
fn copy_sample_to_temp() -> (TempDir, String) {
    let tmp = TempDir::new().unwrap();
    let dest = tmp.path().join("sample.pdf");
    fs::copy(sample_pdf(), &dest).unwrap();
    (tmp, dest.to_string_lossy().to_string())
}

// ==================== Lock tests ====================

#[test]
fn test_lock_creates_encrypted_file() {
    let tmp = TempDir::new().unwrap();
    let output = tmp.path().join("encrypted.pdf");

    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password",
            "testpass",
            "--output",
            output.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Encrypted"));

    assert!(output.exists());
    assert!(output.metadata().unwrap().len() > 0);
}

#[test]
fn test_lock_default_output_adds_suffix() {
    let (tmp, pdf_path) = copy_sample_to_temp();
    let expected_output = tmp.path().join("sample_locked.pdf");

    pdfk()
        .args(&["lock", &pdf_path, "--password", "testpass"])
        .assert()
        .success();

    assert!(expected_output.exists());
}

#[test]
fn test_lock_in_place() {
    let (_tmp, pdf_path) = copy_sample_to_temp();
    let original_size = fs::metadata(&pdf_path).unwrap().len();

    pdfk()
        .args(&["lock", &pdf_path, "--password", "testpass", "--in-place"])
        .assert()
        .success();

    // File should still exist but be different size (encrypted)
    let new_size = fs::metadata(&pdf_path).unwrap().len();
    assert_ne!(original_size, new_size);
}

#[test]
fn test_lock_with_separate_passwords() {
    let tmp = TempDir::new().unwrap();
    let output = tmp.path().join("encrypted.pdf");

    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--user-password",
            "userpass",
            "--owner-password",
            "ownerpass",
            "--output",
            output.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Verify user password works
    pdfk()
        .args(&["check", output.to_str().unwrap(), "--password", "userpass"])
        .assert()
        .success();

    // Verify owner password works
    pdfk()
        .args(&["check", output.to_str().unwrap(), "--password", "ownerpass"])
        .assert()
        .success();
}

#[test]
fn test_lock_with_permission_flags() {
    let tmp = TempDir::new().unwrap();
    let output = tmp.path().join("encrypted.pdf");

    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password",
            "testpass",
            "--no-print",
            "--no-copy",
            "--output",
            output.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(output.exists());
}

#[test]
fn test_lock_password_stdin() {
    let tmp = TempDir::new().unwrap();
    let output = tmp.path().join("encrypted.pdf");

    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password-stdin",
            "--output",
            output.to_str().unwrap(),
        ])
        .write_stdin("stdinpass\n")
        .assert()
        .success();

    // Verify the stdin password works
    pdfk()
        .args(&["check", output.to_str().unwrap(), "--password", "stdinpass"])
        .assert()
        .success();
}

// ==================== Unlock tests ====================

#[test]
fn test_unlock_decrypts_file() {
    let tmp = TempDir::new().unwrap();
    let encrypted = tmp.path().join("encrypted.pdf");
    let decrypted = tmp.path().join("decrypted.pdf");

    // First encrypt
    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password",
            "testpass",
            "--output",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Then decrypt
    pdfk()
        .args(&[
            "unlock",
            encrypted.to_str().unwrap(),
            "--password",
            "testpass",
            "--output",
            decrypted.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Decrypted"));

    assert!(decrypted.exists());
}

#[test]
fn test_unlock_wrong_password() {
    let tmp = TempDir::new().unwrap();
    let encrypted = tmp.path().join("encrypted.pdf");

    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password",
            "testpass",
            "--output",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    pdfk()
        .args(&[
            "unlock",
            encrypted.to_str().unwrap(),
            "--password",
            "wrongpass",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Wrong password"));
}

#[test]
fn test_unlock_not_encrypted() {
    pdfk()
        .args(&["unlock", &sample_pdf(), "--password", "testpass"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not encrypted"));
}

#[test]
fn test_unlock_password_stdin() {
    let tmp = TempDir::new().unwrap();
    let encrypted = tmp.path().join("encrypted.pdf");
    let decrypted = tmp.path().join("decrypted.pdf");

    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password",
            "testpass",
            "--output",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    pdfk()
        .args(&[
            "unlock",
            encrypted.to_str().unwrap(),
            "--password-stdin",
            "--output",
            decrypted.to_str().unwrap(),
        ])
        .write_stdin("testpass\n")
        .assert()
        .success();
}

// ==================== Check tests ====================

#[test]
fn test_check_correct_password() {
    let tmp = TempDir::new().unwrap();
    let encrypted = tmp.path().join("encrypted.pdf");

    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password",
            "testpass",
            "--output",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    pdfk()
        .args(&[
            "check",
            encrypted.to_str().unwrap(),
            "--password",
            "testpass",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Password is correct"));
}

#[test]
fn test_check_wrong_password() {
    let tmp = TempDir::new().unwrap();
    let encrypted = tmp.path().join("encrypted.pdf");

    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password",
            "testpass",
            "--output",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    pdfk()
        .args(&[
            "check",
            encrypted.to_str().unwrap(),
            "--password",
            "wrongpass",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Wrong password"));
}

#[test]
fn test_check_not_encrypted() {
    pdfk()
        .args(&["check", &sample_pdf(), "--password", "testpass"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not encrypted"));
}

// ==================== Change-password tests ====================

#[test]
fn test_change_password() {
    let tmp = TempDir::new().unwrap();
    let encrypted = tmp.path().join("encrypted.pdf");
    let changed = tmp.path().join("changed.pdf");

    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password",
            "oldpass",
            "--output",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    pdfk()
        .args(&[
            "change-password",
            encrypted.to_str().unwrap(),
            "--old",
            "oldpass",
            "--new",
            "newpass",
            "--output",
            changed.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Password changed"));

    // Old password should not work
    pdfk()
        .args(&["check", changed.to_str().unwrap(), "--password", "oldpass"])
        .assert()
        .failure();

    // New password should work
    pdfk()
        .args(&["check", changed.to_str().unwrap(), "--password", "newpass"])
        .assert()
        .success();
}

#[test]
fn test_change_password_stdin() {
    let tmp = TempDir::new().unwrap();
    let encrypted = tmp.path().join("encrypted.pdf");
    let changed = tmp.path().join("changed.pdf");

    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password",
            "oldpass",
            "--output",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    pdfk()
        .args(&[
            "change-password",
            encrypted.to_str().unwrap(),
            "--password-stdin",
            "--output",
            changed.to_str().unwrap(),
        ])
        .write_stdin("oldpass\nnewpass\n")
        .assert()
        .success();

    pdfk()
        .args(&["check", changed.to_str().unwrap(), "--password", "newpass"])
        .assert()
        .success();
}

#[test]
fn test_change_password_wrong_old() {
    let tmp = TempDir::new().unwrap();
    let encrypted = tmp.path().join("encrypted.pdf");

    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password",
            "realpass",
            "--output",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    pdfk()
        .args(&[
            "change-password",
            encrypted.to_str().unwrap(),
            "--old",
            "wrongold",
            "--new",
            "newpass",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Wrong password"));
}

// ==================== Error path tests ====================

#[test]
fn test_file_not_found() {
    pdfk()
        .args(&["lock", "nonexistent.pdf", "--password", "test"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("File not found"));
}

#[test]
fn test_invalid_pdf_file() {
    let tmp = TempDir::new().unwrap();
    let bad_file = tmp.path().join("bad.pdf");
    fs::write(&bad_file, "not a pdf file").unwrap();

    pdfk()
        .args(&["lock", bad_file.to_str().unwrap(), "--password", "test"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Failed to load PDF"));
}

#[test]
fn test_already_encrypted() {
    let tmp = TempDir::new().unwrap();
    let encrypted = tmp.path().join("encrypted.pdf");

    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password",
            "testpass",
            "--output",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    pdfk()
        .args(&[
            "lock",
            encrypted.to_str().unwrap(),
            "--password",
            "testpass",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already encrypted"));
}

#[test]
fn test_no_password_provided() {
    pdfk().args(&["lock", &sample_pdf()]).assert().failure();
}

// ==================== Full roundtrip test ====================

#[test]
fn test_full_roundtrip_lock_check_unlock() {
    let tmp = TempDir::new().unwrap();
    let encrypted = tmp.path().join("encrypted.pdf");
    let decrypted = tmp.path().join("decrypted.pdf");
    let password = "complex_p@ssw0rd!";

    // Lock
    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password",
            password,
            "--output",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Check with correct password
    pdfk()
        .args(&["check", encrypted.to_str().unwrap(), "--password", password])
        .assert()
        .success();

    // Check with wrong password
    pdfk()
        .args(&["check", encrypted.to_str().unwrap(), "--password", "wrong"])
        .assert()
        .failure();

    // Unlock
    pdfk()
        .args(&[
            "unlock",
            encrypted.to_str().unwrap(),
            "--password",
            password,
            "--output",
            decrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Decrypted file should not be encrypted
    pdfk()
        .args(&[
            "check",
            decrypted.to_str().unwrap(),
            "--password",
            "anything",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not encrypted"));
}

// ==================== Help and version tests ====================

#[test]
fn test_help() {
    pdfk()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "managing PDF passwords and encryption",
        ));
}

#[test]
fn test_version() {
    pdfk()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("pdfk 0.1.1"));
}

#[test]
fn test_subcommand_help() {
    pdfk()
        .args(&["lock", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Encrypt a PDF"));
}
