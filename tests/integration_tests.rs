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

#[test]
fn test_lock_generate_password_outputs_password_and_locks_file() {
    let tmp = TempDir::new().unwrap();
    let output = tmp.path().join("encrypted.pdf");

    let assert = pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--generate-password",
            "--output",
            output.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Generated password:"));

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    let password = stderr
        .lines()
        .find_map(|l| l.strip_prefix("Generated password: "))
        .expect("expected a Generated password line")
        .trim()
        .to_string();

    assert_eq!(password.len(), 24);
    assert!(password.chars().all(|c| c.is_ascii_alphanumeric()));
    assert!(output.exists());

    pdfk()
        .args(&["check", output.to_str().unwrap(), "--password", &password])
        .assert()
        .success();
}

#[test]
fn test_lock_generate_password_dry_run_skips_clipboard() {
    let tmp = TempDir::new().unwrap();
    let output = tmp.path().join("encrypted.pdf");

    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--generate-password",
            "--dry-run",
            "--output",
            output.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Generated password:"))
        .stderr(predicate::str::contains("dry-run: clipboard not updated"));

    assert!(!output.exists());
}

#[test]
fn test_lock_generate_password_conflicts_with_password() {
    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--generate-password",
            "--password",
            "manual",
        ])
        .assert()
        .failure();
}

#[test]
fn test_lock_generate_password_conflicts_with_user_password() {
    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--generate-password",
            "--user-password",
            "manual",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--generate-password"));
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

// ==================== Info tests ====================

#[test]
fn test_info_unencrypted() {
    pdfk()
        .args(&["info", &sample_pdf()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Encrypted: no"));
}

#[test]
fn test_info_encrypted() {
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
        .args(&["info", encrypted.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Encrypted:    yes"))
        .stdout(predicate::str::contains("Algorithm:    AES-256"))
        .stdout(predicate::str::contains("Key length:   256 bits"))
        .stdout(predicate::str::contains("Revision:     R6"))
        .stdout(predicate::str::contains("Crypt filter: AESV3"))
        .stdout(predicate::str::contains("Print: allowed"))
        .stdout(predicate::str::contains("Copy:  allowed"))
        .stdout(predicate::str::contains("Edit:  allowed"));
}

#[test]
fn test_info_encrypted_with_permissions() {
    let tmp = TempDir::new().unwrap();
    let encrypted = tmp.path().join("encrypted.pdf");

    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password",
            "testpass",
            "--no-print",
            "--no-copy",
            "--output",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    pdfk()
        .args(&["info", encrypted.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Print: denied"))
        .stdout(predicate::str::contains("Copy:  denied"))
        .stdout(predicate::str::contains("Edit:  allowed"));
}

#[test]
fn test_info_json_unencrypted() {
    let output = pdfk()
        .args(&["info", &sample_pdf(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
    assert_eq!(json["encrypted"], false);
    assert!(json.get("algorithm").is_none());
    assert!(json.get("permissions").is_none());
}

#[test]
fn test_info_json_encrypted() {
    let tmp = TempDir::new().unwrap();
    let encrypted = tmp.path().join("encrypted.pdf");

    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password",
            "testpass",
            "--no-edit",
            "--output",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    let output = pdfk()
        .args(&["info", encrypted.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
    assert_eq!(json["encrypted"], true);
    assert_eq!(json["algorithm"], "AES-256");
    assert_eq!(json["key_length"], 256);
    assert_eq!(json["revision"], "R6");
    assert_eq!(json["crypt_filter"], "AESV3");
    assert_eq!(json["permissions"]["print"], true);
    assert_eq!(json["permissions"]["copy"], true);
    assert_eq!(json["permissions"]["edit"], false);
}

#[test]
fn test_info_file_not_found() {
    pdfk()
        .args(&["info", "nonexistent.pdf"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("File not found"));
}

// ==================== Static fixture tests (RC4-128, AES-128, AES-256 R5) ====================

#[test]
fn test_info_rc4_128_fixture() {
    pdfk()
        .args(&["info", "tests/fixtures/sample_rc4_128.pdf"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Encrypted:    yes"))
        .stdout(predicate::str::contains("Algorithm:    RC4-128"))
        .stdout(predicate::str::contains("Key length:   128 bits"))
        .stdout(predicate::str::contains("Revision:     R3"));
}

#[test]
fn test_info_aes_128_fixture() {
    pdfk()
        .args(&["info", "tests/fixtures/sample_aes_128.pdf"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Encrypted:    yes"))
        .stdout(predicate::str::contains("Algorithm:    AES-128"))
        .stdout(predicate::str::contains("Key length:   128 bits"))
        .stdout(predicate::str::contains("Revision:     R4"))
        .stdout(predicate::str::contains("Crypt filter: AESV2"));
}

#[test]
fn test_info_aes_256_r5_fixture() {
    pdfk()
        .args(&["info", "tests/fixtures/sample_aes_256_r5.pdf"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Encrypted:    yes"))
        .stdout(predicate::str::contains("Algorithm:    AES-256"))
        .stdout(predicate::str::contains("Key length:   256 bits"))
        .stdout(predicate::str::contains("Revision:     R5"))
        .stdout(predicate::str::contains("Crypt filter: AESV3"));
}

#[test]
fn test_check_rc4_128_fixture() {
    pdfk()
        .args(&[
            "check",
            "tests/fixtures/sample_rc4_128.pdf",
            "--password",
            "testpass",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Password is correct"));
}

#[test]
fn test_check_aes_128_fixture() {
    pdfk()
        .args(&[
            "check",
            "tests/fixtures/sample_aes_128.pdf",
            "--password",
            "testpass",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Password is correct"));
}

#[test]
fn test_check_aes_256_r5_fixture() {
    pdfk()
        .args(&[
            "check",
            "tests/fixtures/sample_aes_256_r5.pdf",
            "--password",
            "testpass",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Password is correct"));
}

#[test]
fn test_unlock_rc4_128_fixture() {
    let tmp = TempDir::new().unwrap();
    let decrypted = tmp.path().join("decrypted.pdf");

    pdfk()
        .args(&[
            "unlock",
            "tests/fixtures/sample_rc4_128.pdf",
            "--password",
            "testpass",
            "--output",
            decrypted.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Decrypted"));

    // Verify decrypted file is not encrypted
    pdfk()
        .args(&["info", decrypted.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Encrypted: no"));
}

#[test]
fn test_unlock_aes_128_fixture() {
    let tmp = TempDir::new().unwrap();
    let decrypted = tmp.path().join("decrypted.pdf");

    pdfk()
        .args(&[
            "unlock",
            "tests/fixtures/sample_aes_128.pdf",
            "--password",
            "testpass",
            "--output",
            decrypted.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Decrypted"));

    pdfk()
        .args(&["info", decrypted.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Encrypted: no"));
}

#[test]
fn test_unlock_aes_256_r5_fixture() {
    let tmp = TempDir::new().unwrap();
    let decrypted = tmp.path().join("decrypted.pdf");

    pdfk()
        .args(&[
            "unlock",
            "tests/fixtures/sample_aes_256_r5.pdf",
            "--password",
            "testpass",
            "--output",
            decrypted.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Decrypted"));

    pdfk()
        .args(&["info", decrypted.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Encrypted: no"));
}

#[test]
fn test_info_json_rc4_128_fixture() {
    let output = pdfk()
        .args(&["info", "tests/fixtures/sample_rc4_128.pdf", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
    assert_eq!(json["encrypted"], true);
    assert_eq!(json["algorithm"], "RC4-128");
    assert_eq!(json["key_length"], 128);
    assert_eq!(json["revision"], "R3");
}

#[test]
fn test_info_json_aes_128_fixture() {
    let output = pdfk()
        .args(&["info", "tests/fixtures/sample_aes_128.pdf", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
    assert_eq!(json["encrypted"], true);
    assert_eq!(json["algorithm"], "AES-128");
    assert_eq!(json["key_length"], 128);
    assert_eq!(json["revision"], "R4");
    assert_eq!(json["crypt_filter"], "AESV2");
}

#[test]
fn test_info_json_aes_256_r5_fixture() {
    let output = pdfk()
        .args(&["info", "tests/fixtures/sample_aes_256_r5.pdf", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
    assert_eq!(json["encrypted"], true);
    assert_eq!(json["algorithm"], "AES-256");
    assert_eq!(json["key_length"], 256);
    assert_eq!(json["revision"], "R5");
    assert_eq!(json["crypt_filter"], "AESV3");
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

// ==================== Batch / Multi-file tests ====================

#[test]
fn test_lock_multiple_files() {
    let tmp = TempDir::new().unwrap();
    let pdf1 = tmp.path().join("a.pdf");
    let pdf2 = tmp.path().join("b.pdf");
    let pdf3 = tmp.path().join("c.pdf");
    fs::copy(sample_pdf(), &pdf1).unwrap();
    fs::copy(sample_pdf(), &pdf2).unwrap();
    fs::copy(sample_pdf(), &pdf3).unwrap();

    pdfk()
        .args(&[
            "lock",
            pdf1.to_str().unwrap(),
            pdf2.to_str().unwrap(),
            pdf3.to_str().unwrap(),
            "--password",
            "testpass",
            "--in-place",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("3 succeeded, 0 failed, 0 skipped"));

    // All three should now be encrypted
    for pdf in [&pdf1, &pdf2, &pdf3] {
        pdfk()
            .args(&["check", pdf.to_str().unwrap(), "--password", "testpass"])
            .assert()
            .success();
    }
}

#[test]
fn test_unlock_multiple_files() {
    let tmp = TempDir::new().unwrap();
    let pdf1 = tmp.path().join("a.pdf");
    let pdf2 = tmp.path().join("b.pdf");
    fs::copy(sample_pdf(), &pdf1).unwrap();
    fs::copy(sample_pdf(), &pdf2).unwrap();

    // Lock both first
    pdfk()
        .args(&[
            "lock",
            pdf1.to_str().unwrap(),
            pdf2.to_str().unwrap(),
            "--password",
            "testpass",
            "--in-place",
        ])
        .assert()
        .success();

    // Unlock both
    pdfk()
        .args(&[
            "unlock",
            pdf1.to_str().unwrap(),
            pdf2.to_str().unwrap(),
            "--password",
            "testpass",
            "--in-place",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("2 succeeded, 0 failed, 0 skipped"));

    // Both should now be unencrypted
    for pdf in [&pdf1, &pdf2] {
        pdfk()
            .args(&["info", pdf.to_str().unwrap()])
            .assert()
            .success()
            .stdout(predicate::str::contains("Encrypted: no"));
    }
}

#[test]
fn test_check_multiple_files() {
    let tmp = TempDir::new().unwrap();
    let pdf1 = tmp.path().join("a.pdf");
    let pdf2 = tmp.path().join("b.pdf");
    fs::copy(sample_pdf(), &pdf1).unwrap();
    fs::copy(sample_pdf(), &pdf2).unwrap();

    pdfk()
        .args(&[
            "lock",
            pdf1.to_str().unwrap(),
            pdf2.to_str().unwrap(),
            "--password",
            "testpass",
            "--in-place",
        ])
        .assert()
        .success();

    pdfk()
        .args(&[
            "check",
            pdf1.to_str().unwrap(),
            pdf2.to_str().unwrap(),
            "--password",
            "testpass",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("2 succeeded, 0 failed, 0 skipped"));
}

#[test]
fn test_info_multiple_files() {
    pdfk()
        .args(&[
            "info",
            "tests/fixtures/sample.pdf",
            "tests/fixtures/sample_rc4_128.pdf",
            "tests/fixtures/sample_aes_128.pdf",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Encrypted: no"))
        .stdout(predicate::str::contains("Algorithm:    RC4-128"))
        .stdout(predicate::str::contains("Algorithm:    AES-128"))
        .stderr(predicate::str::contains("3 succeeded, 0 failed, 0 skipped"));
}

#[test]
fn test_lock_folder() {
    let tmp = TempDir::new().unwrap();
    let subdir = tmp.path().join("pdfs");
    fs::create_dir(&subdir).unwrap();
    fs::copy(sample_pdf(), subdir.join("a.pdf")).unwrap();
    fs::copy(sample_pdf(), subdir.join("b.pdf")).unwrap();

    pdfk()
        .args(&[
            "lock",
            subdir.to_str().unwrap(),
            "--password",
            "testpass",
            "--in-place",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("2 succeeded, 0 failed, 0 skipped"));

    // Both should be encrypted
    pdfk()
        .args(&[
            "check",
            subdir.join("a.pdf").to_str().unwrap(),
            "--password",
            "testpass",
        ])
        .assert()
        .success();
    pdfk()
        .args(&[
            "check",
            subdir.join("b.pdf").to_str().unwrap(),
            "--password",
            "testpass",
        ])
        .assert()
        .success();
}

#[test]
fn test_lock_folder_recursive() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("docs");
    let sub = root.join("sub");
    fs::create_dir_all(&sub).unwrap();
    fs::copy(sample_pdf(), root.join("top.pdf")).unwrap();
    fs::copy(sample_pdf(), sub.join("nested.pdf")).unwrap();

    // Without --recursive, only top-level files are processed
    pdfk()
        .args(&[
            "lock",
            root.to_str().unwrap(),
            "--password",
            "testpass",
            "--in-place",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Encrypted"));

    // Verify the nested file was NOT processed
    pdfk()
        .args(&["info", sub.join("nested.pdf").to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Encrypted: no"));

    // Reset the top file
    fs::copy(sample_pdf(), root.join("top.pdf")).unwrap();

    // With --recursive, both are processed
    pdfk()
        .args(&[
            "lock",
            root.to_str().unwrap(),
            "--password",
            "testpass",
            "--in-place",
            "--recursive",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("2 succeeded, 0 failed, 0 skipped"));

    pdfk()
        .args(&[
            "check",
            sub.join("nested.pdf").to_str().unwrap(),
            "--password",
            "testpass",
        ])
        .assert()
        .success();
}

#[test]
fn test_dry_run_lock() {
    let (_tmp, pdf_path) = copy_sample_to_temp();

    pdfk()
        .args(&["lock", &pdf_path, "--password", "testpass", "--dry-run"])
        .assert()
        .success()
        .stderr(predicate::str::contains("[dry-run] Would encrypt"));

    // File should NOT be encrypted
    pdfk()
        .args(&["info", &pdf_path])
        .assert()
        .success()
        .stdout(predicate::str::contains("Encrypted: no"));
}

#[test]
fn test_dry_run_unlock() {
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
            "testpass",
            "--dry-run",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("[dry-run] Would decrypt"));

    // File should still be encrypted
    pdfk()
        .args(&["info", encrypted.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Encrypted:    yes"));
}

#[test]
fn test_batch_partial_failure() {
    let tmp = TempDir::new().unwrap();
    let encrypted = tmp.path().join("encrypted.pdf");
    let unencrypted = tmp.path().join("plain.pdf");

    // Create an encrypted file
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

    // Copy an unencrypted file
    fs::copy(sample_pdf(), &unencrypted).unwrap();

    // Try to unlock both — the unencrypted one should fail
    pdfk()
        .args(&[
            "unlock",
            encrypted.to_str().unwrap(),
            unencrypted.to_str().unwrap(),
            "--password",
            "testpass",
            "--in-place",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("1 succeeded, 1 failed, 0 skipped"));
}

#[test]
fn test_output_not_allowed_with_multiple_files() {
    let tmp = TempDir::new().unwrap();
    let pdf1 = tmp.path().join("a.pdf");
    let pdf2 = tmp.path().join("b.pdf");
    fs::copy(sample_pdf(), &pdf1).unwrap();
    fs::copy(sample_pdf(), &pdf2).unwrap();

    pdfk()
        .args(&[
            "lock",
            pdf1.to_str().unwrap(),
            pdf2.to_str().unwrap(),
            "--password",
            "testpass",
            "--output",
            "/tmp/out.pdf",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--output cannot be used with multiple files",
        ));
}

#[test]
fn test_info_folder() {
    // Info on the fixtures directory
    pdfk()
        .args(&["info", "tests/fixtures"])
        .assert()
        .success()
        .stderr(predicate::str::contains("succeeded"));
}

#[test]
fn test_change_password_multiple_files() {
    let tmp = TempDir::new().unwrap();
    let pdf1 = tmp.path().join("a.pdf");
    let pdf2 = tmp.path().join("b.pdf");
    fs::copy(sample_pdf(), &pdf1).unwrap();
    fs::copy(sample_pdf(), &pdf2).unwrap();

    // Lock both
    pdfk()
        .args(&[
            "lock",
            pdf1.to_str().unwrap(),
            pdf2.to_str().unwrap(),
            "--password",
            "oldpass",
            "--in-place",
        ])
        .assert()
        .success();

    // Change password on both
    pdfk()
        .args(&[
            "change-password",
            pdf1.to_str().unwrap(),
            pdf2.to_str().unwrap(),
            "--old",
            "oldpass",
            "--new",
            "newpass",
            "--in-place",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("2 succeeded, 0 failed, 0 skipped"));

    // Verify new password works on both
    for pdf in [&pdf1, &pdf2] {
        pdfk()
            .args(&["check", pdf.to_str().unwrap(), "--password", "newpass"])
            .assert()
            .success();
    }
}

#[test]
fn test_dry_run_change_password() {
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
            "change-password",
            encrypted.to_str().unwrap(),
            "--old",
            "testpass",
            "--new",
            "newpass",
            "--dry-run",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("[dry-run] Would change password"));

    // Password should still be the old one
    pdfk()
        .args(&[
            "check",
            encrypted.to_str().unwrap(),
            "--password",
            "testpass",
        ])
        .assert()
        .success();
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
        .stdout(predicate::str::contains("pdfk 0.4.0"));
}

#[test]
fn test_subcommand_help() {
    pdfk()
        .args(&["lock", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Encrypt a PDF"));
}

// ==================== Password env/cmd tests ====================

#[test]
fn test_lock_password_env() {
    let tmp = TempDir::new().unwrap();
    let output = tmp.path().join("encrypted.pdf");

    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password-env",
            "PDFK_TEST_PASS",
            "--output",
            output.to_str().unwrap(),
        ])
        .env("PDFK_TEST_PASS", "envpass123")
        .assert()
        .success()
        .stderr(predicate::str::contains("Encrypted"));

    pdfk()
        .args(&[
            "check",
            output.to_str().unwrap(),
            "--password",
            "envpass123",
        ])
        .assert()
        .success();
}

#[test]
fn test_unlock_password_env() {
    let tmp = TempDir::new().unwrap();
    let encrypted = tmp.path().join("encrypted.pdf");
    let decrypted = tmp.path().join("decrypted.pdf");

    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password",
            "envpass",
            "--output",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    pdfk()
        .args(&[
            "unlock",
            encrypted.to_str().unwrap(),
            "--password-env",
            "PDFK_TEST_PASS2",
            "--output",
            decrypted.to_str().unwrap(),
        ])
        .env("PDFK_TEST_PASS2", "envpass")
        .assert()
        .success()
        .stderr(predicate::str::contains("Decrypted"));
}

#[test]
fn test_check_password_env() {
    let tmp = TempDir::new().unwrap();
    let encrypted = tmp.path().join("encrypted.pdf");

    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password",
            "checkenv",
            "--output",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    pdfk()
        .args(&[
            "check",
            encrypted.to_str().unwrap(),
            "--password-env",
            "PDFK_CHECK_PASS",
        ])
        .env("PDFK_CHECK_PASS", "checkenv")
        .assert()
        .success()
        .stderr(predicate::str::contains("Password is correct"));
}

#[test]
fn test_password_env_not_set() {
    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password-env",
            "PDFK_NONEXISTENT_VAR_12345",
        ])
        .env_remove("PDFK_NONEXISTENT_VAR_12345")
        .assert()
        .failure()
        .stderr(predicate::str::contains("is not set"));
}

#[test]
fn test_password_env_empty() {
    pdfk()
        .args(&["lock", &sample_pdf(), "--password-env", "PDFK_EMPTY_VAR"])
        .env("PDFK_EMPTY_VAR", "")
        .assert()
        .failure()
        .stderr(predicate::str::contains("is empty"));
}

#[test]
fn test_lock_password_cmd() {
    let tmp = TempDir::new().unwrap();
    let output = tmp.path().join("encrypted.pdf");

    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password-cmd",
            "echo cmdpass456",
            "--output",
            output.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Encrypted"));

    pdfk()
        .args(&[
            "check",
            output.to_str().unwrap(),
            "--password",
            "cmdpass456",
        ])
        .assert()
        .success();
}

#[test]
fn test_unlock_password_cmd() {
    let tmp = TempDir::new().unwrap();
    let encrypted = tmp.path().join("encrypted.pdf");
    let decrypted = tmp.path().join("decrypted.pdf");

    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password",
            "cmdunlock",
            "--output",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    pdfk()
        .args(&[
            "unlock",
            encrypted.to_str().unwrap(),
            "--password-cmd",
            "echo cmdunlock",
            "--output",
            decrypted.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Decrypted"));
}

#[test]
fn test_check_password_cmd() {
    let tmp = TempDir::new().unwrap();
    let encrypted = tmp.path().join("encrypted.pdf");

    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password",
            "cmdcheck",
            "--output",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    pdfk()
        .args(&[
            "check",
            encrypted.to_str().unwrap(),
            "--password-cmd",
            "echo cmdcheck",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Password is correct"));
}

#[test]
fn test_password_cmd_failure() {
    pdfk()
        .args(&["lock", &sample_pdf(), "--password-cmd", "false"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Command exited with"));
}

#[test]
fn test_change_password_env() {
    let tmp = TempDir::new().unwrap();
    let encrypted = tmp.path().join("encrypted.pdf");
    let changed = tmp.path().join("changed.pdf");

    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password",
            "oldenvpass",
            "--output",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    pdfk()
        .args(&[
            "change-password",
            encrypted.to_str().unwrap(),
            "--old-env",
            "PDFK_OLD",
            "--new-env",
            "PDFK_NEW",
            "--output",
            changed.to_str().unwrap(),
        ])
        .env("PDFK_OLD", "oldenvpass")
        .env("PDFK_NEW", "newenvpass")
        .assert()
        .success()
        .stderr(predicate::str::contains("Password changed"));

    pdfk()
        .args(&[
            "check",
            changed.to_str().unwrap(),
            "--password",
            "newenvpass",
        ])
        .assert()
        .success();
}

#[test]
fn test_change_password_cmd() {
    let tmp = TempDir::new().unwrap();
    let encrypted = tmp.path().join("encrypted.pdf");
    let changed = tmp.path().join("changed.pdf");

    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password",
            "oldcmdpass",
            "--output",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    pdfk()
        .args(&[
            "change-password",
            encrypted.to_str().unwrap(),
            "--old-cmd",
            "echo oldcmdpass",
            "--new-cmd",
            "echo newcmdpass",
            "--output",
            changed.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Password changed"));

    pdfk()
        .args(&[
            "check",
            changed.to_str().unwrap(),
            "--password",
            "newcmdpass",
        ])
        .assert()
        .success();
}

#[test]
fn test_change_password_mixed_env_cmd() {
    let tmp = TempDir::new().unwrap();
    let encrypted = tmp.path().join("encrypted.pdf");
    let changed = tmp.path().join("changed.pdf");

    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password",
            "mixold",
            "--output",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    pdfk()
        .args(&[
            "change-password",
            encrypted.to_str().unwrap(),
            "--old-env",
            "PDFK_MIX_OLD",
            "--new-cmd",
            "echo mixnew",
            "--output",
            changed.to_str().unwrap(),
        ])
        .env("PDFK_MIX_OLD", "mixold")
        .assert()
        .success()
        .stderr(predicate::str::contains("Password changed"));

    pdfk()
        .args(&["check", changed.to_str().unwrap(), "--password", "mixnew"])
        .assert()
        .success();
}

#[test]
fn test_lock_help_shows_env_cmd_flags() {
    pdfk()
        .args(&["lock", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--password-env"))
        .stdout(predicate::str::contains("--password-cmd"));
}

#[test]
fn test_check_help_shows_env_cmd_flags() {
    pdfk()
        .args(&["check", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--password-env"))
        .stdout(predicate::str::contains("--password-cmd"));
}

#[test]
fn test_change_password_help_shows_env_cmd_flags() {
    pdfk()
        .args(&["change-password", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--old-env"))
        .stdout(predicate::str::contains("--new-env"))
        .stdout(predicate::str::contains("--old-cmd"))
        .stdout(predicate::str::contains("--new-cmd"));
}

#[test]
fn test_unlock_help_shows_env_cmd_flags() {
    pdfk()
        .args(&["unlock", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--password-env"))
        .stdout(predicate::str::contains("--password-cmd"));
}

#[test]
fn test_password_cmd_empty_output() {
    pdfk()
        .args(&["lock", &sample_pdf(), "--password-cmd", "printf ''"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("empty"));
}

#[test]
fn test_check_wrong_password_via_env() {
    let tmp = TempDir::new().unwrap();
    let encrypted = tmp.path().join("encrypted.pdf");

    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password",
            "rightpass",
            "--output",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    pdfk()
        .args(&[
            "check",
            encrypted.to_str().unwrap(),
            "--password-env",
            "PDFK_WRONG",
        ])
        .env("PDFK_WRONG", "wrongpass")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Wrong password"));
}

#[test]
fn test_check_wrong_password_via_cmd() {
    let tmp = TempDir::new().unwrap();
    let encrypted = tmp.path().join("encrypted.pdf");

    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password",
            "rightpass",
            "--output",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    pdfk()
        .args(&[
            "check",
            encrypted.to_str().unwrap(),
            "--password-cmd",
            "echo wrongpass",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Wrong password"));
}

#[test]
fn test_password_env_and_password_mutually_exclusive() {
    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password",
            "test",
            "--password-env",
            "VAR",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn test_password_cmd_and_password_mutually_exclusive() {
    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password",
            "test",
            "--password-cmd",
            "echo test",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn test_password_env_and_cmd_mutually_exclusive() {
    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password-env",
            "VAR",
            "--password-cmd",
            "echo test",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn test_change_password_mixed_cmd_env() {
    let tmp = TempDir::new().unwrap();
    let encrypted = tmp.path().join("encrypted.pdf");
    let changed = tmp.path().join("changed.pdf");

    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password",
            "cmdold",
            "--output",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    pdfk()
        .args(&[
            "change-password",
            encrypted.to_str().unwrap(),
            "--old-cmd",
            "echo cmdold",
            "--new-env",
            "PDFK_MIX_NEW",
            "--output",
            changed.to_str().unwrap(),
        ])
        .env("PDFK_MIX_NEW", "envnew")
        .assert()
        .success()
        .stderr(predicate::str::contains("Password changed"));

    pdfk()
        .args(&["check", changed.to_str().unwrap(), "--password", "envnew"])
        .assert()
        .success();
}

// ==================== Audit tests ====================

#[test]
fn test_audit_unencrypted_file() {
    pdfk()
        .args(&["audit", &sample_pdf()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no"))
        .stderr(predicate::str::contains("1 unencrypted"));
}

#[test]
fn test_audit_encrypted_file() {
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
        .args(&["audit", encrypted.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("yes"))
        .stderr(predicate::str::contains("1 encrypted"));
}

#[test]
fn test_audit_mixed_files() {
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
        .args(&["audit", &sample_pdf(), encrypted.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("1 encrypted"))
        .stderr(predicate::str::contains("1 unencrypted"));
}

#[test]
fn test_audit_folder() {
    pdfk()
        .args(&["audit", "tests/fixtures/"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("ENCRYPTED"))
        .stderr(predicate::str::contains("encrypted"))
        .stderr(predicate::str::contains("unencrypted"));
}

#[test]
fn test_audit_recursive() {
    let tmp = TempDir::new().unwrap();
    let subdir = tmp.path().join("sub");
    fs::create_dir(&subdir).unwrap();
    fs::copy(sample_pdf(), subdir.join("a.pdf")).unwrap();

    pdfk()
        .args(&["audit", tmp.path().to_str().unwrap(), "--recursive"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("1 unencrypted"));
}

#[test]
fn test_audit_json_output() {
    pdfk()
        .args(&["audit", &sample_pdf(), "--json"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("\"encrypted\": false"));
}

#[test]
fn test_audit_json_encrypted() {
    let tmp = TempDir::new().unwrap();
    let encrypted = tmp.path().join("enc.pdf");

    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password",
            "pass",
            "--output",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    let output = pdfk()
        .args(&["audit", encrypted.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let entry = &json[0];
    assert_eq!(entry["encrypted"], true);
    assert_eq!(entry["algorithm"], "AES-256");
    assert_eq!(entry["revision"], "R6");
    assert!(entry["permissions"]["print"].as_bool().unwrap());
}

#[test]
fn test_audit_file_not_found() {
    pdfk()
        .args(&["audit", "nonexistent.pdf"])
        .assert()
        .failure();
}

#[test]
fn test_audit_exit_code_zero_all_encrypted() {
    pdfk()
        .args(&["audit", "tests/fixtures/sample_locked.pdf"])
        .assert()
        .success();
}

#[test]
fn test_audit_permissions_in_table() {
    pdfk()
        .args(&["audit", "tests/fixtures/sample_locked.pdf"])
        .assert()
        .success()
        .stderr(predicate::str::contains("✓"));
}

#[test]
fn test_audit_with_restricted_permissions() {
    let tmp = TempDir::new().unwrap();
    let encrypted = tmp.path().join("restricted.pdf");

    pdfk()
        .args(&[
            "lock",
            &sample_pdf(),
            "--password",
            "pass",
            "--no-print",
            "--no-copy",
            "--output",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    let output = pdfk()
        .args(&["audit", encrypted.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let perms = &json[0]["permissions"];
    assert_eq!(perms["print"], false);
    assert_eq!(perms["copy"], false);
    assert_eq!(perms["edit"], true);
}
