use anyhow::{bail, Result};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Resolve a list of input paths into individual PDF files.
/// Handles:
/// - Regular files (passed through)
/// - Directories (collects *.pdf files, optionally recursive)
/// - Glob patterns (expanded)
pub fn resolve_files(inputs: &[PathBuf], recursive: bool) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    for input in inputs {
        let input_str = input.to_string_lossy();

        // Check if it looks like a glob pattern
        if input_str.contains('*') || input_str.contains('?') || input_str.contains('[') {
            let matches: Vec<_> = glob::glob(&input_str)
                .map_err(|e| anyhow::anyhow!("Invalid glob pattern '{input_str}': {e}"))?
                .filter_map(|r| r.ok())
                .filter(|p| p.is_file() && has_pdf_extension(p))
                .collect();
            if matches.is_empty() {
                eprintln!("Warning: no PDF files matched pattern '{input_str}'");
            }
            files.extend(matches);
        } else if input.is_dir() {
            let dir_files = collect_pdfs_from_dir(input, recursive)?;
            if dir_files.is_empty() {
                eprintln!("Warning: no PDF files found in {}", input.display());
            }
            files.extend(dir_files);
        } else if input.is_file() {
            files.push(input.clone());
        } else {
            bail!("File not found: {}", input.display());
        }
    }

    if files.is_empty() {
        bail!("No PDF files found");
    }

    // Sort for consistent ordering and deduplicate
    files.sort();
    files.dedup();

    Ok(files)
}

/// Collect all .pdf files from a directory, optionally recursively.
fn collect_pdfs_from_dir(dir: &Path, recursive: bool) -> Result<Vec<PathBuf>> {
    let mut pdfs = Vec::new();

    let entries = std::fs::read_dir(dir)
        .map_err(|e| anyhow::anyhow!("Cannot read directory {}: {}", dir.display(), e))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() && has_pdf_extension(&path) {
            pdfs.push(path);
        } else if path.is_dir() && recursive {
            pdfs.extend(collect_pdfs_from_dir(&path, recursive)?);
        }
    }

    Ok(pdfs)
}

/// Check if a path has a .pdf extension (case-insensitive).
fn has_pdf_extension(path: &Path) -> bool {
    path.extension()
        .map(|ext| ext.to_string_lossy().to_lowercase() == "pdf")
        .unwrap_or(false)
}

/// Summary of a batch operation.
#[derive(Default)]
pub struct BatchSummary {
    pub succeeded: usize,
    pub failed: usize,
    pub skipped: usize,
}

impl BatchSummary {
    pub fn print(&self) {
        let total = self.succeeded + self.failed + self.skipped;
        eprintln!();
        eprintln!(
            "Summary: {} succeeded, {} failed, {} skipped (out of {} files)",
            self.succeeded, self.failed, self.skipped, total
        );
    }

    pub fn has_failures(&self) -> bool {
        self.failed > 0
    }
}

/// Create a progress bar for batch operations. Returns None for single-file operations.
pub fn create_progress_bar(total: usize) -> Option<ProgressBar> {
    if total <= 1 {
        return None;
    }

    let pb = ProgressBar::new(total as u64);
    pb.set_style(
        ProgressStyle::with_template("{spinner:.green} [{bar:30.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("━━─"),
    );
    pb.enable_steady_tick(Duration::from_millis(100));
    Some(pb)
}
