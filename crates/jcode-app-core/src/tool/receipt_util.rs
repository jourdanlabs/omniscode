//! Shared helpers for action-receipt wiring.

use std::path::{Path, PathBuf};

/// Prefer a repo-relative path for receipt subjects (plaintext, no secrets).
pub fn repo_relative(cwd: &Path, absolute: &Path, display: &str) -> String {
    if let Ok(rel) = absolute.strip_prefix(cwd) {
        return rel.to_string_lossy().replace('\\', "/");
    }
    display.trim_start_matches("./").replace('\\', "/")
}

pub fn cwd_from_ctx(working_dir: &Option<PathBuf>) -> PathBuf {
    working_dir
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}
