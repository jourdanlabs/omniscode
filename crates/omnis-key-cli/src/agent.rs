use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(crate) fn launch_exact_sibling(_invoked_as: &OsStr) -> i32 {
    let current = match std::env::current_exe() {
        Ok(current) => current,
        Err(_) => {
            eprintln!("AGENT_COMPATIBILITY_UNAVAILABLE");
            return 4;
        }
    };
    let sibling = sibling_jcode_path(&current);
    if !is_regular_nonsymlink(&sibling) {
        eprintln!("AGENT_COMPATIBILITY_UNAVAILABLE");
        return 4;
    }

    let mut command = Command::new(&sibling);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let error = command.exec();
        eprintln!("AGENT_COMPATIBILITY_UNAVAILABLE: {error}");
        4
    }
    #[cfg(not(unix))]
    {
        match command.status() {
            Ok(status) => status.code().unwrap_or(3),
            Err(_) => {
                eprintln!("AGENT_COMPATIBILITY_UNAVAILABLE");
                4
            }
        }
    }
}

fn sibling_jcode_path(current: &Path) -> PathBuf {
    let filename = if cfg!(windows) { "jcode.exe" } else { "jcode" };
    current
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(filename)
}

fn is_regular_nonsymlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
}

#[cfg(test)]
mod tests {
    use super::sibling_jcode_path;
    use std::path::Path;

    #[test]
    fn agent_lane_uses_only_the_exact_sibling() {
        let executable = if cfg!(windows) {
            Path::new(r"C:\omnis\omnis-key.exe")
        } else {
            Path::new("/opt/omnis/bin/omnis-key")
        };
        let expected = if cfg!(windows) {
            Path::new(r"C:\omnis\jcode.exe")
        } else {
            Path::new("/opt/omnis/bin/jcode")
        };
        assert_eq!(sibling_jcode_path(executable), expected);
    }
}
