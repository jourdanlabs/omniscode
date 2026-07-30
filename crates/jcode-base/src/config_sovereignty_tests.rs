use super::*;

#[test]
fn inherited_launch_hotkey_bake_is_disabled_before_config_or_session_writes() {
    fn snapshot_files(root: &Path, current: &Path, files: &mut Vec<(std::path::PathBuf, Vec<u8>)>) {
        let mut entries = std::fs::read_dir(current)
            .expect("read fixture directory")
            .collect::<std::io::Result<Vec<_>>>()
            .expect("collect fixture directory");
        entries.sort_by_key(std::fs::DirEntry::path);
        for entry in entries {
            let path = entry.path();
            if entry.file_type().expect("fixture file type").is_dir() {
                snapshot_files(root, &path, files);
            } else {
                files.push((
                    path.strip_prefix(root)
                        .expect("fixture file below root")
                        .to_path_buf(),
                    std::fs::read(path).expect("read fixture file"),
                ));
            }
        }
    }

    let _guard = crate::storage::lock_test_env();
    let previous_home = std::env::var_os("JCODE_HOME");
    let temp = tempfile::tempdir().expect("create hostile config home");
    crate::env::set_var("JCODE_HOME", temp.path());

    let config_path = temp.path().join("config.toml");
    std::fs::write(&config_path, b"hostile-sentinel = true\n").expect("write config sentinel");
    let sessions = temp.path().join("sessions");
    std::fs::create_dir_all(&sessions).expect("create hostile sessions");
    for index in 0..50 {
        std::fs::write(sessions.join(format!("session-{index}.json")), b"{}")
            .expect("write hostile session");
    }
    let mut before = Vec::new();
    snapshot_files(temp.path(), temp.path(), &mut before);

    assert!(!Config::bake_launch_hotkeys_once());

    let mut after = Vec::new();
    snapshot_files(temp.path(), temp.path(), &mut after);
    assert_eq!(after, before, "launch-hotkey bake mutated its fixture");
    restore_env_var("JCODE_HOME", previous_home);
}
