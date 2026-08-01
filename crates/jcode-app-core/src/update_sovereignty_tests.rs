use super::*;

#[test]
fn inherited_updater_refuses_before_network_or_filesystem_access() {
    assert!(!updates_enabled());
    assert!(!should_auto_update());
    assert!(
        fetch_latest_release_blocking()
            .unwrap_err()
            .to_string()
            .contains(UPDATE_DISABLED_MESSAGE)
    );
    let prepare_error = match prepare_update_blocking() {
        Err(error) => error,
        Ok(_) => panic!("disabled updater prepared an update"),
    };
    assert!(prepare_error.to_string().contains(UPDATE_DISABLED_MESSAGE));
    assert!(
        check_for_update_blocking()
            .unwrap_err()
            .to_string()
            .contains(UPDATE_DISABLED_MESSAGE)
    );
    assert!(
        run_git_pull_ff_only(Path::new("/path/that/must/not-be-opened"), false)
            .unwrap_err()
            .to_string()
            .contains(UPDATE_DISABLED_MESSAGE)
    );
    let release = synthetic_main_release("deadbee");
    assert!(
        download_and_install_blocking(&release)
            .unwrap_err()
            .to_string()
            .contains(UPDATE_DISABLED_MESSAGE)
    );
    assert!(matches!(
        check_and_maybe_update(true),
        UpdateCheckResult::NoUpdate
    ));
}
