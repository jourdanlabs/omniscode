use anyhow::Result;
use std::process::Command as ProcessCommand;

pub use crate::session_rebuild::{hot_rebuild, spawn_background_session_rebuild};

use crate::tui::RunResult;

pub fn has_requested_action(run_result: &RunResult) -> bool {
    run_result.reload_session.is_some()
        || run_result.rebuild_session.is_some()
        || run_result.update_session.is_some()
        || run_result.restart_session.is_some()
}

pub fn execute_requested_action(run_result: &RunResult) -> Result<()> {
    if let Some(ref reload_session_id) = run_result.reload_session {
        hot_reload(reload_session_id)?;
    }
    if let Some(ref rebuild_session_id) = run_result.rebuild_session {
        hot_rebuild(rebuild_session_id)?;
    }
    if let Some(ref update_session_id) = run_result.update_session {
        hot_update(update_session_id)?;
    }
    if let Some(ref restart_session_id) = run_result.restart_session {
        hot_restart(restart_session_id)?;
    }
    Ok(())
}

pub fn hot_restart(session_id: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let exe = std::env::current_exe()?;
    let is_selfdev = crate::cli::selfdev::client_selfdev_requested();

    crate::env::set_var("JCODE_RESUMING", "1");
    let mut command = ProcessCommand::new(&exe);
    if is_selfdev {
        command.arg("self-dev");
    }
    command.arg("--resume").arg(session_id).current_dir(&cwd);
    let error = crate::platform::replace_process(&mut command);
    Err(anyhow::anyhow!("Failed to exec {:?}: {}", exe, error))
}

fn updater_disabled<T>() -> Result<T> {
    anyhow::bail!(crate::update::UPDATE_DISABLED_MESSAGE)
}

pub fn hot_reload(_session_id: &str) -> Result<()> {
    updater_disabled()
}

pub fn hot_update(_session_id: &str) -> Result<()> {
    updater_disabled()
}

pub fn check_for_updates() -> Option<bool> {
    None
}

pub fn run_auto_update() -> Result<()> {
    updater_disabled()
}

pub fn run_update() -> Result<()> {
    updater_disabled()
}

#[cfg(test)]
mod tests {
    use super::{check_for_updates, hot_reload, hot_update, run_auto_update, run_update};

    #[test]
    fn inherited_update_and_reload_entries_are_unconditionally_disabled() {
        assert_eq!(check_for_updates(), None);
        for error in [
            hot_reload("fixture-session").expect_err("reload must be disabled"),
            hot_update("fixture-session").expect_err("update must be disabled"),
            run_auto_update().expect_err("automatic update must be disabled"),
            run_update().expect_err("manual update must be disabled"),
        ] {
            assert!(
                error
                    .to_string()
                    .contains(crate::update::UPDATE_DISABLED_MESSAGE),
                "{error}"
            );
        }
    }
}
