use crate::ambient_runner::AmbientRunnerHandle;
use std::sync::Arc;

pub(super) fn deferred_auth_bootstrap_active() -> bool {
    std::env::var_os("JCODE_DEFERRED_AUTH_BOOTSTRAP").is_some()
}

pub(super) fn initialize_ambient_runner() -> Option<AmbientRunnerHandle> {
    if deferred_auth_bootstrap_active() {
        return None;
    }
    let handle = AmbientRunnerHandle::new(Arc::new(crate::safety::SafetySystem::new()));
    crate::tool::ambient::init_schedule_runner(handle.clone());
    Some(handle)
}
