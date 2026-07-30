pub const UPDATE_DISABLED_MESSAGE: &str = "OMNIS_KEY_INHERITED_UPDATER_DISABLED: inherited Jcode update behavior is disabled in OMNIS KEY Local Integrity V1";

/// V1 is source-only and never checks for or installs updates.
pub const fn updates_enabled() -> bool {
    false
}
