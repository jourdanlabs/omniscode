use anyhow::Result;

pub fn hot_rebuild(_session_id: &str) -> Result<()> {
    anyhow::bail!(crate::update::UPDATE_DISABLED_MESSAGE)
}

pub fn spawn_background_session_rebuild(_session_id: String) {}

#[cfg(test)]
mod tests {
    #[test]
    fn inherited_rebuild_is_unconditionally_disabled() {
        let error = super::hot_rebuild("fixture-session")
            .expect_err("inherited source rebuild must be disabled");
        assert!(
            error
                .to_string()
                .contains(crate::update::UPDATE_DISABLED_MESSAGE),
            "{error}"
        );
    }
}
