use super::*;

const SAVED_ACCOUNT_DISCOVERY_DISABLED_MESSAGE: &str = "OMNIS_KEY_INHERITED_SURFACE_DISABLED: saved-account discovery is disabled in OMNIS KEY Local Integrity V1";

impl App {
    pub(crate) fn handle_login_picker_key(
        &mut self,
        _code: KeyCode,
        _modifiers: KeyModifiers,
    ) -> anyhow::Result<()> {
        if self.login_picker_overlay.take().is_some() {
            self.push_display_message(DisplayMessage::error(
                SAVED_ACCOUNT_DISCOVERY_DISABLED_MESSAGE,
            ));
            self.set_status_notice("Saved-account discovery disabled");
        }
        Ok(())
    }
}
