use super::*;

const INHERITED_ACCOUNT_DISABLED_MESSAGE: &str = "OMNIS_KEY_INHERITED_SURFACE_DISABLED: inherited Jcode account behavior is disabled in OMNIS KEY Local Integrity V1";

impl App {
    fn refuse_inherited_account_surface(&mut self) {
        self.account_picker_overlay = None;
        self.pending_account_input = None;
        self.push_display_message(DisplayMessage::error(INHERITED_ACCOUNT_DISABLED_MESSAGE));
        self.set_status_notice("Account surface disabled");
    }

    pub(crate) fn handle_account_picker_command(
        &mut self,
        _command: crate::tui::account_picker::AccountPickerCommand,
    ) {
        self.refuse_inherited_account_surface();
    }

    pub(crate) fn handle_pending_account_input(
        &mut self,
        _pending: PendingAccountInput,
        _input: String,
    ) {
        self.refuse_inherited_account_surface();
    }

    pub(crate) fn next_account_picker_action(
        &mut self,
        _code: KeyCode,
        _modifiers: KeyModifiers,
    ) -> anyhow::Result<Option<crate::tui::account_picker::AccountPickerCommand>> {
        self.account_picker_overlay = None;
        Ok(None)
    }
}
