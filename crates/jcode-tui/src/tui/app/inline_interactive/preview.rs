use super::helpers::slash_command_preview_filter;
use super::preview_request::InlinePickerPreviewRequest;
use super::*;
use crate::tui::PickerKind;
use crossterm::event::{KeyCode, KeyModifiers};

impl App {
    pub(crate) fn model_picker_preview_filter(input: &str) -> Option<String> {
        slash_command_preview_filter(input, &["/model", "/models"])
    }

    fn inline_picker_preview_request(&self, input: &str) -> Option<InlinePickerPreviewRequest> {
        Self::model_picker_preview_filter(input)
            .map(|filter| InlinePickerPreviewRequest::Model { filter })
    }

    pub(crate) fn sync_model_picker_preview_from_input(&mut self) {
        let Some(request) = self.inline_picker_preview_request(&self.input) else {
            if self
                .inline_interactive_state
                .as_ref()
                .map(|picker| picker.preview)
                .unwrap_or(false)
            {
                self.inline_interactive_state = None;
            }
            return;
        };

        let should_open = self
            .inline_interactive_state
            .as_ref()
            .map(|picker| !request.matches_picker(self, picker))
            .unwrap_or(true);

        if should_open {
            let saved_input = self.input.clone();
            let saved_cursor = self.cursor_pos;
            let append_model_filter_space =
                matches!(
                    request,
                    InlinePickerPreviewRequest::Model { ref filter } if filter.is_empty()
                ) && matches!(saved_input.trim_start(), "/model" | "/models")
                    && saved_cursor == saved_input.len();
            request.open(self);
            let mut preview_opened = false;
            if let Some(ref mut picker) = self.inline_interactive_state {
                picker.preview = true;
                preview_opened = true;
            }
            // Preview must not steal the user's command input.
            self.input = saved_input;
            self.cursor_pos = saved_cursor;
            // Once the model picker is visible, put the cursor in its filter
            // argument so typing narrows models instead of extending `/model`.
            if preview_opened && append_model_filter_space {
                self.input.push(' ');
                self.cursor_pos = self.input.len();
            }
        }

        if let Some(ref mut picker) = self.inline_interactive_state
            && picker.preview
        {
            picker.filter = request.filter().to_string();
            Self::apply_inline_interactive_filter(picker);
        }
    }

    pub(crate) fn activate_picker_from_preview(&mut self) -> bool {
        if !self
            .inline_interactive_state
            .as_ref()
            .map(|picker| picker.preview)
            .unwrap_or(false)
        {
            return false;
        }

        if let Some(ref mut picker) = self.inline_interactive_state {
            picker.preview = false;
        }
        if self
            .inline_interactive_state
            .as_ref()
            .map(|picker| picker.kind == PickerKind::Usage)
            .unwrap_or(false)
        {
            if let Some(ref mut picker) = self.inline_interactive_state {
                picker.column = 0;
            }
            self.input.clear();
            self.cursor_pos = 0;
            return true;
        }
        // `/login` + immediate Enter must not silently start the first
        // provider's login flow. With no filter and no explicit selection,
        // just focus the picker so the user chooses deliberately.
        if self
            .inline_interactive_state
            .as_ref()
            .map(|picker| {
                picker.kind == PickerKind::Login && picker.filter.is_empty() && picker.selected == 0
            })
            .unwrap_or(false)
        {
            if let Some(ref mut picker) = self.inline_interactive_state {
                picker.column = 0;
            }
            self.input.clear();
            self.cursor_pos = 0;
            return true;
        }
        self.input.clear();
        self.cursor_pos = 0;
        let _ = self.handle_inline_interactive_key(KeyCode::Enter, KeyModifiers::NONE);
        true
    }
}
