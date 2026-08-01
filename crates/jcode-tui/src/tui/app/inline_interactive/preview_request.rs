use crate::tui::app::App;
use crate::tui::{InlineInteractiveState, PickerKind};

pub(super) enum InlinePickerPreviewRequest {
    Model { filter: String },
}

impl InlinePickerPreviewRequest {
    fn kind(&self) -> PickerKind {
        match self {
            Self::Model { .. } => PickerKind::Model,
        }
    }

    pub(super) fn filter(&self) -> &str {
        match self {
            Self::Model { filter } => filter,
        }
    }

    pub(super) fn open(&self, app: &mut App) {
        match self {
            Self::Model { .. } => app.open_model_picker(),
        }
    }

    pub(super) fn matches_picker(&self, _app: &App, picker: &InlineInteractiveState) -> bool {
        picker.preview && picker.kind == self.kind()
    }
}
