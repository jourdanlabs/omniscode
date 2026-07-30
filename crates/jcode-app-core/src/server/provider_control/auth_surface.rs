use super::*;

pub(super) fn requests_disabled_jcode_auth(
    provider_hint: Option<&str>,
    auth: Option<&AuthChanged>,
) -> bool {
    crate::auth::lifecycle::AuthActivationRequest::new(
        provider_hint.map(str::to_string),
        auth.cloned(),
    )
    .requests_disabled_jcode_subscription()
}

pub(super) fn reject_disabled_auth(
    id: u64,
    provider_hint: &Option<String>,
    auth: &Option<AuthChanged>,
    client_event_tx: &mpsc::UnboundedSender<ServerEvent>,
) -> bool {
    if !requests_disabled_jcode_auth(provider_hint.as_deref(), auth.as_ref()) {
        return false;
    }
    drop(client_event_tx.send(ServerEvent::Error {
        id,
        message: crate::subscription_catalog::INHERITED_SUBSCRIPTION_DISABLED_MESSAGE.to_string(),
        retry_after_secs: None,
    }));
    true
}

pub(super) fn format_auth_catalog_refresh_complete(
    provider_name: Option<&str>,
    provider_model: Option<&str>,
    summary: &ModelCatalogRefreshSummary,
    has_warning: bool,
) -> String {
    let provider_label = provider_name.unwrap_or("provider");
    let title = provider_model
        .map(|model| format!("**Model ready:** `{model}`"))
        .unwrap_or_else(|| "**Model access refreshed**".to_string());
    let changed = summary.models_added > 0
        || summary.models_removed > 0
        || summary.routes_added > 0
        || summary.routes_removed > 0
        || summary.routes_changed > 0;
    let catalog_status = if has_warning {
        if changed {
            format!("{provider_label} catalog changed; some routes missing. Use `/model`.")
        } else {
            format!("{provider_label} catalog unchanged; some routes missing. Use `/model`.")
        }
    } else if changed {
        format!(
            "{provider_label} catalog changed: models +{}/-{}, routes +{}/-{}/~{}. Use `/model`.",
            summary.models_added,
            summary.models_removed,
            summary.routes_added,
            summary.routes_removed,
            summary.routes_changed,
        )
    } else {
        format!(
            "{provider_label} catalog unchanged: {} models, {} routes. Use `/model`.",
            summary.model_count_after, summary.route_count_after,
        )
    };
    format!("{title}\n{catalog_status}")
}
