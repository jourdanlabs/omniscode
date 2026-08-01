use crate::protocol::AuthChanged;

fn inherited_jcode_identity(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "jcode" | "subscription" | "jcode-subscription"
    )
}

pub(crate) fn requests_disabled_jcode_subscription(
    legacy_provider_hint: Option<&str>,
    auth: Option<&AuthChanged>,
) -> bool {
    legacy_provider_hint.is_some_and(inherited_jcode_identity)
        || auth.is_some_and(|changed| {
            inherited_jcode_identity(changed.provider.as_str())
                || changed
                    .expected_runtime
                    .as_ref()
                    .is_some_and(|runtime| inherited_jcode_identity(runtime.as_str()))
                || changed
                    .expected_catalog_namespace
                    .as_ref()
                    .is_some_and(|namespace| inherited_jcode_identity(namespace.as_str()))
        })
}
