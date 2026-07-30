use super::{RouteSelection, RuntimeKey};
use anyhow::Result;

pub const INHERITED_JCODE_SUBSCRIPTION_DISABLED_MESSAGE: &str = "OMNIS_KEY_INHERITED_SURFACE_DISABLED: inherited Jcode subscription behavior is disabled in OMNIS KEY Local Integrity V1";

/// Return whether a route/account identity names the inherited proprietary
/// Jcode subscription surface. Route identities cross process and persistence
/// boundaries, so comparisons are separator- and case-insensitive.
pub fn is_inherited_jcode_subscription_alias(value: &str) -> bool {
    let mut normalized = String::with_capacity(value.len());
    let mut pending_separator = false;
    for ch in value.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            if pending_separator && !normalized.is_empty() {
                normalized.push('-');
            }
            normalized.push(ch.to_ascii_lowercase());
            pending_separator = false;
        } else {
            pending_separator = true;
        }
    }

    matches!(
        normalized.as_str(),
        "jcode"
            | "subscription"
            | "jcode-subscription"
            | "jcode-subscription-provider"
            | "inherited-jcode-provider-disabled"
    )
}

impl RuntimeKey {
    pub fn requests_inherited_jcode_subscription(&self) -> bool {
        match self {
            Self::JcodeSubscription => true,
            Self::OpenAiCompatible {
                profile_id: Some(profile_id),
            }
            | Self::Other(profile_id) => is_inherited_jcode_subscription_alias(profile_id),
            _ => false,
        }
    }
}

impl RouteSelection {
    /// Check every redundant identity field because the wire representation is
    /// attacker-controlled and the fields need not agree.
    pub fn requests_inherited_jcode_subscription(&self) -> bool {
        self.runtime_key.requests_inherited_jcode_subscription()
            || is_inherited_jcode_subscription_alias(&self.api_method)
            || is_inherited_jcode_subscription_alias(&self.provider_label)
    }

    pub fn ensure_no_inherited_jcode_subscription(&self) -> Result<()> {
        if self.requests_inherited_jcode_subscription() {
            anyhow::bail!(INHERITED_JCODE_SUBSCRIPTION_DISABLED_MESSAGE);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inherited_jcode_route_identity_is_fail_closed_across_redundant_fields() {
        let benign = RouteSelection {
            model: "fixture-model".to_string(),
            runtime_key: RuntimeKey::Current,
            api_method: "current".to_string(),
            provider_label: "Fixture".to_string(),
            detail: String::new(),
        };
        assert!(!benign.requests_inherited_jcode_subscription());

        for hostile in [
            RouteSelection {
                runtime_key: RuntimeKey::JcodeSubscription,
                ..benign.clone()
            },
            RouteSelection {
                runtime_key: RuntimeKey::Other("SUBSCRIPTION".to_string()),
                ..benign.clone()
            },
            RouteSelection {
                api_method: "JCODE_SUBSCRIPTION".to_string(),
                ..benign.clone()
            },
            RouteSelection {
                provider_label: "Jcode Subscription".to_string(),
                ..benign.clone()
            },
        ] {
            assert!(
                hostile.requests_inherited_jcode_subscription(),
                "hostile route identity was not classified: {hostile:?}"
            );
        }
    }
}
