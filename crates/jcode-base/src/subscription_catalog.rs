pub const JCODE_API_KEY_ENV: &str = "JCODE_API_KEY";
pub const JCODE_API_BASE_ENV: &str = "JCODE_API_BASE";
pub const JCODE_ACCOUNT_ID_ENV: &str = "JCODE_ACCOUNT_ID";
pub const JCODE_ACCOUNT_EMAIL_ENV: &str = "JCODE_ACCOUNT_EMAIL";
pub const JCODE_TIER_ENV: &str = "JCODE_TIER";
pub const JCODE_ENV_FILE: &str = "jcode-subscription.env";
pub const JCODE_CACHE_NAMESPACE: &str = "jcode-subscription";
pub const JCODE_SUBSCRIPTION_ACTIVE_ENV: &str = "JCODE_SUBSCRIPTION_ACTIVE";
pub const DEFAULT_JCODE_API_BASE: &str = "disabled://omnis-key-v1";
pub const JCODE_PRICING_URL: &str = "disabled://omnis-key-v1";
pub const JCODE_ACCOUNT_URL: &str = "disabled://omnis-key-v1";
pub const JCODE_PROVIDER_DISPLAY_NAME: &str = "Jcode Subscription";
pub const JCODE_ROUTE_API_METHOD: &str = "jcode-subscription";
pub const INHERITED_SUBSCRIPTION_DISABLED_MESSAGE: &str =
    jcode_provider_core::sovereignty::INHERITED_JCODE_SUBSCRIPTION_DISABLED_MESSAGE;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum JcodeTier {
    Plus,
    Pro,
    Max,
    Ultra,
    Flagship,
}

impl JcodeTier {
    pub const ALL: &'static [JcodeTier] = &[
        JcodeTier::Plus,
        JcodeTier::Pro,
        JcodeTier::Max,
        JcodeTier::Ultra,
        JcodeTier::Flagship,
    ];

    pub fn retail_price_usd(self) -> u32 {
        match self {
            Self::Plus => 10,
            Self::Pro => 20,
            Self::Max => 100,
            Self::Ultra => 200,
            Self::Flagship => 1000,
        }
    }

    pub fn usable_budget_usd(self) -> f64 {
        match self {
            Self::Plus => 18.00,
            Self::Pro => 40.00,
            Self::Max => 225.00,
            Self::Ultra => 500.00,
            Self::Flagship => 3000.00,
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            Self::Plus => "Plus",
            Self::Pro => "Pro",
            Self::Max => "Max",
            Self::Ultra => "Ultra",
            Self::Flagship => "Solo",
        }
    }

    /// Stable machine identifier used for wire values and local persistence.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plus => "plus",
            Self::Pro => "pro",
            Self::Max => "max",
            Self::Ultra => "ultra",
            Self::Flagship => "flagship",
        }
    }

    /// Parse a tier from a wire/persisted value (case-insensitive).
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "plus" => Some(Self::Plus),
            "pro" => Some(Self::Pro),
            "max" => Some(Self::Max),
            "ultra" => Some(Self::Ultra),
            "flagship" | "solo" => Some(Self::Flagship),
            _ => None,
        }
    }

    /// Whether an account on this tier may use a model gated at `required`.
    pub fn allows(self, required: JcodeTier) -> bool {
        self >= required
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamRoutingPolicy {
    /// Routing is decided server-side by the jcode router (model -> provider +
    /// org key). The client does not pick upstreams; this is the only policy for
    /// the managed subscription.
    ServerManaged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CuratedModel {
    pub id: &'static str,
    pub display_name: &'static str,
    pub aliases: &'static [&'static str],
    pub default_enabled: bool,
    pub routing_policy: UpstreamRoutingPolicy,
    /// Minimum subscription tier that may use this model.
    pub min_tier: JcodeTier,
    pub note: &'static str,
}

pub const CURATED_MODELS: &[CuratedModel] = &[
    CuratedModel {
        id: "claude-opus-4-8",
        display_name: "Claude Opus 4.8",
        aliases: &["claude-opus-4-8", "opus-4-8", "opus 4.8", "claude opus 4.8"],
        default_enabled: true,
        routing_policy: UpstreamRoutingPolicy::ServerManaged,
        min_tier: JcodeTier::Plus,
        note: "Frontier model; routed server-side to Anthropic by the jcode router.",
    },
    CuratedModel {
        id: "claude-sonnet-4-6",
        display_name: "Claude Sonnet 4.6",
        aliases: &[
            "claude-sonnet-4-6",
            "sonnet-4-6",
            "sonnet 4.6",
            "claude sonnet 4.6",
        ],
        default_enabled: false,
        routing_policy: UpstreamRoutingPolicy::ServerManaged,
        min_tier: JcodeTier::Plus,
        note: "Frontier model; routed server-side to Amazon Bedrock by the jcode router.",
    },
    CuratedModel {
        id: "gpt-5.5",
        display_name: "GPT-5.5",
        aliases: &["gpt-5.5", "gpt-5-5", "gpt 5.5"],
        default_enabled: false,
        routing_policy: UpstreamRoutingPolicy::ServerManaged,
        min_tier: JcodeTier::Plus,
        note: "Frontier model; routed server-side to OpenAI by the jcode router.",
    },
    CuratedModel {
        id: "claude-fable-5",
        display_name: "Claude Fable 5",
        aliases: &["claude-fable-5", "fable-5", "fable 5", "claude fable 5"],
        default_enabled: false,
        routing_policy: UpstreamRoutingPolicy::ServerManaged,
        min_tier: JcodeTier::Ultra,
        note: "Ultra-tier model; routed server-side to Anthropic by the jcode router.",
    },
    CuratedModel {
        id: "gpt-5.6-sol",
        display_name: "GPT-5.6 Sol",
        aliases: &["gpt-5.6-sol", "gpt 5.6 sol", "sol"],
        default_enabled: false,
        routing_policy: UpstreamRoutingPolicy::ServerManaged,
        min_tier: JcodeTier::Plus,
        note: "Frontier model; routed server-side to OpenAI by the jcode router.",
    },
    CuratedModel {
        id: "qwen3-coder-next",
        display_name: "Qwen3 Coder Next",
        aliases: &["qwen3-coder-next", "qwen 3 coder next", "qwen3 coder next"],
        default_enabled: false,
        routing_policy: UpstreamRoutingPolicy::ServerManaged,
        min_tier: JcodeTier::Plus,
        note: "Open-weight coding model; routed server-side to Amazon Bedrock by the jcode router.",
    },
    CuratedModel {
        id: "devstral-2-123b",
        display_name: "Devstral 2 123B",
        aliases: &[
            "devstral-2-123b",
            "devstral 2 123b",
            "mistral devstral 2 123b",
        ],
        default_enabled: false,
        routing_policy: UpstreamRoutingPolicy::ServerManaged,
        min_tier: JcodeTier::Plus,
        note: "Open-weight coding model; routed server-side to Amazon Bedrock by the jcode router.",
    },
    CuratedModel {
        id: "deepseek-v3.2",
        display_name: "DeepSeek V3.2",
        aliases: &["deepseek-v3.2", "deepseek v3.2", "deepseek 3.2"],
        default_enabled: false,
        routing_policy: UpstreamRoutingPolicy::ServerManaged,
        min_tier: JcodeTier::Plus,
        note: "Open-weight reasoning and coding model; routed server-side to Amazon Bedrock by the jcode router.",
    },
    CuratedModel {
        id: "nova-2-lite",
        display_name: "Amazon Nova 2 Lite",
        aliases: &["nova-2-lite", "nova 2 lite", "amazon nova 2 lite"],
        default_enabled: false,
        routing_policy: UpstreamRoutingPolicy::ServerManaged,
        min_tier: JcodeTier::Plus,
        note: "Recent efficient multimodal model; routed server-side to Amazon Bedrock by the jcode router.",
    },
    CuratedModel {
        id: "minimax-m2.5",
        display_name: "MiniMax M2.5",
        aliases: &["minimax-m2.5", "minimax m2.5", "minimax m2 5"],
        default_enabled: false,
        routing_policy: UpstreamRoutingPolicy::ServerManaged,
        min_tier: JcodeTier::Plus,
        note: "Recent reasoning and coding model; routed server-side to Amazon Bedrock by the jcode router.",
    },
    CuratedModel {
        id: "mistral-large-3",
        display_name: "Mistral Large 3",
        aliases: &["mistral-large-3", "mistral large 3"],
        default_enabled: false,
        routing_policy: UpstreamRoutingPolicy::ServerManaged,
        min_tier: JcodeTier::Plus,
        note: "Open-weight general and coding model; routed server-side to Amazon Bedrock by the jcode router.",
    },
    CuratedModel {
        id: "kimi-k2.5",
        display_name: "Kimi K2.5",
        aliases: &["kimi-k2.5", "kimi k2.5", "kimi k2 5"],
        default_enabled: false,
        routing_policy: UpstreamRoutingPolicy::ServerManaged,
        min_tier: JcodeTier::Plus,
        note: "Recent reasoning and agentic model; routed server-side to Amazon Bedrock by the jcode router.",
    },
    CuratedModel {
        id: "kimi-k2-thinking",
        display_name: "Kimi K2 Thinking",
        aliases: &["kimi-k2-thinking", "kimi k2 thinking"],
        default_enabled: false,
        routing_policy: UpstreamRoutingPolicy::ServerManaged,
        min_tier: JcodeTier::Plus,
        note: "Reasoning-focused model; routed server-side to Amazon Bedrock by the jcode router.",
    },
    CuratedModel {
        id: "nemotron-nano-3-30b",
        display_name: "Nemotron Nano 3 30B",
        aliases: &[
            "nemotron-nano-3-30b",
            "nemotron nano 3 30b",
            "nvidia nemotron nano 3 30b",
        ],
        default_enabled: false,
        routing_policy: UpstreamRoutingPolicy::ServerManaged,
        min_tier: JcodeTier::Plus,
        note: "Efficient open-weight reasoning model; routed server-side to Amazon Bedrock by the jcode router.",
    },
    CuratedModel {
        id: "gpt-oss-120b",
        display_name: "GPT-OSS 120B",
        aliases: &["gpt-oss-120b", "gpt oss 120b", "openai gpt oss 120b"],
        default_enabled: false,
        routing_policy: UpstreamRoutingPolicy::ServerManaged,
        min_tier: JcodeTier::Plus,
        note: "Large open-weight reasoning model; routed server-side to Amazon Bedrock by the jcode router.",
    },
    CuratedModel {
        id: "gpt-oss-20b",
        display_name: "GPT-OSS 20B",
        aliases: &["gpt-oss-20b", "gpt oss 20b", "openai gpt oss 20b"],
        default_enabled: false,
        routing_policy: UpstreamRoutingPolicy::ServerManaged,
        min_tier: JcodeTier::Plus,
        note: "Efficient open-weight reasoning model; routed server-side to Amazon Bedrock by the jcode router.",
    },
    CuratedModel {
        id: "qwen3-next-80b",
        display_name: "Qwen3 Next 80B A3B",
        aliases: &["qwen3-next-80b", "qwen3 next 80b", "qwen 3 next 80b a3b"],
        default_enabled: false,
        routing_policy: UpstreamRoutingPolicy::ServerManaged,
        min_tier: JcodeTier::Plus,
        note: "Open-weight general and coding model; routed server-side to Amazon Bedrock by the jcode router.",
    },
    CuratedModel {
        id: "glm-5",
        display_name: "GLM-5",
        aliases: &["glm-5", "glm 5", "zai glm 5"],
        default_enabled: false,
        routing_policy: UpstreamRoutingPolicy::ServerManaged,
        min_tier: JcodeTier::Plus,
        note: "Recent general and coding model; routed server-side to Amazon Bedrock by the jcode router.",
    },
    CuratedModel {
        id: "glm-4.7-flash",
        display_name: "GLM 4.7 Flash",
        aliases: &["glm-4.7-flash", "glm 4.7 flash", "zai glm 4.7 flash"],
        default_enabled: false,
        routing_policy: UpstreamRoutingPolicy::ServerManaged,
        min_tier: JcodeTier::Plus,
        note: "Efficient recent general model; routed server-side to Amazon Bedrock by the jcode router.",
    },
];

pub fn curated_models() -> &'static [CuratedModel] {
    CURATED_MODELS
}

pub fn default_model() -> &'static CuratedModel {
    CURATED_MODELS
        .iter()
        .find(|model| model.default_enabled)
        .unwrap_or(&CURATED_MODELS[0])
}

/// Normalize a model id for curated-catalog matching: strips any `@provider`
/// routing suffix, the `[1m]` long-context suffix, and lowercases.
fn normalize_model_key(model: &str) -> String {
    let base = model.trim().split('@').next().unwrap_or("").trim();
    jcode_provider_core::model_id::canonical(base)
}

pub fn find_curated_model(model: &str) -> Option<&'static CuratedModel> {
    let normalized = normalize_model_key(model);
    CURATED_MODELS.iter().find(|candidate| {
        candidate.id.eq_ignore_ascii_case(&normalized)
            || candidate
                .aliases
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(&normalized))
    })
}

pub fn canonical_model_id(model: &str) -> Option<&'static str> {
    find_curated_model(model).map(|model| model.id)
}

pub fn is_curated_model(model: &str) -> bool {
    canonical_model_id(model).is_some()
}

/// The effective subscription tier for gating decisions.
///
/// `/v1/me` is the source of truth; the last-known tier is persisted to
/// `jcode-subscription.env` (`JCODE_TIER`). Unknown/absent tier behaves like
/// Plus for backward compatibility.
pub fn effective_tier() -> JcodeTier {
    JcodeTier::Plus
}

/// The last tier reported by the backend, if any was persisted.
pub fn cached_tier() -> Option<JcodeTier> {
    None
}

/// Persist the last-known tier reported by the backend (`None` clears it).
pub fn store_cached_tier(_tier: Option<JcodeTier>) -> anyhow::Result<()> {
    anyhow::bail!(INHERITED_SUBSCRIPTION_DISABLED_MESSAGE)
}

/// Whether the current (cached) tier is allowed to use `model`.
/// Non-curated models return `false`.
pub fn is_model_allowed_for_current_tier(model: &str) -> bool {
    find_curated_model(model)
        .map(|curated| effective_tier().allows(curated.min_tier))
        .unwrap_or(false)
}

pub fn routing_policy_detail(model: &CuratedModel) -> String {
    match model.routing_policy {
        UpstreamRoutingPolicy::ServerManaged => {
            "jcode subscription routing · managed server-side".to_string()
        }
    }
}

pub fn configured_api_key() -> Option<String> {
    None
}

pub fn configured_api_base() -> Option<String> {
    None
}

pub fn has_credentials() -> bool {
    false
}

/// Persist an account API key and its non-secret account metadata in jcode's
/// owner-only subscription file.
pub fn persist_account_credentials(
    _api_key: &str,
    _account_id: Option<&str>,
    _email: Option<&str>,
    _tier: Option<&str>,
) -> anyhow::Result<()> {
    anyhow::bail!(INHERITED_SUBSCRIPTION_DISABLED_MESSAGE)
}

/// Remove the local account credential and cached account identity/tier. The
/// configured API base is intentionally retained because it is endpoint
/// configuration, not an authorization credential.
pub fn clear_account_credentials() -> anyhow::Result<()> {
    anyhow::bail!(INHERITED_SUBSCRIPTION_DISABLED_MESSAGE)
}

pub fn account_credential_path() -> anyhow::Result<std::path::PathBuf> {
    anyhow::bail!(INHERITED_SUBSCRIPTION_DISABLED_MESSAGE)
}

/// Re-harden and verify the subscription file after every credential mutation.
/// This is deliberately an explicit postcondition even though the shared secret
/// writer also applies owner-only permissions.
pub fn ensure_account_credential_permissions() -> anyhow::Result<()> {
    anyhow::bail!(INHERITED_SUBSCRIPTION_DISABLED_MESSAGE)
}

pub fn has_router_base() -> bool {
    false
}

pub fn is_runtime_mode_enabled() -> bool {
    false
}

pub fn apply_runtime_env() {
    // Intentionally inert. A hostile inherited environment cannot activate the
    // provider because `is_runtime_mode_enabled` is permanently false, and
    // disabling this entry must not mutate ambient process state.
}

pub fn clear_runtime_env() {
    // Intentionally inert; see `apply_runtime_env`.
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECTED_PLUS_MODELS: &[&str] = &[
        "claude-opus-4-8",
        "claude-sonnet-4-6",
        "gpt-5.5",
        "gpt-5.6-sol",
        "qwen3-coder-next",
        "devstral-2-123b",
        "deepseek-v3.2",
        "nova-2-lite",
        "minimax-m2.5",
        "mistral-large-3",
        "kimi-k2.5",
        "kimi-k2-thinking",
        "nemotron-nano-3-30b",
        "gpt-oss-120b",
        "gpt-oss-20b",
        "qwen3-next-80b",
        "glm-5",
        "glm-4.7-flash",
    ];

    #[test]
    fn curated_model_aliases_resolve_to_canonical_ids() {
        assert_eq!(canonical_model_id("opus 4.8"), Some("claude-opus-4-8"));
        assert_eq!(
            canonical_model_id("Claude Opus 4.8"),
            Some("claude-opus-4-8")
        );
        assert_eq!(canonical_model_id("gpt-5.5"), Some("gpt-5.5"));
        assert_eq!(canonical_model_id("GPT 5.5"), Some("gpt-5.5"));
        assert_eq!(
            canonical_model_id("Claude Sonnet 4.6"),
            Some("claude-sonnet-4-6")
        );
        assert_eq!(canonical_model_id("sonnet 4.6"), Some("claude-sonnet-4-6"));
        assert_eq!(canonical_model_id("fable-5"), Some("claude-fable-5"));
        assert_eq!(canonical_model_id("Claude Fable 5"), Some("claude-fable-5"));
        assert_eq!(canonical_model_id("sol"), Some("gpt-5.6-sol"));
        assert_eq!(canonical_model_id("GPT 5.6 Sol"), Some("gpt-5.6-sol"));
        assert_eq!(
            canonical_model_id("Qwen 3 Coder Next"),
            Some("qwen3-coder-next")
        );
        assert_eq!(
            canonical_model_id("Mistral Devstral 2 123B"),
            Some("devstral-2-123b")
        );
        assert_eq!(canonical_model_id("DeepSeek 3.2"), Some("deepseek-v3.2"));
        for (alias, expected) in [
            ("Amazon Nova 2 Lite", "nova-2-lite"),
            ("MiniMax M2.5", "minimax-m2.5"),
            ("Mistral Large 3", "mistral-large-3"),
            ("Kimi K2.5", "kimi-k2.5"),
            ("Kimi K2 Thinking", "kimi-k2-thinking"),
            ("NVIDIA Nemotron Nano 3 30B", "nemotron-nano-3-30b"),
            ("OpenAI GPT OSS 120B", "gpt-oss-120b"),
            ("OpenAI GPT OSS 20B", "gpt-oss-20b"),
            ("Qwen 3 Next 80B A3B", "qwen3-next-80b"),
            ("ZAI GLM 5", "glm-5"),
            ("ZAI GLM 4.7 Flash", "glm-4.7-flash"),
        ] {
            assert_eq!(canonical_model_id(alias), Some(expected), "alias {alias}");
        }
        assert_eq!(canonical_model_id("NVIDIA Nemotron Super 3 120B"), None);
        assert_eq!(canonical_model_id("unknown-model"), None);
    }

    #[test]
    fn curated_model_lookup_ignores_provider_pin_suffix() {
        assert_eq!(
            canonical_model_id("claude-opus-4-8@anthropic"),
            Some("claude-opus-4-8")
        );
        assert_eq!(canonical_model_id("gpt-5.5@openai"), Some("gpt-5.5"));
    }

    #[test]
    fn default_model_is_opus() {
        assert_eq!(default_model().id, "claude-opus-4-8");
    }

    #[test]
    fn curated_catalog_has_exact_paid_and_ultra_sets() {
        assert_eq!(
            CURATED_MODELS
                .iter()
                .filter(|model| model.min_tier == JcodeTier::Plus)
                .map(|model| model.id)
                .collect::<Vec<_>>(),
            EXPECTED_PLUS_MODELS
        );
        assert_eq!(
            CURATED_MODELS
                .iter()
                .filter(|model| model.min_tier == JcodeTier::Ultra)
                .map(|model| model.id)
                .collect::<Vec<_>>(),
            vec!["claude-fable-5"]
        );
        assert!(
            CURATED_MODELS
                .iter()
                .all(|model| model.min_tier != JcodeTier::Flagship)
        );
        assert_eq!(CURATED_MODELS.len(), 19);
        assert!(find_curated_model("magistral-small-1.2").is_none());
        assert!(find_curated_model("gemma-3-27b").is_none());
        assert!(find_curated_model("llama-4-maverick").is_none());
        assert!(find_curated_model("llama-4-scout").is_none());
        assert!(find_curated_model("nemotron-super-3-120b").is_none());
    }

    #[test]
    fn tier_pricing_matches_launched_plans() {
        let expected = [
            (JcodeTier::Plus, "plus", "Plus", 10, 18.00),
            (JcodeTier::Pro, "pro", "Pro", 20, 40.00),
            (JcodeTier::Max, "max", "Max", 100, 225.00),
            (JcodeTier::Ultra, "ultra", "Ultra", 200, 500.00),
            (JcodeTier::Flagship, "flagship", "Solo", 1000, 3000.00),
        ];

        assert_eq!(JcodeTier::ALL, expected.map(|(tier, ..)| tier));
        for (tier, id, display_name, retail_price, usable_budget) in expected {
            assert_eq!(tier.as_str(), id);
            assert_eq!(tier.display_name(), display_name);
            assert_eq!(tier.retail_price_usd(), retail_price);
            assert_eq!(tier.usable_budget_usd(), usable_budget);
        }
    }

    #[test]
    fn tier_parse_round_trips() {
        for tier in JcodeTier::ALL {
            assert_eq!(JcodeTier::parse(tier.as_str()), Some(*tier));
        }
        assert_eq!(JcodeTier::parse("PLUS"), Some(JcodeTier::Plus));
        assert_eq!(JcodeTier::parse(" Pro "), Some(JcodeTier::Pro));
        assert_eq!(JcodeTier::parse("MAX"), Some(JcodeTier::Max));
        assert_eq!(JcodeTier::parse(" ultra "), Some(JcodeTier::Ultra));
        assert_eq!(JcodeTier::parse(" Flagship "), Some(JcodeTier::Flagship));
        assert_eq!(JcodeTier::parse(" Solo "), Some(JcodeTier::Flagship));
        assert_eq!(JcodeTier::parse("starter"), None);
    }

    #[test]
    fn tier_gating_follows_catalog_order() {
        for (account_index, account_tier) in JcodeTier::ALL.iter().copied().enumerate() {
            for (required_index, required_tier) in JcodeTier::ALL.iter().copied().enumerate() {
                assert_eq!(
                    account_tier.allows(required_tier),
                    account_index >= required_index,
                    "{} gating {}",
                    account_tier.display_name(),
                    required_tier.display_name()
                );
            }
        }
    }

    #[test]
    fn model_entitlements_match_paid_tiers() {
        for model in CURATED_MODELS {
            match model.id {
                "claude-fable-5" => assert_eq!(model.min_tier, JcodeTier::Ultra),
                _ => assert_eq!(model.min_tier, JcodeTier::Plus),
            }
        }

        for tier in JcodeTier::ALL {
            for model in EXPECTED_PLUS_MODELS {
                assert!(tier.allows(find_curated_model(model).unwrap().min_tier));
            }
            assert_eq!(
                tier.allows(find_curated_model("claude-fable-5").unwrap().min_tier),
                matches!(tier, JcodeTier::Ultra | JcodeTier::Flagship)
            );
        }
    }

    #[test]
    fn inherited_tier_state_is_ignored_and_cannot_be_persisted() {
        let _guard = crate::storage::lock_test_env();
        crate::env::remove_var(JCODE_TIER_ENV);
        let temp = tempfile::tempdir().expect("temp home");
        crate::env::set_var("JCODE_HOME", temp.path().to_string_lossy().to_string());

        assert_eq!(cached_tier(), None);
        assert_eq!(effective_tier(), JcodeTier::Plus);

        crate::env::set_var(JCODE_TIER_ENV, JcodeTier::Flagship.as_str());
        assert_eq!(cached_tier(), None);
        assert_eq!(effective_tier(), JcodeTier::Plus);
        assert!(!is_model_allowed_for_current_tier("claude-fable-5"));
        let error = store_cached_tier(Some(JcodeTier::Flagship))
            .expect_err("inherited tier persistence must refuse");
        assert_eq!(error.to_string(), INHERITED_SUBSCRIPTION_DISABLED_MESSAGE);
        assert_eq!(cached_tier(), None);
        assert!(
            !temp.path().join(JCODE_ENV_FILE).exists(),
            "disabled tier persistence must not create a credential file"
        );

        crate::env::remove_var("JCODE_HOME");
        crate::env::remove_var(JCODE_TIER_ENV);
    }

    #[test]
    fn runtime_mode_remains_disabled_after_hostile_activation_attempt() {
        let _guard = crate::storage::lock_test_env();
        clear_runtime_env();
        assert!(!is_runtime_mode_enabled());

        crate::env::set_var(JCODE_SUBSCRIPTION_ACTIVE_ENV, "1");
        crate::env::set_var("JCODE_OPENROUTER_API_BASE", "https://example.invalid/v1");
        crate::env::set_var("JCODE_OPENROUTER_TRANSPORT_STATE", "jcode-subscription");
        apply_runtime_env();
        assert!(!is_runtime_mode_enabled());
        assert_eq!(
            std::env::var(JCODE_SUBSCRIPTION_ACTIVE_ENV).as_deref(),
            Ok("1")
        );
        assert_eq!(
            std::env::var("JCODE_OPENROUTER_API_BASE").as_deref(),
            Ok("https://example.invalid/v1")
        );
        assert_eq!(
            std::env::var("JCODE_OPENROUTER_TRANSPORT_STATE").as_deref(),
            Ok("jcode-subscription")
        );

        clear_runtime_env();
        assert!(!is_runtime_mode_enabled());
        assert_eq!(
            std::env::var(JCODE_SUBSCRIPTION_ACTIVE_ENV).as_deref(),
            Ok("1")
        );
        crate::env::remove_var(JCODE_SUBSCRIPTION_ACTIVE_ENV);
        crate::env::remove_var("JCODE_OPENROUTER_API_BASE");
        crate::env::remove_var("JCODE_OPENROUTER_TRANSPORT_STATE");
    }

    #[test]
    fn inherited_credential_entries_refuse_without_touching_the_fixture() {
        let _guard = crate::storage::lock_test_env();
        let temp = tempfile::tempdir().expect("temp home");
        crate::env::set_var("JCODE_HOME", temp.path().to_string_lossy().to_string());
        let sentinel = temp.path().join("sentinel");
        std::fs::write(&sentinel, b"unchanged").expect("seed sentinel");

        for error in [
            persist_account_credentials("secret", Some("account"), Some("a@example.invalid"), None)
                .expect_err("credential persistence must refuse"),
            clear_account_credentials().expect_err("credential clearing must refuse"),
            account_credential_path().expect_err("credential path lookup must refuse"),
            ensure_account_credential_permissions()
                .expect_err("credential permission mutation must refuse"),
        ] {
            assert_eq!(error.to_string(), INHERITED_SUBSCRIPTION_DISABLED_MESSAGE);
        }
        assert_eq!(
            std::fs::read(&sentinel).expect("read sentinel"),
            b"unchanged"
        );
        assert_eq!(
            std::fs::read_dir(temp.path())
                .expect("read fixture")
                .count(),
            1
        );
        crate::env::remove_var("JCODE_HOME");
    }
}
