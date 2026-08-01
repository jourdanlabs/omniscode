use crate::auth::{AuthState, AuthStatus};

use super::pricing::cheapness_for_route;
use super::{
    ALL_OPENAI_MODELS, AccountModelAvailabilityState, CHATGPT_WEB_MODEL, ModelRoute, MultiProvider,
    Provider, anthropic_api_key_route_availability, anthropic_oauth_route_availability, bedrock,
    build_anthropic_oauth_route, build_chatgpt_web_route, build_copilot_route,
    build_openai_oauth_route, build_openrouter_auto_route, build_openrouter_endpoint_route,
    build_openrouter_fallback_provider_route, dedupe_model_routes,
    format_account_model_availability_detail, is_listable_model_name,
    model_availability_for_account, openrouter, openrouter_catalog_model_id, provider_for_model,
};

/// Build the fast local route snapshot used by the TUI model picker while the
/// full provider catalog is hydrating.
///
/// This intentionally lives in the provider layer rather than the TUI so auth,
/// provider, and catalog policy have one source of truth. The TUI should only
/// group, sort, and render the returned routes.
pub fn simplified_model_routes_for_picker(
    current_provider_name: &str,
    current_model: &str,
    display_models: impl IntoIterator<Item = String>,
) -> Vec<ModelRoute> {
    let auth = AuthStatus::check_fast_nonblocking();
    let mut routes = Vec::new();

    for model in display_models {
        if model == CHATGPT_WEB_MODEL {
            routes.push(build_chatgpt_web_route());
            continue;
        }
        if !model.contains('/') && provider_for_model(&model) == Some("openai") {
            // Platform-API-only GPT Pro models: never advertise an OAuth route.
            if jcode_provider_core::is_openai_api_only_pro_model(&model) {
                routes.push(ModelRoute {
                    model: model.clone(),
                    provider: "OpenAI".to_string(),
                    api_method: "openai-api-key".to_string(),
                    available: auth.openai_has_api_key,
                    detail: if auth.openai_has_api_key {
                        String::new()
                    } else {
                        "requires OPENAI_API_KEY".to_string()
                    },
                    cheapness: None,
                });
                continue;
            }
            if auth.openai_has_oauth {
                routes.push(ModelRoute {
                    model: model.clone(),
                    provider: "OpenAI".to_string(),
                    api_method: "openai-oauth".to_string(),
                    available: true,
                    detail: String::new(),
                    cheapness: None,
                });
            }
            if auth.openai_has_api_key {
                routes.push(ModelRoute {
                    model: model.clone(),
                    provider: "OpenAI".to_string(),
                    api_method: "openai-api-key".to_string(),
                    available: true,
                    detail: String::new(),
                    cheapness: None,
                });
            }
            if auth.openai == AuthState::NotConfigured {
                routes.push(ModelRoute {
                    model,
                    provider: "OpenAI".to_string(),
                    api_method: "openai-oauth".to_string(),
                    available: false,
                    detail: "no credentials".to_string(),
                    cheapness: None,
                });
            }
            continue;
        }

        let (provider, api_method, available, detail) =
            if super::bedrock::BedrockProvider::is_bedrock_model_id(&model) {
                (
                    "AWS Bedrock".to_string(),
                    "bedrock".to_string(),
                    auth.bedrock != AuthState::NotConfigured,
                    if auth.bedrock == AuthState::NotConfigured {
                        "no Bedrock credentials or region; run /login bedrock".to_string()
                    } else {
                        String::new()
                    },
                )
            } else if model.contains('/') {
                (
                    "auto".to_string(),
                    "openrouter".to_string(),
                    auth.openrouter != AuthState::NotConfigured,
                    "simplified catalog".to_string(),
                )
            } else {
                match provider_for_model(&model) {
                    Some("claude") => {
                        append_simplified_anthropic_model_routes(&mut routes, model, &auth);
                        continue;
                    }
                    Some("openai") => unreachable!("OpenAI models are handled above"),
                    Some("gemini") => (
                        "Gemini".to_string(),
                        "code-assist-oauth".to_string(),
                        auth.gemini != AuthState::NotConfigured,
                        String::new(),
                    ),
                    Some("cursor") => (
                        "Cursor".to_string(),
                        "cursor".to_string(),
                        auth.cursor != AuthState::NotConfigured,
                        String::new(),
                    ),
                    Some("openrouter") => (
                        "auto".to_string(),
                        "openrouter".to_string(),
                        auth.openrouter != AuthState::NotConfigured,
                        "simplified catalog".to_string(),
                    ),
                    Some(other) => (other.to_string(), other.to_string(), true, String::new()),
                    None => (
                        current_provider_name.to_string(),
                        "current".to_string(),
                        true,
                        String::new(),
                    ),
                }
            };

        routes.push(ModelRoute {
            model,
            provider,
            api_method,
            available,
            detail,
            cheapness: None,
        });
    }

    if routes.is_empty() && !current_model.is_empty() && current_model != "unknown" {
        routes.push(ModelRoute {
            model: current_model.to_string(),
            provider: current_provider_name.to_string(),
            api_method: "current".to_string(),
            available: true,
            detail: "simplified catalog".to_string(),
            cheapness: None,
        });
    }

    routes
}

pub fn append_simplified_anthropic_model_routes(
    routes: &mut Vec<ModelRoute>,
    model: impl Into<String>,
    auth: &AuthStatus,
) {
    let model = model.into();
    if auth.anthropic.has_oauth {
        routes.push(ModelRoute {
            model: model.clone(),
            provider: "Anthropic".to_string(),
            api_method: "claude-oauth".to_string(),
            available: true,
            detail: String::new(),
            cheapness: None,
        });
    }
    if auth.anthropic.has_api_key {
        routes.push(ModelRoute {
            model: model.clone(),
            provider: "Anthropic".to_string(),
            api_method: "claude-api".to_string(),
            available: true,
            detail: String::new(),
            cheapness: None,
        });
    }
    if !auth.anthropic.has_oauth && !auth.anthropic.has_api_key {
        routes.push(ModelRoute {
            model,
            provider: "Anthropic".to_string(),
            api_method: "claude-oauth".to_string(),
            available: false,
            detail: "no credentials".to_string(),
            cheapness: None,
        });
    }
}

/// One coherent, in-memory view of the runtimes already installed in a
/// `MultiProvider`.
///
/// Route enumeration must not discover providers. In particular, it must not
/// consult credential stores, environment/config profiles, or external account
/// locations to decide which route families exist. Explicit login/auth refresh
/// paths own provider installation; this snapshot only renders those slots.
struct InitializedProviderSlots {
    claude: Option<std::sync::Arc<dyn Provider>>,
    anthropic: Option<std::sync::Arc<dyn Provider>>,
    openai: Option<std::sync::Arc<dyn Provider>>,
    copilot: Option<std::sync::Arc<dyn Provider>>,
    antigravity: Option<std::sync::Arc<dyn Provider>>,
    gemini: Option<std::sync::Arc<dyn Provider>>,
    cursor: Option<std::sync::Arc<dyn Provider>>,
    bedrock: Option<std::sync::Arc<bedrock::BedrockProvider>>,
    openrouter: Option<std::sync::Arc<dyn Provider>>,
    openai_compatible_profiles: Vec<(String, std::sync::Arc<dyn Provider>)>,
}

impl InitializedProviderSlots {
    fn capture(provider: &MultiProvider) -> Self {
        let mut openai_compatible_profiles = provider
            .openai_compatible_profiles
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|(profile, runtime)| (profile.clone(), std::sync::Arc::clone(runtime)))
            .collect::<Vec<_>>();
        openai_compatible_profiles.sort_by(|(left, _), (right, _)| left.cmp(right));

        Self {
            claude: provider.claude_provider(),
            anthropic: provider.anthropic_provider(),
            openai: provider.openai_provider(),
            copilot: provider.copilot_provider(),
            antigravity: provider.antigravity_provider(),
            gemini: provider.gemini_provider(),
            cursor: provider.cursor_provider(),
            bedrock: provider.bedrock_provider(),
            openrouter: provider.openrouter_provider(),
            openai_compatible_profiles,
        }
    }

    fn initialized_count(&self) -> usize {
        [
            self.claude.is_some(),
            self.anthropic.is_some(),
            self.openai.is_some(),
            self.copilot.is_some(),
            self.antigravity.is_some(),
            self.gemini.is_some(),
            self.cursor.is_some(),
            self.bedrock.is_some(),
            self.openrouter.is_some(),
        ]
        .into_iter()
        .filter(|initialized| *initialized)
        .count()
            + self.openai_compatible_profiles.len()
    }
}

/// Build the full multi-provider route catalog.
///
/// Orchestration only: each provider family contributes routes through its
/// own `append_*_routes` builder below, so provider-specific policy stays in
/// one place per provider instead of one 400-line function.
pub(super) fn multiprovider_model_routes(provider: &MultiProvider) -> Vec<ModelRoute> {
    let routes_started = std::time::Instant::now();
    let slots = InitializedProviderSlots::capture(provider);
    let mut routes = Vec::new();
    append_anthropic_routes(&slots, &mut routes);
    append_openai_routes(&slots, &mut routes);
    append_openai_compatible_profile_routes(&slots, &mut routes);
    append_copilot_routes(&slots, &mut routes);
    append_gemini_routes(&slots, &mut routes);
    append_antigravity_routes(&slots, &mut routes);
    append_cursor_routes(&slots, &mut routes);
    append_bedrock_routes(&slots, &mut routes);
    append_openrouter_routes(&slots, &mut routes);

    let total_ms = routes_started.elapsed().as_millis();
    if total_ms >= 250 {
        crate::logging::info(&format!(
            "[TIMING] model_routes: routes={}, initialized_provider_slots={}, total={}ms",
            routes.len(),
            slots.initialized_count(),
            total_ms,
        ));
    }

    let routes_before_filter = routes.len();

    // Drop obviously non-chat models (embeddings, speech, rerankers, etc.) that
    // some providers (Bedrock, OpenAI-compatible profiles like NVIDIA NIM / FPT
    // / Chutes) dump wholesale into their catalogs. Without this the picker is
    // flooded with hundreds of unusable entries.
    routes.retain(|route| is_listable_model_name(&route.model));

    let routes = dedupe_model_routes(routes);

    // Structured, always-on summary of catalog route building. This is the
    // single most useful line for the recurring "model picker empty / only
    // OpenAI+Anthropic appear / configured provider's models missing" reports
    // (issues #292, #268, #312, #304): it records which credentials were
    // detected and how many routes each provider contributed, so a shared log
    // explains exactly why a model was or was not offered. No secrets here.
    log_model_routes_summary("build", &routes, routes_before_filter, &slots, total_ms);

    routes
}

fn snapshot_models(runtime: &dyn Provider) -> Vec<String> {
    let static_models = runtime.available_models();
    if !static_models.is_empty() {
        return static_models.into_iter().map(str::to_string).collect();
    }

    let display_models = runtime.available_models_display();
    if !display_models.is_empty() {
        return display_models;
    }

    let current = runtime.model();
    if current.trim().is_empty() || current == "unknown" {
        Vec::new()
    } else {
        vec![current]
    }
}

fn dual_auth_snapshot_method(
    mode: jcode_provider_core::CredentialMode,
    oauth_method: &'static str,
    api_key_method: &'static str,
) -> &'static str {
    match mode {
        jcode_provider_core::CredentialMode::OAuth => oauth_method,
        jcode_provider_core::CredentialMode::ApiKey => api_key_method,
        // Auto is intentionally not resolved here. Resolving it would inspect
        // credential/account state; `current` preserves the initialized
        // runtime's own in-memory choice.
        jcode_provider_core::CredentialMode::Auto => "current",
    }
}

fn append_anthropic_runtime_routes(
    runtime: &dyn Provider,
    routes: &mut Vec<ModelRoute>,
    api_method: &str,
) {
    routes.extend(
        snapshot_models(runtime)
            .into_iter()
            .map(|model| ModelRoute {
                model,
                provider: "Anthropic".to_string(),
                api_method: api_method.to_string(),
                available: true,
                detail: String::new(),
                cheapness: None,
            }),
    );
}

/// Enumerate only Anthropic runtimes already installed in the snapshot.
fn append_anthropic_routes(slots: &InitializedProviderSlots, routes: &mut Vec<ModelRoute>) {
    if let Some(anthropic) = slots.anthropic.as_deref() {
        let api_method =
            dual_auth_snapshot_method(anthropic.credential_mode(), "claude-oauth", "claude-api");
        append_anthropic_runtime_routes(anthropic, routes, api_method);
    }
    if let Some(claude) = slots.claude.as_deref() {
        append_anthropic_runtime_routes(claude, routes, "current");
    }
}

/// Enumerate only the initialized OpenAI runtime. Account availability and
/// ambient OAuth/API-key state are deliberately outside this render path.
fn append_openai_routes(slots: &InitializedProviderSlots, routes: &mut Vec<ModelRoute>) {
    let Some(openai) = slots.openai.as_deref() else {
        return;
    };
    let api_method =
        dual_auth_snapshot_method(openai.credential_mode(), "openai-oauth", "openai-api-key");

    routes.extend(snapshot_models(openai).into_iter().map(|model| {
        if model == CHATGPT_WEB_MODEL {
            ModelRoute {
                model,
                provider: "OpenAI".to_string(),
                api_method: "chatgpt-web".to_string(),
                available: true,
                detail: String::new(),
                cheapness: None,
            }
        } else {
            ModelRoute {
                model,
                provider: "OpenAI".to_string(),
                api_method: api_method.to_string(),
                available: true,
                detail: String::new(),
                cheapness: None,
            }
        }
    }));
}

fn snapshot_runtime_routes(runtime: &dyn Provider) -> Vec<ModelRoute> {
    let mut runtime_routes = runtime.model_routes();
    for route in &mut runtime_routes {
        // Cheapness enrichment can consult auth/config/account state. Route
        // enumeration carries only the runtime's model/routing snapshot.
        route.cheapness = None;
    }
    runtime_routes
}

/// Enumerate direct profiles only after an explicit operation installed their
/// runtime. Configured-but-uninitialized profiles are intentionally absent.
fn append_openai_compatible_profile_routes(
    slots: &InitializedProviderSlots,
    routes: &mut Vec<ModelRoute>,
) {
    for (_, runtime) in &slots.openai_compatible_profiles {
        routes.extend(snapshot_runtime_routes(runtime.as_ref()));
    }
}

fn append_copilot_routes(slots: &InitializedProviderSlots, routes: &mut Vec<ModelRoute>) {
    let Some(copilot) = slots.copilot.as_deref() else {
        return;
    };
    let detail = copilot.model_catalog_detail();
    routes.extend(
        snapshot_models(copilot)
            .into_iter()
            .map(|model| ModelRoute {
                model,
                provider: "GitHub Copilot".to_string(),
                api_method: "copilot".to_string(),
                available: true,
                detail: detail.clone(),
                cheapness: None,
            }),
    );
}

fn append_gemini_routes(slots: &InitializedProviderSlots, routes: &mut Vec<ModelRoute>) {
    if let Some(gemini) = slots.gemini.as_deref() {
        routes.extend(snapshot_runtime_routes(gemini));
    }
}

fn append_antigravity_routes(slots: &InitializedProviderSlots, routes: &mut Vec<ModelRoute>) {
    if let Some(antigravity) = slots.antigravity.as_deref() {
        routes.extend(snapshot_runtime_routes(antigravity));
    }
}

fn append_cursor_routes(slots: &InitializedProviderSlots, routes: &mut Vec<ModelRoute>) {
    if let Some(cursor) = slots.cursor.as_deref() {
        routes.extend(snapshot_runtime_routes(cursor));
    }
}

fn append_bedrock_routes(slots: &InitializedProviderSlots, routes: &mut Vec<ModelRoute>) {
    if let Some(bedrock) = slots.bedrock.as_deref() {
        routes.extend(snapshot_runtime_routes(bedrock));
    }
}

fn append_openrouter_routes(slots: &InitializedProviderSlots, routes: &mut Vec<ModelRoute>) {
    let Some(openrouter) = slots.openrouter.as_deref() else {
        return;
    };
    let aggregator = openrouter.supports_provider_routing_features();
    routes.extend(
        snapshot_runtime_routes(openrouter)
            .into_iter()
            .map(|mut route| {
                if aggregator {
                    // "auto" means the installed OpenRouter aggregator chooses
                    // an endpoint. "OpenRouter" would be parsed as a provider
                    // pin by model selection.
                    route.provider = "auto".to_string();
                }
                route
            }),
    );
}

/// Count routes per provider label (lowercased, spaces removed) so the catalog
/// summary log shows where the picker entries came from.
fn provider_route_counts(routes: &[ModelRoute]) -> std::collections::BTreeMap<String, usize> {
    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for route in routes {
        let key = route.provider.trim().to_ascii_lowercase().replace(' ', "_");
        let key = if key.is_empty() {
            "unknown".to_string()
        } else {
            key
        };
        *counts.entry(key).or_insert(0) += 1;
    }
    counts
}

/// Emit a structured, non-secret summary from the same initialized-slot
/// snapshot used to build the routes.
fn log_model_routes_summary(
    phase: &str,
    routes: &[ModelRoute],
    routes_before_filter: usize,
    slots: &InitializedProviderSlots,
    total_ms: u128,
) {
    let available = routes.iter().filter(|route| route.available).count();
    let per_provider = provider_route_counts(routes)
        .into_iter()
        .map(|(provider, count)| format!("{provider}:{count}"))
        .collect::<Vec<_>>()
        .join(",");

    crate::logging::event_info(
        "model_routes_summary",
        vec![
            ("phase", phase.to_string()),
            ("routes_total", routes.len().to_string()),
            ("routes_available", available.to_string()),
            ("routes_before_filter", routes_before_filter.to_string()),
            (
                "routes_dropped",
                routes_before_filter
                    .saturating_sub(routes.len())
                    .to_string(),
            ),
            ("claude_initialized", slots.claude.is_some().to_string()),
            (
                "anthropic_initialized",
                slots.anthropic.is_some().to_string(),
            ),
            ("openai_initialized", slots.openai.is_some().to_string()),
            ("copilot_initialized", slots.copilot.is_some().to_string()),
            (
                "antigravity_initialized",
                slots.antigravity.is_some().to_string(),
            ),
            ("gemini_initialized", slots.gemini.is_some().to_string()),
            ("cursor_initialized", slots.cursor.is_some().to_string()),
            ("bedrock_initialized", slots.bedrock.is_some().to_string()),
            (
                "openrouter_initialized",
                slots.openrouter.is_some().to_string(),
            ),
            (
                "compatible_profiles_initialized",
                slots.openai_compatible_profiles.len().to_string(),
            ),
            ("by_provider", per_provider),
            ("build_ms", total_ms.to_string()),
        ],
    );
}

pub fn remote_model_routes_fallback(
    remote_provider_name: Option<&str>,
    remote_available_entries: &[String],
) -> Vec<ModelRoute> {
    if remote_provider_name.is_some_and(|name| {
        name.eq_ignore_ascii_case(crate::subscription_catalog::JCODE_PROVIDER_DISPLAY_NAME)
    }) {
        return Vec::new();
    }

    let auth = AuthStatus::check_fast_nonblocking();
    let mut routes = Vec::new();
    for model in remote_available_entries {
        if !is_listable_model_name(model) {
            continue;
        }

        let openrouter_catalog_model = openrouter_catalog_model_id(model);
        let openrouter_cached = openrouter_catalog_model
            .as_deref()
            .and_then(openrouter::load_endpoints_disk_cache_public);

        if super::bedrock::BedrockProvider::is_bedrock_model_id(model) {
            let available = auth.bedrock != AuthState::NotConfigured
                || super::bedrock::BedrockProvider::has_credentials();
            routes.push(ModelRoute {
                model: model.clone(),
                provider: "AWS Bedrock".to_string(),
                api_method: "bedrock".to_string(),
                available,
                detail: if available {
                    String::new()
                } else {
                    "no Bedrock credentials or region; run /login bedrock".to_string()
                },
                cheapness: None,
            });
            continue;
        }

        if model.contains('/') {
            let cached = openrouter_cached;
            let auto_detail = cached
                .as_ref()
                .and_then(|(eps, _)| eps.first().map(|ep| format!("→ {}", ep.provider_name)))
                .unwrap_or_default();
            routes.push(build_openrouter_auto_route(
                model,
                auth.openrouter != AuthState::NotConfigured,
                auto_detail,
            ));
            if let Some((endpoints, age)) = cached {
                let age_str = if age < 3600 {
                    format!("{}m ago", age / 60)
                } else if age < 86400 {
                    format!("{}h ago", age / 3600)
                } else {
                    format!("{}d ago", age / 86400)
                };
                for ep in &endpoints {
                    routes.push(build_openrouter_endpoint_route(
                        model,
                        ep,
                        auth.openrouter != AuthState::NotConfigured,
                        Some(&age_str),
                    ));
                }
            }
            continue;
        }

        let mut added_any = false;

        if provider_for_model(model) == Some("claude") {
            if auth.anthropic.has_oauth {
                let (available, detail) = anthropic_oauth_route_availability(model);
                routes.push(build_anthropic_oauth_route(model, available, detail));
                added_any = true;
            }
            // An Anthropic API key is an equally valid direct route. Without
            // this, a model that only reaches the picker via the names-only
            // fallback path (e.g. a newly released model whose detailed route
            // frame was oversized) shows an OAuth route but silently loses its
            // API-key route even though the key works.
            if auth.anthropic.has_api_key {
                let (available, detail) = anthropic_api_key_route_availability(model);
                routes.push(ModelRoute {
                    model: model.clone(),
                    provider: "Anthropic".to_string(),
                    api_method: "claude-api".to_string(),
                    available,
                    detail,
                    cheapness: cheapness_for_route(model, "Anthropic", "claude-api"),
                });
                added_any = true;
            }
        }

        if jcode_provider_core::model_id::matches_known_model(model, ALL_OPENAI_MODELS) {
            let availability = model_availability_for_account(model);
            let (available, detail) = if auth.openai == AuthState::NotConfigured {
                (false, "no credentials".to_string())
            } else {
                match availability.state {
                    AccountModelAvailabilityState::Available => (true, String::new()),
                    AccountModelAvailabilityState::Unavailable => (
                        false,
                        format_account_model_availability_detail(&availability)
                            .unwrap_or_else(|| "not available".to_string()),
                    ),
                    AccountModelAvailabilityState::Unknown => (
                        true,
                        format_account_model_availability_detail(&availability)
                            .unwrap_or_else(|| "availability unknown".to_string()),
                    ),
                }
            };
            routes.push(build_openai_oauth_route(model, available, detail));
            added_any = true;
        }

        if auth.openrouter != AuthState::NotConfigured {
            let catalog_lists_model = openrouter_catalog_model
                .as_deref()
                .and_then(openrouter::standard_catalog_lists_model);
            match (provider_for_model(model), openrouter_cached.as_ref()) {
                (_, Some((endpoints, _age))) => {
                    for ep in endpoints {
                        routes.push(build_openrouter_endpoint_route(model, ep, true, None));
                    }
                    added_any = true;
                }
                // Skip fallback routes for models the OpenRouter catalog
                // definitively does not list (e.g. gpt-5.3-codex-spark).
                (Some("claude"), None) if catalog_lists_model != Some(false) => {
                    routes.push(build_openrouter_fallback_provider_route(
                        model,
                        openrouter_catalog_model.as_deref().unwrap_or(model),
                        "Anthropic",
                    ));
                    added_any = true;
                }
                (Some("openai"), None) if catalog_lists_model != Some(false) => {
                    routes.push(build_openrouter_fallback_provider_route(
                        model,
                        openrouter_catalog_model.as_deref().unwrap_or(model),
                        "OpenAI",
                    ));
                    added_any = true;
                }
                _ => {}
            }
        }

        if let Some(route) = remote_openai_compatible_route_for_model(model) {
            routes.push(route);
            added_any = true;
        }

        if !added_any
            && let Some(route) =
                remote_current_openai_compatible_route_for_model(remote_provider_name, model)
        {
            routes.push(route);
            added_any = true;
        }

        if !added_any && remote_model_should_offer_copilot_route(model) && !model.contains("[1m]") {
            routes.push(build_copilot_route(
                model,
                auth.copilot == AuthState::Available || remote_model_is_server_copilot_only(model),
                String::new(),
            ));
            added_any = true;
        }

        if super::gemini::is_gemini_model_id(model) {
            routes.push(ModelRoute {
                model: model.clone(),
                provider: "Gemini".to_string(),
                api_method: "code-assist-oauth".to_string(),
                available: auth.gemini == AuthState::Available,
                detail: String::new(),
                cheapness: None,
            });
            added_any = true;
        }

        if !added_any {
            routes.push(ModelRoute {
                model: model.clone(),
                provider: "unknown".to_string(),
                api_method: "unknown".to_string(),
                available: false,
                detail: "no matching configured provider route".to_string(),
                cheapness: None,
            });
        }
    }
    routes
}

pub fn remote_model_routes_lightweight_fallback(
    remote_provider_name: Option<&str>,
    remote_available_entries: &[String],
    current_model: &str,
) -> Vec<ModelRoute> {
    if remote_provider_name.is_some_and(|name| {
        name.eq_ignore_ascii_case(crate::subscription_catalog::JCODE_PROVIDER_DISPLAY_NAME)
    }) {
        return Vec::new();
    }
    let provider = remote_provider_name
        .map(str::to_string)
        .unwrap_or_else(|| "remote".to_string());
    let mut routes = Vec::new();
    for model in remote_available_entries {
        if !is_listable_model_name(model) {
            continue;
        }
        routes.push(ModelRoute {
            model: model.clone(),
            provider: provider.clone(),
            api_method: "remote-catalog".to_string(),
            available: true,
            detail: "refreshing route details…".to_string(),
            cheapness: None,
        });
    }

    if routes.is_empty() && !current_model.is_empty() && current_model != "unknown" {
        routes.push(ModelRoute {
            model: current_model.to_string(),
            provider,
            api_method: "current".to_string(),
            available: true,
            detail: "refreshing model catalog…".to_string(),
            cheapness: None,
        });
    }

    routes
}

pub fn remote_current_openai_compatible_route_for_model(
    remote_provider_name: Option<&str>,
    model: &str,
) -> Option<ModelRoute> {
    if model.trim().is_empty() || model.contains('/') || provider_for_model(model).is_some() {
        return None;
    }

    let provider_name = remote_provider_name?.trim();
    let profile_id =
        crate::provider_catalog::openai_compatible_profile_id_for_display_name(provider_name)?;
    let profile = crate::provider_catalog::openai_compatible_profile_by_id(profile_id)?;
    if !crate::provider_catalog::openai_compatible_profile_is_configured(profile) {
        return None;
    }
    let resolved = crate::provider_catalog::resolve_openai_compatible_profile(profile);

    Some(ModelRoute {
        model: model.to_string(),
        provider: resolved.display_name,
        api_method: format!("openai-compatible:{}", resolved.id),
        available: true,
        detail: resolved.api_base,
        cheapness: None,
    })
}

pub fn remote_model_should_offer_copilot_route(model: &str) -> bool {
    remote_openai_compatible_route_for_model(model).is_none()
        && (remote_model_is_server_copilot_only(model)
            || super::copilot::is_known_display_model(model))
}

pub fn remote_openai_compatible_route_for_model(model: &str) -> Option<ModelRoute> {
    for profile in crate::provider_catalog::openai_compatible_profiles()
        .iter()
        .copied()
    {
        if !crate::provider_catalog::openai_compatible_profile_is_configured(profile) {
            continue;
        }
        let resolved = crate::provider_catalog::resolve_openai_compatible_profile(profile);
        let Some(from_live_catalog) = remote_openai_compatible_profile_models(&resolved, profile)
            .iter()
            .find_map(|candidate| (candidate.0 == model).then_some(candidate.1))
        else {
            continue;
        };
        let detail = if from_live_catalog {
            resolved.api_base.clone()
        } else if resolved.api_base.trim().is_empty() {
            "fallback: static provider model list".to_string()
        } else {
            format!(
                "{}; fallback: static provider model list",
                resolved.api_base
            )
        };
        return Some(ModelRoute {
            model: model.to_string(),
            provider: resolved.display_name,
            api_method: format!("openai-compatible:{}", resolved.id),
            available: true,
            detail,
            cheapness: None,
        });
    }
    None
}

fn remote_openai_compatible_profile_models(
    resolved: &crate::provider_catalog::ResolvedOpenAiCompatibleProfile,
    profile: crate::provider_catalog::OpenAiCompatibleProfile,
) -> Vec<(String, bool)> {
    let mut models = Vec::new();
    let mut push = |model: String, from_live_catalog: bool| {
        let model = model.trim().to_string();
        if !model.is_empty() && !models.iter().any(|(existing, _)| existing == &model) {
            models.push((model, from_live_catalog));
        }
    };

    if let Some(cache) =
        jcode_provider_openrouter::load_disk_cache_entry_for_namespace(&resolved.id)
    {
        let source_matches = cache
            .source_api_base
            .as_deref()
            .and_then(crate::provider_catalog::normalize_api_base)
            == crate::provider_catalog::normalize_api_base(&resolved.api_base);
        if source_matches {
            for model in cache.models {
                push(model.id, true);
            }
        }
    }

    for model in crate::provider_catalog::openai_compatible_profile_static_models(profile) {
        push(model, false);
    }

    models
}

pub fn remote_model_is_server_copilot_only(model: &str) -> bool {
    !model.is_empty()
        && !model.contains('/')
        && remote_openai_compatible_route_for_model(model).is_none()
        && !matches!(
            provider_for_model(model),
            Some("claude" | "openai" | "gemini" | "cursor")
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthState, ProviderAuth};

    struct EnvGuard {
        vars: Vec<(&'static str, Option<std::ffi::OsString>)>,
        _temp: tempfile::TempDir,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn new() -> Self {
            let lock = crate::storage::lock_test_env();
            let temp = tempfile::tempdir().expect("tempdir");
            let vars = vec![
                ("JCODE_HOME", std::env::var_os("JCODE_HOME")),
                ("OPENCODE_API_KEY", std::env::var_os("OPENCODE_API_KEY")),
            ];
            crate::env::set_var("JCODE_HOME", temp.path());
            crate::env::set_var("OPENCODE_API_KEY", "sk-test-opencode");
            Self {
                vars,
                _temp: temp,
                _lock: lock,
            }
        }

        fn save_opencode_cache(&self, source_api_base: &str, model_ids: &[&str]) {
            let jcode_home = std::env::var_os("JCODE_HOME").expect("JCODE_HOME set");
            let cache_dir = std::path::PathBuf::from(jcode_home).join("cache");
            std::fs::create_dir_all(&cache_dir).expect("create cache dir");
            let cache = jcode_provider_openrouter::DiskCache {
                cached_at: jcode_provider_openrouter::current_unix_secs()
                    .expect("current unix time"),
                source_api_base: Some(source_api_base.to_string()),
                models: model_ids
                    .iter()
                    .map(|id| jcode_provider_openrouter::ModelInfo {
                        id: (*id).to_string(),
                        name: String::new(),
                        context_length: None,
                        pricing: jcode_provider_openrouter::ModelPricing::default(),
                        created: None,
                    })
                    .collect(),
            };
            std::fs::write(
                cache_dir.join("opencode_models.json"),
                serde_json::to_string(&cache).expect("serialize cache"),
            )
            .expect("write cache");
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in self.vars.drain(..) {
                if let Some(value) = value {
                    crate::env::set_var(key, value);
                } else {
                    crate::env::remove_var(key);
                }
            }
        }
    }

    #[test]
    fn simplified_anthropic_routes_preserve_oauth_vs_api_key_state_space() {
        for (has_oauth, has_api_key, expected_methods) in [
            (true, false, vec!["claude-oauth"]),
            (false, true, vec!["claude-api"]),
            (true, true, vec!["claude-oauth", "claude-api"]),
            (false, false, vec!["claude-oauth"]),
        ] {
            let auth = AuthStatus {
                anthropic: ProviderAuth {
                    state: if has_oauth || has_api_key {
                        AuthState::Available
                    } else {
                        AuthState::NotConfigured
                    },
                    has_oauth,
                    oauth_state: if has_oauth {
                        AuthState::Available
                    } else {
                        AuthState::NotConfigured
                    },
                    has_api_key,
                },
                ..AuthStatus::default()
            };
            let mut routes = Vec::new();

            append_simplified_anthropic_model_routes(
                &mut routes,
                "claude-opus-4-6".to_string(),
                &auth,
            );

            let methods = routes
                .iter()
                .map(|route| route.api_method.as_str())
                .collect::<Vec<_>>();
            assert_eq!(
                methods, expected_methods,
                "oauth={has_oauth} api={has_api_key}"
            );
            assert!(routes.iter().all(|route| route.provider == "Anthropic"));
            assert_eq!(
                routes.iter().all(|route| route.available),
                has_oauth || has_api_key
            );
        }
    }

    #[test]
    fn remote_compatible_route_uses_live_cache_and_does_not_mark_fallback() {
        let guard = EnvGuard::new();
        guard.save_opencode_cache("https://opencode.ai/zen/v1", &["qwen3.6-plus"]);

        let route = remote_openai_compatible_route_for_model("qwen3.6-plus")
            .expect("live-cache-only OpenCode model should be routed");

        assert_eq!(route.provider, "OpenCode Zen");
        assert_eq!(route.api_method, "openai-compatible:opencode");
        assert_eq!(route.detail, "https://opencode.ai/zen/v1");
        assert!(!route.detail.contains("fallback"));
    }

    #[test]
    fn remote_compatible_route_marks_static_model_list_fallback() {
        let _guard = EnvGuard::new();

        let route = remote_openai_compatible_route_for_model("glm-4.7")
            .expect("static OpenCode fallback model should be routed");

        assert_eq!(route.provider, "OpenCode Zen");
        assert!(
            route
                .detail
                .contains("fallback: static provider model list")
        );
    }

    #[test]
    fn remote_compatible_route_ignores_live_cache_from_wrong_api_base() {
        let guard = EnvGuard::new();
        guard.save_opencode_cache("https://wrong.example.test/v1", &["qwen3.6-plus"]);

        assert!(remote_openai_compatible_route_for_model("qwen3.6-plus").is_none());
    }
}
