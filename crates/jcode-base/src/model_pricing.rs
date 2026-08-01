//! Optional cached model pricing catalog.
//!
//! jcode's static pricing tables (`jcode_provider_core::pricing`) only cover
//! first-party Anthropic/OpenAI models and go stale whenever a provider ships
//! new models or changes prices. models.dev publishes a free, no-auth JSON
//! catalog (`https://models.dev/api.json`) with per-model `input`/`output`/
//! `cache_read`/`cache_write` USD prices per million tokens across 140+
//! providers, including every OpenAI-compatible profile jcode ships.
//!
//! This distribution treats the disk cache as read-only. A lookup never
//! schedules a network request or writes state when the cache is missing or
//! stale.
//!
//! Lookup order for callers is curated static table first (exact, reviewed),
//! then this catalog, then provider-specific sources (OpenRouter endpoints),
//! and only then a generic fallback.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const CACHE_FILE: &str = "models_dev_pricing.json";
const CACHE_TTL_SECS: u64 = 24 * 60 * 60;

/// Per-model USD prices per million tokens.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ModelCost {
    pub input_usd_per_mtok: f64,
    pub output_usd_per_mtok: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_read_usd_per_mtok: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_write_usd_per_mtok: Option<f64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PricingCache {
    cached_at_unix_secs: u64,
    /// provider id -> model id -> cost. Provider ids are models.dev ids
    /// (e.g. `anthropic`, `openai`, `deepseek`, `moonshotai`).
    providers: HashMap<String, HashMap<String, ModelCost>>,
}

/// In-memory pricing cache keyed by the on-disk cache path it was loaded
/// from, so changing `JCODE_HOME` (tests, multi-home setups) never serves
/// pricing that belongs to a different home directory.
///
/// Held behind an `Arc` so per-route pricing lookups share one parsed catalog
/// instead of deep-cloning the multi-thousand-model map on every call (that
/// clone dominated server CPU during client connect bursts).
static MEMORY_CACHE: Mutex<Option<(PathBuf, Arc<PricingCache>)>> = Mutex::new(None);

fn cache_path() -> PathBuf {
    crate::storage::jcode_dir()
        .unwrap_or_else(|_| PathBuf::from(".").join(".jcode"))
        .join("cache")
        .join(CACHE_FILE)
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn load_cache() -> Option<Arc<PricingCache>> {
    let path = cache_path();
    {
        let memory = MEMORY_CACHE.lock().ok()?;
        if let Some((cached_path, cache)) = memory.as_ref()
            && cached_path == &path
        {
            return Some(Arc::clone(cache));
        }
    }
    let cache: PricingCache = crate::storage::read_json(&path).ok()?;
    let cache = Arc::new(cache);
    if let Ok(mut memory) = MEMORY_CACHE.lock() {
        *memory = Some((path, Arc::clone(&cache)));
    }
    Some(cache)
}

#[cfg(test)]
fn save_cache(cache: &PricingCache) {
    let path = cache_path();
    if let Ok(mut memory) = MEMORY_CACHE.lock() {
        *memory = Some((path.clone(), Arc::new(cache.clone())));
    }
    let _ = crate::storage::write_json(&path, cache);
}

/// Translate a jcode provider key (runtime key, activity source key, or
/// compatible-profile id) to the models.dev provider id.
pub fn models_dev_provider_id(jcode_provider: &str) -> Option<&'static str> {
    let key = jcode_provider
        .trim()
        .strip_prefix("openai-compatible:")
        .unwrap_or_else(|| jcode_provider.trim());
    Some(match key {
        "anthropic" | "claude" | "claude:api-key" | "anthropic-api" => "anthropic",
        "openai" | "openai:api-key" | "openai-api" => "openai",
        "openrouter" => "openrouter",
        "opencode" => "opencode",
        "opencode-go" => "opencode-go",
        "deepseek" => "deepseek",
        "moonshotai" => "moonshotai",
        "kimi" => "kimi-for-coding",
        "zai" => "zai",
        "cerebras" => "cerebras",
        "groq" => "groq",
        "mistral" => "mistral",
        "xai" => "xai",
        "minimax" => "minimax",
        "togetherai" => "togetherai",
        "fireworks" => "fireworks-ai",
        "deepinfra" => "deepinfra",
        "perplexity" => "perplexity",
        "nebius" => "nebius",
        "scaleway" => "scaleway",
        "stackit" => "stackit",
        "huggingface" => "huggingface",
        "baseten" => "baseten",
        "chutes" => "chutes",
        "nvidia-nim" => "nvidia",
        "302ai" => "302ai",
        "cortecs" => "cortecs",
        "alibaba-coding-plan" => "alibaba",
        "bedrock" => "amazon-bedrock",
        "azure-openai" | "azure" => "azure",
        "gemini" | "gemini-api" => "google",
        _ => return None,
    })
}

/// Strip jcode-local suffixes/prefixes a model id may carry before catalog
/// lookup (`[1m]` long-context alias, `provider/` prefixes for OpenRouter ids).
fn normalize_model_id(model: &str) -> &str {
    jcode_provider_core::model_id::strip_long_context_suffix(model).trim()
}

/// Look up cached pricing for `model` under a jcode provider key. Returns
/// `None` when the local cache has no entry; never blocks on or schedules
/// network work.
pub fn lookup(jcode_provider: &str, model: &str) -> Option<ModelCost> {
    let provider_id = models_dev_provider_id(jcode_provider)?;
    let cache = ensure_cache_fresh()?;
    let models = cache.providers.get(provider_id)?;
    let model = normalize_model_id(model);
    if let Some(cost) = models.get(model) {
        return Some(*cost);
    }
    // OpenRouter-style ids (`anthropic/claude-...`) may reach here with the
    // provider prefix still attached; retry on the bare model name.
    if let Some((_, bare)) = model.rsplit_once('/') {
        return models.get(bare).copied();
    }
    None
}

/// Return the available cache without scheduling ambient discovery.
fn ensure_cache_fresh() -> Option<Arc<PricingCache>> {
    let cache = load_cache();
    let _stale = cache
        .as_ref()
        .map(|c| now_unix_secs().saturating_sub(c.cached_at_unix_secs) >= CACHE_TTL_SECS)
        .unwrap_or(true);
    cache
}

/// Compatibility entry retained for callers; ambient refresh is disabled.
pub fn schedule_refresh() {
    // Intentionally inert.
}

#[cfg(test)]
fn parse_api_response(body: &str) -> anyhow::Result<PricingCache> {
    let json: serde_json::Value = serde_json::from_str(body)?;
    let top = json
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("expected top-level provider object"))?;

    let mut providers: HashMap<String, HashMap<String, ModelCost>> = HashMap::new();
    for (provider_id, provider) in top {
        let Some(models) = provider.get("models").and_then(|m| m.as_object()) else {
            continue;
        };
        let mut parsed_models = HashMap::new();
        for (model_id, model) in models {
            let Some(cost) = model.get("cost") else {
                continue;
            };
            let (Some(input), Some(output)) = (
                cost.get("input").and_then(|v| v.as_f64()),
                cost.get("output").and_then(|v| v.as_f64()),
            ) else {
                continue;
            };
            parsed_models.insert(
                model_id.clone(),
                ModelCost {
                    input_usd_per_mtok: input,
                    output_usd_per_mtok: output,
                    cache_read_usd_per_mtok: cost.get("cache_read").and_then(|v| v.as_f64()),
                    cache_write_usd_per_mtok: cost.get("cache_write").and_then(|v| v.as_f64()),
                },
            );
        }
        if !parsed_models.is_empty() {
            providers.insert(provider_id.clone(), parsed_models);
        }
    }

    if providers.is_empty() {
        anyhow::bail!("no priced models in models.dev response");
    }
    Ok(PricingCache {
        cached_at_unix_secs: now_unix_secs(),
        providers,
    })
}

#[cfg(test)]
pub(crate) fn save_test_cache(entries: &[(&str, &str, ModelCost)]) {
    let mut providers: HashMap<String, HashMap<String, ModelCost>> = HashMap::new();
    for (provider, model, cost) in entries {
        providers
            .entry((*provider).to_string())
            .or_default()
            .insert((*model).to_string(), *cost);
    }
    save_cache(&PricingCache {
        cached_at_unix_secs: now_unix_secs(),
        providers,
    });
}

#[cfg(test)]
pub(crate) fn clear_memory_cache_for_tests() {
    if let Ok(mut memory) = MEMORY_CACHE.lock() {
        *memory = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_models_dev_shape() {
        let body = r#"{
            "deepseek": {
                "id": "deepseek",
                "models": {
                    "deepseek-v4-flash": {
                        "cost": {"input": 0.14, "output": 0.28, "cache_read": 0.0028}
                    },
                    "free-model": {"cost": {"input": 0, "output": 0}},
                    "no-cost-model": {}
                }
            },
            "anthropic": {
                "models": {
                    "claude-fable-5": {
                        "cost": {"input": 10, "output": 50, "cache_read": 1, "cache_write": 12.5}
                    }
                }
            }
        }"#;
        let cache = parse_api_response(body).expect("parsed");
        let deepseek = cache.providers.get("deepseek").expect("deepseek");
        assert_eq!(deepseek.len(), 2, "model without cost is skipped");
        let flash = deepseek.get("deepseek-v4-flash").expect("flash");
        assert!((flash.input_usd_per_mtok - 0.14).abs() < 1e-9);
        assert!((flash.output_usd_per_mtok - 0.28).abs() < 1e-9);
        assert_eq!(flash.cache_read_usd_per_mtok, Some(0.0028));
        assert_eq!(flash.cache_write_usd_per_mtok, None);

        let fable = cache
            .providers
            .get("anthropic")
            .and_then(|m| m.get("claude-fable-5"))
            .expect("fable");
        assert!((fable.input_usd_per_mtok - 10.0).abs() < 1e-9);
        assert_eq!(fable.cache_write_usd_per_mtok, Some(12.5));
    }

    #[test]
    fn rejects_empty_response() {
        assert!(parse_api_response("{}").is_err());
        assert!(parse_api_response("[]").is_err());
    }

    #[test]
    fn provider_key_mapping_covers_jcode_providers() {
        assert_eq!(models_dev_provider_id("claude:api-key"), Some("anthropic"));
        assert_eq!(models_dev_provider_id("openai:api-key"), Some("openai"));
        assert_eq!(
            models_dev_provider_id("openai-compatible:deepseek"),
            Some("deepseek")
        );
        assert_eq!(
            models_dev_provider_id("openai-compatible:nvidia-nim"),
            Some("nvidia")
        );
        assert_eq!(models_dev_provider_id("bedrock"), Some("amazon-bedrock"));
        assert_eq!(models_dev_provider_id("unknown-thing"), None);
    }

    #[test]
    fn lookup_normalizes_model_ids() {
        let _guard = crate::storage::lock_test_env();
        let temp = tempfile::tempdir().expect("tempdir");
        let prev_home = std::env::var_os("JCODE_HOME");
        crate::env::set_var("JCODE_HOME", temp.path());
        clear_memory_cache_for_tests();

        save_test_cache(&[
            (
                "anthropic",
                "claude-opus-4-6",
                ModelCost {
                    input_usd_per_mtok: 5.0,
                    output_usd_per_mtok: 25.0,
                    cache_read_usd_per_mtok: Some(0.5),
                    cache_write_usd_per_mtok: Some(6.25),
                },
            ),
            (
                "openrouter",
                "kimi-k2",
                ModelCost {
                    input_usd_per_mtok: 0.5,
                    output_usd_per_mtok: 2.0,
                    cache_read_usd_per_mtok: None,
                    cache_write_usd_per_mtok: None,
                },
            ),
        ]);

        // [1m] suffix strips before lookup.
        let opus = lookup("claude:api-key", "claude-opus-4-6[1m]").expect("priced");
        assert!((opus.input_usd_per_mtok - 5.0).abs() < 1e-9);

        // provider/model ids fall back to the bare model name.
        let kimi = lookup("openrouter", "moonshotai/kimi-k2").expect("priced");
        assert!((kimi.output_usd_per_mtok - 2.0).abs() < 1e-9);

        assert!(lookup("claude:api-key", "claude-unknown").is_none());

        clear_memory_cache_for_tests();
        if let Some(prev) = prev_home {
            crate::env::set_var("JCODE_HOME", prev);
        } else {
            crate::env::remove_var("JCODE_HOME");
        }
    }

    #[tokio::test]
    async fn missing_pricing_lookup_and_refresh_entry_is_zero_write() {
        let temp = tempfile::tempdir().expect("temp home");
        let previous = {
            let _guard = crate::storage::lock_test_env();
            let previous = std::env::var_os("JCODE_HOME");
            crate::env::set_var("JCODE_HOME", temp.path().to_string_lossy().to_string());
            let sentinel = temp.path().join("sentinel");
            std::fs::write(&sentinel, b"unchanged").expect("seed sentinel");
            clear_memory_cache_for_tests();
            assert!(lookup("openrouter", "unknown-model").is_none());
            schedule_refresh();
            previous
            // drop test-env lock before await (clippy::await_holding_lock)
        };
        let sentinel = temp.path().join("sentinel");
        tokio::task::yield_now().await;

        assert_eq!(
            std::fs::read(&sentinel).expect("read sentinel"),
            b"unchanged"
        );
        assert_eq!(
            std::fs::read_dir(temp.path())
                .expect("read fixture")
                .count(),
            1,
            "cache miss must not create a cache directory or pricing file"
        );
        clear_memory_cache_for_tests();
        if let Some(previous) = previous {
            crate::env::set_var("JCODE_HOME", previous);
        } else {
            crate::env::remove_var("JCODE_HOME");
        }
    }
}
