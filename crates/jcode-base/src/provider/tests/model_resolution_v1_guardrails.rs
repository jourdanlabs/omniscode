#[test]
fn test_direct_chutes_ignores_legacy_openrouter_catalog_cache() {
    with_clean_provider_test_env(|| {
        let jcode_home = std::env::var_os("JCODE_HOME").expect("isolated JCODE_HOME");
        let cache_dir = std::path::PathBuf::from(jcode_home).join("cache");
        std::fs::create_dir_all(&cache_dir).expect("create cache dir");
        let cached_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_secs();
        std::fs::write(
            cache_dir.join("chutes_models.json"),
            serde_json::json!({
                "cached_at": cached_at,
                "models": [
                    { "id": "openai/gpt-chat-latest" },
                    { "id": "anthropic/claude-sonnet-latest" },
                    { "id": "openrouter/owl-alpha" }
                ]
            })
            .to_string(),
        )
        .expect("write legacy chutes cache");

        with_env_var("CHUTES_API_KEY", "test-chutes-key", || {
            let openrouter = external::instantiate_openrouter_runtime(
                external::OpenRouterRuntimeSpec::CompatibleProfile(
                    crate::provider_catalog::CHUTES_PROFILE,
                ),
            )
            .expect("explicit Chutes provider should initialize");
            let direct_route = openrouter
                .direct_openai_compatible_route_parts()
                .expect("Chutes should initialize as a direct profile");
            assert_eq!(direct_route.0, "Chutes");
            assert_eq!(direct_route.1, "openai-compatible:chutes");

            let display_models = openrouter.available_models_display();
            assert!(
                !display_models
                    .iter()
                    .any(|model| model == "openai/gpt-chat-latest"),
                "legacy source-less Chutes cache must not be trusted as a direct Chutes catalog: {display_models:?}"
            );

            let provider = MultiProvider {
                claude: RwLock::new(None),
                anthropic: RwLock::new(None),
                openai: RwLock::new(None),
                copilot_api: RwLock::new(None),
                antigravity: RwLock::new(None),
                gemini: RwLock::new(None),
                cursor: RwLock::new(None),
                bedrock: RwLock::new(None),
                openrouter: RwLock::new(Some(openrouter)),
                openai_compatible_profiles: RwLock::new(std::collections::HashMap::new()),
                active_openai_compatible_profile: RwLock::new(None),
                active: RwLock::new(ActiveProvider::OpenRouter),
                use_claude_cli: false,
                startup_notices: RwLock::new(Vec::new()),
                initial_provider: Some(ActiveProvider::OpenRouter),
                routes_memo: std::sync::Mutex::new(None),
                post_auth_refreshes_pending: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            };

            let routes = provider.model_routes();
            assert!(routes.iter().any(|route| {
                route.provider == "Chutes"
                    && route.api_method == "openai-compatible:chutes"
                    && route.available
            }));
            assert!(
                !routes.iter().any(|route| {
                    route.provider == "Chutes" && route.model == "openai/gpt-chat-latest"
                }),
                "stale OpenRouter catalog entries must not be relabeled as Chutes routes: {routes:?}"
            );
            assert!(
                !routes.iter().any(|route| {
                    route.api_method == "openrouter"
                        && matches!(route.provider.as_str(), "OpenAI" | "Anthropic")
                }),
                "direct Chutes profiles must not add OpenRouter fallback routes: {routes:?}"
            );
        })
    });
}
