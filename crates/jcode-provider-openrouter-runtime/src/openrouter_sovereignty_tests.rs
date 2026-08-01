use super::*;

#[test]
fn ambient_catalog_entry_points_make_zero_network_attempts_and_zero_writes() {
    let _lock = ENV_LOCK.lock();
    let temp = TempDir::new().expect("create temp home");
    let jcode_home = temp.path().join("jcode-home");
    std::fs::create_dir_all(&jcode_home).expect("create jcode home");
    let sentinel = jcode_home.join("credential-sentinel.json");
    std::fs::write(&sentinel, b"do-not-touch").expect("write sentinel");
    let _home = EnvVarGuard::set("HOME", temp.path());
    let _appdata = EnvVarGuard::set("APPDATA", temp.path().join("AppData").join("Roaming"));
    let _jcode_home = EnvVarGuard::set("JCODE_HOME", &jcode_home);
    let _api_key = EnvVarGuard::set("OPENROUTER_API_KEY", "hostile-present-key");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind attempt detector");
    listener
        .set_nonblocking(true)
        .expect("set attempt detector nonblocking");
    let api_base = format!(
        "http://{}",
        listener.local_addr().expect("listener address")
    );
    let provider = OpenRouterProvider {
        api_base,
        model: Arc::new(RwLock::new("ambient-test-model".to_string())),
        ..make_provider()
    };

    let profile = jcode_base::provider_catalog::openai_compatible_profiles()
        .first()
        .copied()
        .expect("at least one compatible profile");
    assert!(!maybe_schedule_openai_compatible_profile_catalog_refresh(
        profile,
        "ambient test"
    ));
    assert!(!maybe_schedule_standard_openrouter_catalog_refresh(
        "ambient test"
    ));
    assert!(!provider.maybe_schedule_endpoint_refresh_for_display(
        "ambient-test-model",
        None,
        "ambient test"
    ));

    let _models = provider.available_models_display();
    let _providers = provider.available_providers_for_model("ambient-test-model");
    let _details = provider.provider_details_for_model("ambient-test-model");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async {
        assert!(
            provider
                .fetch_models()
                .await
                .expect("cached model read")
                .is_empty()
        );
        assert!(
            provider
                .fetch_endpoints("ambient-test-model")
                .await
                .expect("cached endpoint read")
                .is_empty()
        );
        provider
            .prefetch_models()
            .await
            .expect("inert provider prefetch");
        tokio::task::yield_now().await;
    });

    assert!(
        matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ),
        "an ambient catalog path attempted a network connection"
    );
    assert_eq!(
        std::fs::read(&sentinel).expect("read preserved sentinel"),
        b"do-not-touch"
    );
    assert_eq!(
        std::fs::read_dir(&jcode_home)
            .expect("read jcode home")
            .count(),
        1,
        "ambient catalog paths must not create cache or credential files"
    );
}
