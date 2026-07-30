#[test]
fn inherited_jcode_auth_protocol_aliases_and_metadata_are_rejected() {
    for alias in ["jcode", "subscription", "jcode-subscription"] {
        assert!(auth_surface::requests_disabled_jcode_auth(
            Some(alias),
            None
        ));
        assert!(auth_surface::requests_disabled_jcode_auth(
            None,
            Some(&AuthChanged::new(alias))
        ));
    }

    let mut metadata_only = AuthChanged::new("openai");
    metadata_only.expected_runtime = Some(crate::protocol::RuntimeProviderKey::new("jcode"));
    assert!(auth_surface::requests_disabled_jcode_auth(
        None,
        Some(&metadata_only)
    ));

    let mut namespace_only = AuthChanged::new("openai");
    namespace_only.expected_catalog_namespace =
        Some(crate::protocol::CatalogNamespace::new("jcode-subscription"));
    assert!(auth_surface::requests_disabled_jcode_auth(
        None,
        Some(&namespace_only)
    ));
    assert!(!auth_surface::requests_disabled_jcode_auth(
        Some("openai"),
        None
    ));
}

#[tokio::test]
async fn raw_set_route_refuses_jcode_subscription_without_mutation_or_write() {
    let _guard = EnvGuard::save(&[]);
    let concrete = Arc::new(AuthChangeMockProvider::new());
    let state = Arc::clone(&concrete.state);
    let provider: Arc<dyn Provider> = concrete;
    let agent = Arc::new(Mutex::new(Agent::new(provider, Registry::empty())));
    let (session_id, provider_key_before, route_before, model_before) = {
        let agent = agent.lock().await;
        (
            agent.session_id().to_string(),
            agent.session_provider_key(),
            agent.session_route_api_method(),
            agent.provider_model(),
        )
    };
    let session_path = crate::session::session_path(&session_id).expect("session path");
    let journal_path = crate::session::session_journal_path(&session_id).expect("journal path");
    let session_bytes_before = std::fs::read(&session_path).ok();
    let journal_bytes_before = std::fs::read(&journal_path).ok();

    let raw = r#"{"type":"set_route","id":91,"selection":{"model":"hostile-model","runtime_key":{"kind":"jcode-subscription"},"api_method":"jcode-subscription","provider_label":"Jcode Subscription","detail":""}}"#;
    let request = crate::protocol::decode_request(raw).expect("raw structured route request");
    let crate::protocol::Request::SetRoute { id, selection } = request else {
        panic!("expected structured SetRoute request");
    };
    let (client_event_tx, mut client_event_rx) = mpsc::unbounded_channel();
    handle_set_route(id, selection, &agent, &client_event_tx).await;

    assert!(matches!(
        client_event_rx.recv().await,
        Some(ServerEvent::ModelChanged {
            id: 91,
            model,
            provider_name: None,
            error: Some(error),
        }) if model == model_before
            && error == crate::subscription_catalog::INHERITED_SUBSCRIPTION_DISABLED_MESSAGE
    ));
    assert_eq!(
        state.selected_model.read().unwrap().as_deref(),
        None,
        "provider set_model must not run"
    );
    let agent = agent.lock().await;
    assert_eq!(agent.provider_model(), model_before);
    assert_eq!(agent.session_provider_key(), provider_key_before);
    assert_eq!(agent.session_route_api_method(), route_before);
    assert_eq!(
        std::fs::read(&session_path).ok(),
        session_bytes_before,
        "hostile SetRoute changed the session file"
    );
    assert_eq!(
        std::fs::read(&journal_path).ok(),
        journal_bytes_before,
        "hostile SetRoute changed the session journal"
    );
}

#[test]
fn hostile_persisted_session_route_never_reaches_provider_or_disk() {
    let _guard = EnvGuard::save(&[]);
    let concrete = Arc::new(AuthChangeMockProvider::new());
    let state = Arc::clone(&concrete.state);
    let provider: Arc<dyn Provider> = concrete;
    let mut session = crate::session::Session::create(None, None);
    session.model = Some("hostile-model".to_string());
    session.provider_key = Some("jcode-subscription".to_string());
    session.route_api_method = Some("JCODE_SUBSCRIPTION".to_string());
    let session_path = crate::session::session_path(&session.id).expect("session path");
    let journal_path = crate::session::session_journal_path(&session.id).expect("journal path");
    session.save().expect("persist hostile fixture");
    let session_bytes_before = std::fs::read(&session_path).ok();
    let journal_bytes_before = std::fs::read(&journal_path).ok();

    let error = crate::provider::MultiProvider::model_switch_request_for_session_route(
        session.model.as_deref().expect("model"),
        session.provider_key.as_deref(),
        session.route_api_method.as_deref(),
    )
    .expect_err("hostile persisted route must refuse");
    assert_eq!(
        error.to_string(),
        crate::subscription_catalog::INHERITED_SUBSCRIPTION_DISABLED_MESSAGE
    );
    assert_eq!(
        std::fs::read(&session_path).ok(),
        session_bytes_before,
        "hostile persisted route refusal changed the session file"
    );
    assert_eq!(
        std::fs::read(&journal_path).ok(),
        journal_bytes_before,
        "hostile persisted route refusal changed the session journal"
    );

    let agent = Agent::new_with_session(provider, Registry::empty(), session, None);
    assert_eq!(
        state.selected_model.read().unwrap().as_deref(),
        None,
        "persisted route reconstruction called provider set_model"
    );
    assert_eq!(agent.provider_model(), "logged-out-model");
    assert_eq!(
        agent.session_provider_key().as_deref(),
        Some("jcode-subscription")
    );
    assert_eq!(
        agent.session_route_api_method().as_deref(),
        Some("JCODE_SUBSCRIPTION")
    );
}
