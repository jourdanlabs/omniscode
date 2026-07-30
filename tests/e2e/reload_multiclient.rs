//! Release-V1 quarantine tests for the inherited server-reload surface.

use crate::test_support::*;

async fn assert_reload_is_refused(force: bool, label: &str) -> Result<()> {
    let _env = setup_test_env()?;
    let runtime_dir = short_runtime_dir(format!(
        "jcode-reload-refusal-{label}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(&runtime_dir)?;
    let socket_path = runtime_dir.join("jcode.sock");
    let debug_socket_path = runtime_dir.join("jcode-debug.sock");

    let provider: Arc<dyn Provider> = Arc::new(MockProvider::new());
    let server_instance =
        server::Server::new_with_paths(provider, socket_path.clone(), debug_socket_path.clone());
    let server_handle = tokio::spawn(async move { server_instance.run().await });
    wait_for_socket(&socket_path).await?;

    let result = async {
        let mut client = server::Client::connect_with_path(socket_path.clone()).await?;
        let error = client
            .reload_with_force(force)
            .await
            .expect_err("the inherited reload surface must refuse");
        assert_eq!(
            error.to_string(),
            jcode::update::UPDATE_DISABLED_MESSAGE,
            "reload refusal must use the frozen public message"
        );
        assert!(
            !server::reload_marker_active(Duration::from_secs(30)),
            "a refused reload must not create an active reload marker"
        );

        // Refusal happens before a reload request is written. The server must
        // remain available for an independent local connection.
        let _second = server::Client::connect_with_path(socket_path.clone()).await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;

    server::clear_reload_marker();
    abort_server_and_cleanup(&server_handle, &socket_path, &debug_socket_path);
    result
}

#[tokio::test]
async fn inherited_forced_reload_is_refused_before_server_mutation() -> Result<()> {
    assert_reload_is_refused(true, "forced").await
}

#[tokio::test]
async fn inherited_conditional_reload_is_refused_before_server_mutation() -> Result<()> {
    assert_reload_is_refused(false, "conditional").await
}
