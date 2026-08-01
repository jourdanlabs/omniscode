use super::{App, DisplayMessage};

const REMOTE_PAIRING_DISABLED: &str = "OMNIS_KEY_INHERITED_SURFACE_DISABLED: inherited Jcode pairing behavior is disabled in OMNIS KEY Local Integrity V1";

fn claims_remote_command(input: &str) -> bool {
    let Some(rest) = input.strip_prefix("/remote") else {
        return false;
    };
    rest.is_empty() || rest.chars().next().is_some_and(char::is_whitespace)
}

pub(super) fn handle_remote_command(app: &mut App, trimmed: &str) -> bool {
    if !claims_remote_command(trimmed) {
        return false;
    }

    // V1 ships no remote client application. Intercept every inherited
    // `/remote` spelling before config, gateway status, device-registry, QR,
    // or pairing-code logic can run.
    app.push_display_message(DisplayMessage::error(REMOTE_PAIRING_DISABLED.to_string()));
    app.set_status_notice("Remote pairing disabled in OMNIS KEY V1");
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::Provider;
    use anyhow::Result;
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::sync::Arc;

    struct MockProvider;

    #[async_trait::async_trait]
    impl Provider for MockProvider {
        async fn complete(
            &self,
            _messages: &[crate::message::Message],
            _tools: &[crate::message::ToolDefinition],
            _system: &str,
            _resume_session_id: Option<&str>,
        ) -> Result<crate::provider::EventStream> {
            Err(anyhow::anyhow!(
                "disabled remote-pairing tests must not call a provider"
            ))
        }

        fn name(&self) -> &str {
            "mock"
        }

        fn fork(&self) -> Arc<dyn Provider> {
            Arc::new(Self)
        }
    }

    fn snapshot_tree(root: &Path) -> BTreeMap<String, Option<Vec<u8>>> {
        fn walk(root: &Path, directory: &Path, out: &mut BTreeMap<String, Option<Vec<u8>>>) {
            let mut entries = std::fs::read_dir(directory)
                .expect("read snapshot directory")
                .collect::<std::io::Result<Vec<_>>>()
                .expect("collect snapshot directory");
            entries.sort_by_key(std::fs::DirEntry::file_name);
            for entry in entries {
                let path = entry.path();
                let relative = path
                    .strip_prefix(root)
                    .expect("snapshot path under root")
                    .to_string_lossy()
                    .into_owned();
                if entry.file_type().expect("snapshot file type").is_dir() {
                    out.insert(relative, None);
                    walk(root, &path, out);
                } else {
                    out.insert(
                        relative,
                        Some(std::fs::read(path).expect("read snapshot file")),
                    );
                }
            }
        }

        let mut out = BTreeMap::new();
        walk(root, root, &mut out);
        out
    }

    #[test]
    fn remote_refusal_claims_only_the_exact_command_family() {
        for command in [
            "/remote",
            "/remote status",
            "/remote on",
            "/remote off",
            "/remote pair",
            "/remote revoke fixture-device",
            "/remote\tpair",
        ] {
            assert!(claims_remote_command(command), "{command}");
        }
        for other in ["/remote-release", "/remote-skill", "/remotely", "/remot"] {
            assert!(!claims_remote_command(other), "{other}");
        }
    }

    #[test]
    fn every_remote_subcommand_refuses_without_touching_pairing_state() {
        let _guard = crate::storage::lock_test_env();
        let previous_home = std::env::var_os("JCODE_HOME");
        let previous_deferred = std::env::var_os("JCODE_DEFERRED_AUTH_BOOTSTRAP");
        let temp = tempfile::tempdir().expect("create pairing-refusal fixture");
        crate::env::set_var("JCODE_HOME", temp.path());
        crate::env::set_var("JCODE_DEFERRED_AUTH_BOOTSTRAP", "1");
        crate::config::Config::invalidate_cache();

        let provider: Arc<dyn Provider> = Arc::new(MockProvider);
        let runtime = tokio::runtime::Runtime::new().expect("create test runtime");
        let registry = runtime.block_on(crate::tool::Registry::new(provider.clone()));
        let mut app = App::new_for_test_harness(provider, registry);

        std::fs::write(
            temp.path().join("config.toml"),
            b"[gateway]\nenabled = false\n",
        )
        .expect("plant gateway config");
        std::fs::write(
            temp.path().join("devices.json"),
            br#"{"devices":[],"pending_codes":[{"code":"123456"}]}"#,
        )
        .expect("plant device registry");
        let before = snapshot_tree(temp.path());

        for command in [
            "/remote",
            "/remote status",
            "/remote on",
            "/remote off",
            "/remote pair",
            "/remote revoke fixture-device",
            "/remote nonsense",
        ] {
            assert!(handle_remote_command(&mut app, command), "{command}");
            let refusal = app
                .display_messages
                .last()
                .expect("refusal display message");
            assert_eq!(refusal.role, "error");
            assert!(
                refusal.content.starts_with(REMOTE_PAIRING_DISABLED),
                "{command}: {}",
                refusal.content
            );
        }

        assert_eq!(
            snapshot_tree(temp.path()),
            before,
            "disabled /remote command mutated config or pairing state"
        );

        if let Some(value) = previous_home {
            crate::env::set_var("JCODE_HOME", value);
        } else {
            crate::env::remove_var("JCODE_HOME");
        }
        if let Some(value) = previous_deferred {
            crate::env::set_var("JCODE_DEFERRED_AUTH_BOOTSTRAP", value);
        } else {
            crate::env::remove_var("JCODE_DEFERRED_AUTH_BOOTSTRAP");
        }
        crate::config::Config::invalidate_cache();
    }
}
