use anyhow::Result;
use clap::Parser;

use crate::{logging, perf, server, startup_profile, storage};

#[cfg(test)]
use super::args::OmnisCommand;
use super::{
    args::{Args, Command, ServerCommand},
    commands, dispatch, output, terminal,
};

fn sync_output_style_from_config() {
    crate::output_style::set_emoji_enabled(crate::config::config().display.emoji);
}

pub async fn run() -> Result<()> {
    // The compatibility spelling shares the canonical OMNIS KEY parser and
    // execution contract. Route it before even startup profiling so help,
    // parser failures, and every integrity operation remain ambient-free.
    if let Some(code) = omnis_key_cli::run_jcode_omnis_from(std::env::args_os()) {
        std::process::exit(code);
    }

    startup_profile::init();

    // Parse before installing hooks or initializing any ambient subsystem.
    // `clap::Error::exit` preserves clap's zero exit for help/version and exit
    // 2 for malformed input while keeping those forms on this write-free,
    // network-free path.
    let mut args = match Args::try_parse() {
        Ok(args) => args,
        Err(error) => error.exit(),
    };

    // Action receipt policy (mutations → ledger). Explicit --no-receipts is
    // recorded so sessions cannot quietly claim unreceipted work.
    {
        let mut policy = jcode_receipts::ActionReceiptPolicy::from_env();
        if args.no_receipts {
            policy.no_receipts = true;
        }
        if args.receipt_full_argv {
            policy.full_argv = true;
            eprintln!("{}", jcode_receipts::FULL_ARGV_WARNING);
        }
        if args.receipt_reads {
            policy.receipt_reads = true;
        }
        policy.install();
    }

    // Other no-ambient compatibility operations are handled before logging,
    // cleanup threads, config migration, provider registration, or updater
    // machinery.
    if let Some(command) = args.command.take() {
        match command {
            Command::Omnis { .. } => {
                return inherited_service_disabled("legacy OMNIS parser");
            }
            Command::Version { json } => return commands::run_version_command(json),
            Command::Account { .. } => return inherited_service_disabled("account"),
            Command::Update => return inherited_service_disabled("update"),
            Command::SetupLauncher | Command::SetupHotkey { .. } => {
                return inherited_service_disabled("installer");
            }
            Command::Browser { .. } => return inherited_service_disabled("installer"),
            Command::Pair { .. } => return inherited_service_disabled("pairing"),
            Command::Server {
                action: ServerCommand::Reload { .. },
            } => return inherited_service_disabled("server reload"),
            Command::Login {
                provider: Some(super::provider_init::ProviderChoice::Jcode),
                ..
            } => return inherited_service_disabled("account"),
            other => args.command = Some(other),
        }
    }

    // The legacy managed Jcode provider is an inherited account/subscription
    // surface. Reject it even when selected through the global provider flag
    // or as the implicit provider for `login`.
    if args.provider == super::provider_init::ProviderChoice::Jcode {
        return inherited_service_disabled("subscription");
    }

    if args.command.is_none() {
        let deferred = args.provider == super::provider_init::ProviderChoice::Auto
            && args.model.is_none()
            && args.provider_profile.is_none();
        if deferred {
            crate::env::set_var("JCODE_DEFERRED_AUTH_BOOTSTRAP", "1");
        } else {
            crate::env::remove_var("JCODE_DEFERRED_AUTH_BOOTSTRAP");
        }
    }

    terminal::install_panic_hook();
    startup_profile::mark("panic_hook");

    logging::init();
    startup_profile::mark("logging_init");
    // Old log pruning now runs on a background thread inside logging::init(),
    // so it no longer blocks startup. Memory-event logs have a separate,
    // longer (14-day) retention, so prune them on their own background thread.
    std::thread::Builder::new()
        .name("jcode-memlog-cleanup".to_string())
        .spawn(crate::memory_log::cleanup_old_memory_logs)
        .ok();
    // Prune stale per-session `.bak` recovery copies (never the transcripts
    // themselves) so the sessions directory does not grow without bound.
    std::thread::Builder::new()
        .name("jcode-session-bak-prune".to_string())
        .spawn(crate::session::prune_old_session_backups)
        .ok();
    logging::info("jcode starting");

    // Wire config-reload reactions without making config depend on auth/bus:
    // when the config cache reloads, invalidate the auth-status cache and
    // broadcast a models-updated event.
    sync_output_style_from_config();
    crate::config::on_config_reloaded(sync_output_style_from_config);
    crate::config::on_config_reloaded(crate::auth::AuthStatus::invalidate_cache);
    crate::config::on_config_reloaded(|| crate::bus::Bus::global().publish_models_updated());

    // Invert the legacy provider_catalog -> auth dependency: provider_catalog
    // consults registered fallback resolvers, and auth (the higher layer)
    // registers its external-CLI credential scan here.
    crate::provider_catalog::register_api_key_fallback_resolver(
        crate::auth::external::load_api_key_for_env,
    );

    // Register externally-implemented provider runtimes with the base
    // provider registry. These crates sit downstream of jcode-base (so
    // provider edits do not rebuild the app spine), which means base cannot
    // name their concrete types; this composition root wires them up instead.
    register_external_provider_runtimes();

    // Invert the legacy safety -> notifications dependency: safety raises a
    // permission request and the notifications layer (which depends on safety
    // types) delivers it via the dispatcher registered here.
    crate::safety::register_permission_notifier(|action, description, request_id| {
        crate::notifications::NotificationDispatcher::new().dispatch_permission_request(
            action,
            description,
            request_id,
        );
    });

    // Invert the legacy memory -> skill dependency: memory collects synthetic
    // entries from registered providers, and skill (the higher layer that
    // depends on MemoryEntry) registers its registry->memory adapter here.
    // The shared snapshot holds global skills only; memory retrieval is
    // process-scoped, so compose the project overlay from the process cwd
    // (issue #457 keeps session overlays out of the shared registry).
    crate::memory::register_synthetic_entry_provider(|| {
        let global = crate::skill::SkillRegistry::shared_snapshot();
        crate::skill::SkillRegistry::effective_for_working_dir(&global, None)
            .list()
            .into_iter()
            .map(|skill| skill.as_memory_entry())
            .collect()
    });

    // Invert the legacy server -> tui dependency: the TUI session picker owns
    // the session-list cache and registers its invalidator here, so the server
    // can drop the cache (e.g. after a rename) without referencing tui.
    crate::session_list_cache::register_invalidator(
        crate::tui::session_picker::invalidate_session_list_cache,
    );

    // Invert the legacy tui -> cli dependency for shared-server spawning: the
    // CLI owns the provider-bootstrap spawn logic and registers it here, so the
    // TUI reconnect loop can request a replacement server via server_spawn
    // without referencing cli.
    crate::server_spawn::register_default_server_spawner(Box::new(|| {
        Box::pin(async {
            dispatch::spawn_server(&crate::cli::provider_init::ProviderChoice::Auto, None, None)
                .await
        })
    }));

    crate::tui::keybind::log_keybinding_default_warnings();
    crate::platform::raise_nofile_limit_best_effort(8_192);
    startup_profile::mark("nofile_limit");

    storage::harden_user_config_permissions();
    startup_profile::mark("perm_harden");

    perf::init_background();
    startup_profile::mark("perf_init");

    let args = prepare_args(args)?;

    if let Err(e) = dispatch::run_main(args).await {
        report_main_error(&e);
        return Err(e);
    }

    Ok(())
}

fn inherited_service_disabled(surface: &str) -> Result<()> {
    anyhow::bail!(
        "OMNIS_KEY_INHERITED_SURFACE_DISABLED: inherited Jcode {surface} behavior is disabled in OMNIS KEY Local Integrity V1"
    )
}

/// Register provider runtimes that live downstream of `jcode-base` with the
/// base crate's external provider registry. Keep every downstream runtime
/// registration in this one function so the composition-root wiring stays
/// discoverable as more providers move out of the base crate.
pub fn register_external_provider_runtimes() {
    crate::provider::external::register_external_provider(
        crate::provider::external::GEMINI_RUNTIME,
        || std::sync::Arc::new(jcode_provider_gemini_runtime::GeminiProvider::new()),
    );
    crate::provider::external::register_external_provider(
        crate::provider::external::CURSOR_RUNTIME,
        || std::sync::Arc::new(jcode_provider_cursor_runtime::CursorCliProvider::new()),
    );
    crate::provider::external::register_external_provider(
        crate::provider::external::ANTIGRAVITY_RUNTIME,
        || std::sync::Arc::new(jcode_provider_antigravity_runtime::AntigravityProvider::new()),
    );
    crate::provider::external::register_external_provider(
        crate::provider::external::CLAUDE_CLI_RUNTIME,
        || std::sync::Arc::new(jcode_provider_claude_cli_runtime::ClaudeProvider::new()),
    );
    crate::provider::external::register_external_provider(
        crate::provider::external::ANTHROPIC_RUNTIME,
        || std::sync::Arc::new(jcode_provider_anthropic_runtime::AnthropicProvider::new()),
    );
    // OpenRouter serves several identities (aggregator, pinned API-key
    // runtime, direct OpenAI-compatible profiles, named config profiles)
    // through one concrete type, so it registers a parameterized factory.
    crate::provider::external::register_openrouter_factory(|spec| {
        use crate::provider::external::OpenRouterRuntimeSpec;
        use jcode_provider_openrouter_runtime::OpenRouterProvider;
        let provider: std::sync::Arc<dyn crate::provider::Provider> = match spec {
            OpenRouterRuntimeSpec::Default => std::sync::Arc::new(OpenRouterProvider::new()?),
            OpenRouterRuntimeSpec::OpenRouterApiKey => {
                std::sync::Arc::new(OpenRouterProvider::new_openrouter_api_key_runtime()?)
            }
            OpenRouterRuntimeSpec::CompatibleProfile(profile) => std::sync::Arc::new(
                OpenRouterProvider::new_openai_compatible_profile_runtime(profile)?,
            ),
            OpenRouterRuntimeSpec::NamedProfile { name, config } => std::sync::Arc::new(
                OpenRouterProvider::new_named_openai_compatible(&name, &config)?,
            ),
        };
        Ok(provider)
    });
    // API-backed OpenAI routes use Codex/platform credentials. The runtime is
    // still registered without them so browser-backed ChatGPT models remain
    // usable through the logged-in Firefox session.
    crate::provider::external::register_external_provider_fallible(
        crate::provider::external::OPENAI_RUNTIME,
        || {
            let provider = match crate::auth::codex::load_credentials() {
                Ok(credentials) => jcode_provider_openai_runtime::OpenAIProvider::new(credentials),
                Err(_) => jcode_provider_openai_runtime::OpenAIProvider::new_browser_only(),
            };
            Some(std::sync::Arc::new(provider) as std::sync::Arc<dyn crate::provider::Provider>)
        },
    );
    // Copilot's constructor is fallible (needs a GitHub token). Construction
    // must remain local-only; catalog/tier detection is deferred until an
    // explicit provider action or user turn.
    crate::provider::external::register_external_provider_fallible(
        crate::provider::external::COPILOT_RUNTIME,
        || {
            let provider = std::sync::Arc::new(
                jcode_provider_copilot_runtime::CopilotApiProvider::new().ok()?,
            );
            provider.complete_init_without_tier_detection();
            Some(provider as std::sync::Arc<dyn crate::provider::Provider>)
        },
    );
}

fn prepare_args(args: Args) -> Result<Args> {
    startup_profile::mark("args_parse");

    output::set_quiet_enabled(args.quiet);

    if let Some(cwd) = &args.cwd {
        std::env::set_current_dir(cwd)?;
        logging::info(&format!("Changed working directory to: {}", cwd));
    }

    validate_remote_working_dir(args.remote_working_dir.as_deref())?;

    if args.trace {
        crate::env::set_var("JCODE_TRACE", "1");
    }

    if let Some(ref socket) = args.socket {
        server::set_socket_path(socket);
    }

    crate::cli::proctitle::set_initial_title(&args);

    Ok(args)
}

fn validate_remote_working_dir(remote_working_dir: Option<&str>) -> Result<()> {
    if let Some(remote_working_dir) = remote_working_dir
        && !remote_working_dir_is_absolute(remote_working_dir)
    {
        anyhow::bail!("--remote-working-dir must be an absolute path");
    }
    Ok(())
}

fn remote_working_dir_is_absolute(path: &str) -> bool {
    if path.starts_with('/') || path.starts_with('\\') {
        return true;
    }

    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes[1] == b':'
        && (bytes[2] == b'/' || bytes[2] == b'\\')
        && bytes[0].is_ascii_alphabetic()
}

#[cfg(test)]
fn should_spawn_background_update_check(args: &Args) -> bool {
    let _ = args;
    false
}

#[cfg(test)]
fn take_isolated_omnis_command(args: Args) -> Option<OmnisCommand> {
    match args.command {
        Some(Command::Omnis { action }) => Some(action),
        _ => None,
    }
}

#[cfg(test)]
fn should_auto_install_update(args: &Args) -> bool {
    let _ = args;
    false
}

fn report_main_error(error: &anyhow::Error) {
    let error_str = format!("{:?}", error);
    logging::error(&error_str);

    if let Some(session_id) = terminal::get_current_session() {
        output::stderr_blank_line();
        output::stderr_info("\x1b[33mTo restore this session, run:\x1b[0m");
        output::stderr_info(format!("  jcode --resume {}", session_id));
        output::stderr_blank_line();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::args::{Args, Command};
    use clap::Parser;

    fn parse_args(argv: &[&str]) -> Args {
        Args::parse_from(argv)
    }

    #[test]
    fn auto_install_is_disabled_without_live_terminal() {
        let args = parse_args(&["jcode", "login"]);
        assert!(!should_auto_install_update(&args));
    }

    #[test]
    fn auto_install_is_disabled_with_live_terminal_attached() {
        let args = parse_args(&["jcode", "login"]);
        assert!(!should_auto_install_update(&args));
    }

    #[test]
    fn auto_install_respects_explicit_disable_even_without_terminal() {
        let mut args = parse_args(&["jcode", "login"]);
        args.auto_update = false;
        assert!(!should_auto_install_update(&args));
    }

    #[test]
    fn remote_working_dir_validation_requires_absolute_path() {
        assert!(validate_remote_working_dir(Some("/home/agent/project")).is_ok());
        assert!(validate_remote_working_dir(Some("C:\\Users\\agent\\project")).is_ok());
        assert!(validate_remote_working_dir(None).is_ok());

        let error = validate_remote_working_dir(Some("relative/project")).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("--remote-working-dir must be an absolute path")
        );
    }

    #[test]
    fn update_command_still_skips_background_check_before_auto_install_logic() {
        let args = parse_args(&["jcode", "update"]);
        assert!(matches!(args.command, Some(Command::Update)));
        assert!(!should_spawn_background_update_check(&args));
        assert!(!should_auto_install_update(&args));
    }

    #[test]
    fn inherited_pairing_is_hidden_and_refuses_before_ambient_startup() {
        let pair = parse_args(&["jcode", "pair"]);
        assert!(matches!(pair.command, Some(Command::Pair { .. })));

        let pair_help = Args::try_parse_from(["jcode", "pair", "--help"]).unwrap_err();
        assert_eq!(
            pair_help.kind(),
            clap::error::ErrorKind::UnknownArgument,
            "disabled pairing must not expose command-specific help"
        );

        let help = Args::try_parse_from(["jcode", "--help"])
            .unwrap_err()
            .to_string();
        assert!(
            !help
                .lines()
                .any(|line| line.trim_start().starts_with("pair ")),
            "disabled pairing must not be advertised in root help"
        );

        let error = inherited_service_disabled("pairing").unwrap_err();
        assert_eq!(
            error.to_string(),
            "OMNIS_KEY_INHERITED_SURFACE_DISABLED: inherited Jcode pairing behavior is disabled in OMNIS KEY Local Integrity V1"
        );
    }

    #[test]
    fn every_omnis_command_takes_the_isolated_no_update_path() {
        let anchor = parse_args(&[
            "jcode",
            "omnis",
            "anchor",
            "--request-id",
            "anchor:release/1",
        ]);
        assert!(!should_spawn_background_update_check(&anchor));
        assert!(matches!(
            take_isolated_omnis_command(anchor),
            Some(OmnisCommand::Anchor { request_id, .. })
                if request_id == "anchor:release/1"
        ));

        let verify = parse_args(&["jcode", "omnis", "verify-anchored"]);
        assert!(!should_spawn_background_update_check(&verify));
        assert!(matches!(
            take_isolated_omnis_command(verify),
            Some(OmnisCommand::VerifyAnchored { .. })
        ));

        let local_record = parse_args(&[
            "jcode",
            "omnis",
            "record",
            "--event-id",
            "event:one",
            "test",
            "subject",
            "--evidence-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ]);
        assert!(
            !should_spawn_background_update_check(&local_record),
            "all OMNIS operations must refuse ambient auto-update"
        );
        assert!(matches!(
            take_isolated_omnis_command(local_record),
            Some(OmnisCommand::Record { .. })
        ));
    }

    #[test]
    fn help_version_and_parse_errors_are_classified_before_ambient_startup() {
        let help = Args::try_parse_from(["jcode", "--help"]).unwrap_err();
        assert_eq!(help.kind(), clap::error::ErrorKind::DisplayHelp);

        let version = Args::try_parse_from(["jcode", "--version"]).unwrap_err();
        assert_eq!(version.kind(), clap::error::ErrorKind::DisplayVersion);

        let parse_error = Args::try_parse_from(["jcode", "not-a-command"]).unwrap_err();
        assert_eq!(
            parse_error.kind(),
            clap::error::ErrorKind::InvalidSubcommand
        );

        let omnis_help = Args::try_parse_from(["jcode", "omnis", "--help"]).unwrap_err();
        assert_eq!(omnis_help.kind(), clap::error::ErrorKind::DisplayHelp);

        let omnis_parse_error =
            Args::try_parse_from(["jcode", "omnis", "record", "--event-id"]).unwrap_err();
        assert_eq!(
            omnis_parse_error.kind(),
            clap::error::ErrorKind::InvalidValue
        );
    }

    #[test]
    fn root_global_flags_before_omnis_use_the_shared_isolated_parser() {
        assert_eq!(
            omnis_key_cli::run_jcode_omnis_from(["jcode", "--quiet", "omnis", "--help"]),
            Some(0)
        );
        assert_eq!(
            omnis_key_cli::run_jcode_omnis_from([
                "jcode",
                "--quiet",
                "omnis",
                "record",
                "--ledger",
                "/tmp/not-allowed"
            ]),
            Some(2)
        );
    }

    #[test]
    fn hidden_spawn_hotkey_argument_is_accepted_without_tracking_writes() {
        let _guard = crate::storage::lock_test_env();
        let previous_home = std::env::var_os("JCODE_HOME");
        let temp = tempfile::tempdir().expect("create hostile startup home");
        crate::env::set_var("JCODE_HOME", temp.path());
        let state_path = temp.path().join("setup_hints.json");
        let sentinel = br#"{"launch_hotkey_usage":{"cmd+shift+'":9}}"#;
        std::fs::write(&state_path, sentinel).expect("write setup-hint sentinel");

        let args = parse_args(&["jcode", "--spawn-hotkey", "shift+cmd+'"]);
        let prepared = prepare_args(args).expect("prepare hidden compatibility argument");

        assert_eq!(prepared.spawn_hotkey.as_deref(), Some("shift+cmd+'"));
        assert_eq!(
            std::fs::read(&state_path).expect("read setup-hint sentinel"),
            sentinel
        );
        assert!(
            !temp.path().join("hotkey").exists(),
            "hidden compatibility flag wrote launch-hotkey state"
        );

        if let Some(previous_home) = previous_home {
            crate::env::set_var("JCODE_HOME", previous_home);
        } else {
            crate::env::remove_var("JCODE_HOME");
        }
    }

    #[test]
    fn external_provider_runtimes_register_and_instantiate() {
        register_external_provider_runtimes();
        for (key, expected_name) in [
            (crate::provider::external::GEMINI_RUNTIME, "gemini"),
            (crate::provider::external::CURSOR_RUNTIME, "cursor"),
            (
                crate::provider::external::ANTIGRAVITY_RUNTIME,
                "antigravity",
            ),
        ] {
            assert!(
                crate::provider::external::external_provider_registered(key),
                "{key} runtime should be registered"
            );
            let provider = crate::provider::external::instantiate_external_provider(key)
                .unwrap_or_else(|| panic!("{key} runtime factory should instantiate"));
            assert_eq!(provider.name(), expected_name);
            assert!(!provider.model().is_empty());
        }

        // Copilot's factory is fallible (requires a GitHub token), so only
        // assert registration; instantiation legitimately returns None when no
        // Copilot credentials exist on the machine running the tests.
        assert!(crate::provider::external::external_provider_registered(
            crate::provider::external::COPILOT_RUNTIME
        ));
    }
}
