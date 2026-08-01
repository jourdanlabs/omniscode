use anyhow::Result;
use std::io::{self, Write};
use std::sync::Arc;

use crate::auth;
use crate::provider;
use crate::provider::Provider;
use crate::provider_catalog::{
    LoginProviderDescriptor, LoginProviderTarget, OpenAiCompatibleProfile,
    apply_openai_compatible_profile_env, force_apply_openai_compatible_profile_env,
    is_safe_env_file_name, is_safe_env_key_name, resolve_login_selection,
    resolve_openai_compatible_profile,
};
use crate::tool;

use super::login::run_login_provider;
use super::output;

pub(crate) use crate::external_auth::maybe_run_external_auth_auto_import_flow;
use crate::external_auth::{
    can_prompt_for_external_auth, external_auth_blocked_message, prompt_to_trust_external_auth,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ProviderChoice {
    #[value(skip)]
    Jcode,
    Claude,
    #[value(alias = "claude-api", alias = "anthropic-key", alias = "claude-key")]
    AnthropicApi,
    #[deprecated(
        note = "Claude Code CLI subprocess transport is deprecated; use ProviderChoice::Claude for native Anthropic OAuth/API transport"
    )]
    #[value(alias = "claude-subprocess", hide = true)]
    ClaudeSubprocess,
    Openai,
    #[value(
        alias = "openai-key",
        alias = "openai-apikey",
        alias = "openai-platform"
    )]
    OpenaiApi,
    Openrouter,
    #[value(alias = "aws-bedrock", alias = "aws_bedrock")]
    Bedrock,
    #[value(alias = "azure-openai", alias = "aoai")]
    Azure,
    #[value(alias = "opencode-zen", alias = "zen")]
    Opencode,
    #[value(alias = "opencodego")]
    OpencodeGo,
    #[value(alias = "z.ai", alias = "z-ai", alias = "zai-coding")]
    Zai,
    #[value(
        alias = "kimi-code",
        alias = "kimi-coding",
        alias = "kimi-coding-plan",
        alias = "kimi-for-coding",
        alias = "moonshot-coding"
    )]
    Kimi,
    #[value(alias = "302.ai")]
    Ai302,
    Baseten,
    Cortecs,
    #[value(alias = "cgc", alias = "comtegra-gpu-cloud")]
    Comtegra,
    Deepseek,
    #[value(alias = "fpt-ai", alias = "fptcloud", alias = "fpt-cloud")]
    Fpt,
    Firmware,
    #[value(alias = "hugging-face", alias = "hf")]
    HuggingFace,
    #[value(alias = "moonshot")]
    MoonshotAi,
    Nebius,
    Scaleway,
    Stackit,
    Groq,
    #[value(alias = "mistralai")]
    Mistral,
    #[value(alias = "pplx")]
    Perplexity,
    #[value(alias = "together", alias = "together-ai")]
    TogetherAi,
    #[value(alias = "deep-infra")]
    Deepinfra,
    #[value(alias = "fireworks-ai", alias = "fireworks.ai")]
    Fireworks,
    #[value(alias = "minimax-ai", alias = "minimaxi")]
    Minimax,
    #[value(alias = "x.ai", alias = "x-ai", alias = "grok")]
    Xai,
    #[value(alias = "nvidia", alias = "nim")]
    NvidiaNim,
    #[value(alias = "xiaomi", alias = "mimo", alias = "xiaomi-mimo-api")]
    XiaomiMimo,
    #[value(alias = "celeris-ai", alias = "celeris1", alias = "celeris-1")]
    Celeris,
    #[value(alias = "lm-studio")]
    Lmstudio,
    Ollama,
    Chutes,
    #[value(alias = "cerebrascode", alias = "cerberascode")]
    Cerebras,
    #[value(
        alias = "bailian",
        alias = "aliyun-bailian",
        alias = "coding-plan",
        alias = "alibaba-coding"
    )]
    AlibabaCodingPlan,
    #[value(alias = "compat", alias = "custom")]
    OpenaiCompatible,
    Cursor,
    Copilot,
    Gemini,
    #[value(
        alias = "gemini-key",
        alias = "gemini-apikey",
        alias = "google-ai-studio",
        alias = "ai-studio"
    )]
    GeminiApi,
    Antigravity,
    Google,
    Auto,
}

impl ProviderChoice {
    #[allow(deprecated)]
    pub fn as_arg_value(&self) -> &'static str {
        match self {
            Self::Jcode => "jcode",
            Self::Claude => "claude",
            Self::AnthropicApi => "anthropic-api",
            Self::ClaudeSubprocess => "claude-subprocess",
            Self::Openai => "openai",
            Self::OpenaiApi => "openai-api",
            Self::Openrouter => "openrouter",
            Self::Bedrock => "bedrock",
            Self::Azure => "azure",
            Self::Opencode => "opencode",
            Self::OpencodeGo => "opencode-go",
            Self::Zai => "zai",
            Self::Kimi => "kimi",
            Self::Ai302 => "302ai",
            Self::Baseten => "baseten",
            Self::Cortecs => "cortecs",
            Self::Comtegra => "comtegra",
            Self::Deepseek => "deepseek",
            Self::Fpt => "fpt",
            Self::Firmware => "firmware",
            Self::HuggingFace => "huggingface",
            Self::MoonshotAi => "moonshotai",
            Self::Nebius => "nebius",
            Self::Scaleway => "scaleway",
            Self::Stackit => "stackit",
            Self::Groq => "groq",
            Self::Mistral => "mistral",
            Self::Perplexity => "perplexity",
            Self::TogetherAi => "togetherai",
            Self::Deepinfra => "deepinfra",
            Self::Fireworks => "fireworks",
            Self::Minimax => "minimax",
            Self::Xai => "xai",
            Self::NvidiaNim => "nvidia-nim",
            Self::XiaomiMimo => "xiaomi-mimo",
            Self::Celeris => "celeris",
            Self::Lmstudio => "lmstudio",
            Self::Ollama => "ollama",
            Self::Chutes => "chutes",
            Self::Cerebras => "cerebras",
            Self::AlibabaCodingPlan => "alibaba-coding-plan",
            Self::OpenaiCompatible => "openai-compatible",
            Self::Cursor => "cursor",
            Self::Copilot => "copilot",
            Self::Gemini => "gemini",
            Self::GeminiApi => "gemini-api",
            Self::Antigravity => "antigravity",
            Self::Google => "google",
            Self::Auto => "auto",
        }
    }
}

#[allow(deprecated)]
const PROVIDER_CHOICE_LOGIN_PROVIDERS: &[(ProviderChoice, LoginProviderDescriptor)] = &[
    (
        ProviderChoice::Claude,
        crate::provider_catalog::CLAUDE_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::AnthropicApi,
        crate::provider_catalog::ANTHROPIC_API_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::ClaudeSubprocess,
        crate::provider_catalog::CLAUDE_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Openai,
        crate::provider_catalog::OPENAI_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::OpenaiApi,
        crate::provider_catalog::OPENAI_API_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Openrouter,
        crate::provider_catalog::OPENROUTER_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Bedrock,
        crate::provider_catalog::BEDROCK_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Azure,
        crate::provider_catalog::AZURE_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Opencode,
        crate::provider_catalog::OPENCODE_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::OpencodeGo,
        crate::provider_catalog::OPENCODE_GO_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Zai,
        crate::provider_catalog::ZAI_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Kimi,
        crate::provider_catalog::KIMI_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Ai302,
        crate::provider_catalog::AI302_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Baseten,
        crate::provider_catalog::BASETEN_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Cortecs,
        crate::provider_catalog::CORTECS_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Comtegra,
        crate::provider_catalog::COMTEGRA_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Deepseek,
        crate::provider_catalog::DEEPSEEK_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Fpt,
        crate::provider_catalog::FPT_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Firmware,
        crate::provider_catalog::FIRMWARE_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::HuggingFace,
        crate::provider_catalog::HUGGING_FACE_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::MoonshotAi,
        crate::provider_catalog::MOONSHOT_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Nebius,
        crate::provider_catalog::NEBIUS_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Scaleway,
        crate::provider_catalog::SCALEWAY_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Stackit,
        crate::provider_catalog::STACKIT_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Groq,
        crate::provider_catalog::GROQ_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Mistral,
        crate::provider_catalog::MISTRAL_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Perplexity,
        crate::provider_catalog::PERPLEXITY_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::TogetherAi,
        crate::provider_catalog::TOGETHER_AI_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Deepinfra,
        crate::provider_catalog::DEEPINFRA_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Fireworks,
        crate::provider_catalog::FIREWORKS_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Minimax,
        crate::provider_catalog::MINIMAX_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Xai,
        crate::provider_catalog::XAI_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::NvidiaNim,
        crate::provider_catalog::NVIDIA_NIM_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::XiaomiMimo,
        crate::provider_catalog::XIAOMI_MIMO_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Celeris,
        crate::provider_catalog::CELERIS_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Lmstudio,
        crate::provider_catalog::LMSTUDIO_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Ollama,
        crate::provider_catalog::OLLAMA_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Chutes,
        crate::provider_catalog::CHUTES_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Cerebras,
        crate::provider_catalog::CEREBRAS_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::AlibabaCodingPlan,
        crate::provider_catalog::ALIBABA_CODING_PLAN_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::OpenaiCompatible,
        crate::provider_catalog::OPENAI_COMPAT_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Cursor,
        crate::provider_catalog::CURSOR_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Copilot,
        crate::provider_catalog::COPILOT_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Gemini,
        crate::provider_catalog::GEMINI_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::GeminiApi,
        crate::provider_catalog::GEMINI_API_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Antigravity,
        crate::provider_catalog::ANTIGRAVITY_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Google,
        crate::provider_catalog::GOOGLE_LOGIN_PROVIDER,
    ),
];

pub fn login_provider_choice_mappings() -> &'static [(ProviderChoice, LoginProviderDescriptor)] {
    PROVIDER_CHOICE_LOGIN_PROVIDERS
}

pub fn profile_for_choice(choice: &ProviderChoice) -> Option<OpenAiCompatibleProfile> {
    match login_provider_for_choice(choice)?.target {
        LoginProviderTarget::OpenAiCompatible(profile) => Some(profile),
        _ => None,
    }
}

#[allow(deprecated)]
pub fn login_provider_for_choice(choice: &ProviderChoice) -> Option<LoginProviderDescriptor> {
    PROVIDER_CHOICE_LOGIN_PROVIDERS
        .iter()
        .find(|(candidate, _)| candidate == choice)
        .map(|(_, provider)| *provider)
}

#[allow(deprecated)]
pub fn choice_for_login_provider(provider: LoginProviderDescriptor) -> Option<ProviderChoice> {
    PROVIDER_CHOICE_LOGIN_PROVIDERS
        .iter()
        .find(|(choice, candidate)| {
            candidate.id == provider.id && !matches!(choice, ProviderChoice::ClaudeSubprocess)
        })
        .map(|(choice, _)| *choice)
}

pub fn prompt_login_provider_selection(
    providers: &[LoginProviderDescriptor],
    heading: &str,
) -> Result<LoginProviderDescriptor> {
    prompt_login_provider_selection_optional(providers, heading)?.ok_or_else(|| {
        anyhow::anyhow!("Login skipped. Run `jcode login` when you're ready to authenticate.")
    })
}

pub fn prompt_login_provider_selection_optional(
    providers: &[LoginProviderDescriptor],
    heading: &str,
) -> Result<Option<LoginProviderDescriptor>> {
    let status = auth::AuthStatus::check_fast();
    eprint!(
        "{}",
        render_login_provider_selection_menu(heading, providers, &status)
    );
    eprint!(
        "\nEnter 1-{}, provider name, or Enter=skip: ",
        providers.len()
    );
    io::stderr().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    parse_login_provider_selection_input(&input, providers)
}

pub fn parse_login_provider_selection_input(
    input: &str,
    providers: &[LoginProviderDescriptor],
) -> Result<Option<LoginProviderDescriptor>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let normalized = trimmed.to_ascii_lowercase();
    if matches!(
        normalized.as_str(),
        "s" | "skip" | "q" | "quit" | "cancel" | "none"
    ) {
        return Ok(None);
    }

    resolve_login_selection(trimmed, providers)
        .map(Some)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Invalid choice '{}'. Enter 1-{}, a provider name, or 'skip'.",
                trimmed,
                providers.len()
            )
        })
}

pub fn render_login_provider_selection_menu(
    heading: &str,
    providers: &[LoginProviderDescriptor],
    status: &auth::AuthStatus,
) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    let _ = writeln!(out, "{heading}");
    let _ = writeln!(out);

    let detected = providers
        .iter()
        .copied()
        .filter_map(|provider| {
            let assessment = status.assessment_for_provider(provider);
            (assessment.state != auth::AuthState::NotConfigured).then(|| {
                format!(
                    "  - {}: {}",
                    provider.display_name,
                    login_provider_detection_detail(provider, &assessment)
                )
            })
        })
        .collect::<Vec<_>>();

    if detected.is_empty() {
        let _ = writeln!(out, "Autodetected auth: none found yet.");
    } else {
        let _ = writeln!(out, "Autodetected auth:");
        for line in detected {
            let _ = writeln!(out, "{line}");
        }
    }

    let _ = writeln!(out);
    for (index, provider) in providers.iter().copied().enumerate() {
        let assessment = status.assessment_for_provider(provider);
        let _ = writeln!(
            out,
            "  {}. {:<22} [{:<15}] - {}",
            index + 1,
            provider.display_name,
            login_provider_state_badge(provider, assessment.state),
            provider.menu_detail
        );
    }

    let recommended = providers
        .iter()
        .filter(|provider| provider.recommended)
        .map(|provider| provider.display_name)
        .collect::<Vec<_>>();
    if !recommended.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "  Recommended if you have a subscription: {}.",
            recommended.join(", ")
        );
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "  Skip: press Enter, or type `skip`.");
    out
}

fn login_provider_state_badge(
    provider: LoginProviderDescriptor,
    state: auth::AuthState,
) -> &'static str {
    match state {
        auth::AuthState::Available => {
            if matches!(provider.target, LoginProviderTarget::AutoImport) {
                "detected"
            } else {
                "configured"
            }
        }
        auth::AuthState::Expired => "needs attention",
        auth::AuthState::NotConfigured => "not configured",
    }
}

fn login_provider_detection_detail(
    provider: LoginProviderDescriptor,
    assessment: &auth::ProviderAuthAssessment,
) -> String {
    match assessment.state {
        auth::AuthState::Available => {
            let prefix = if matches!(provider.target, LoginProviderTarget::AutoImport) {
                "detected"
            } else {
                "configured"
            };
            format!("{}: {}", prefix, assessment.method_detail)
        }
        auth::AuthState::Expired => format!("needs attention: {}", assessment.method_detail),
        auth::AuthState::NotConfigured => "not configured".to_string(),
    }
}

fn provider_label_for_api_key_env(env_key: &str) -> String {
    if env_key == "OPENROUTER_API_KEY" {
        return "OpenRouter".to_string();
    }

    crate::provider_catalog::openai_compatible_profiles()
        .iter()
        .find_map(|profile| {
            let resolved = resolve_openai_compatible_profile(*profile);
            (resolved.api_key_env == env_key).then_some(resolved.display_name)
        })
        .unwrap_or_else(|| env_key.to_string())
}

fn provider_login_hint_for_api_key_env(env_key: &str) -> String {
    if env_key == "OPENROUTER_API_KEY" {
        return "jcode login --provider openrouter".to_string();
    }

    crate::provider_catalog::openai_compatible_profiles()
        .iter()
        .find_map(|profile| {
            let resolved = resolve_openai_compatible_profile(*profile);
            (resolved.api_key_env == env_key)
                .then(|| format!("jcode login --provider {}", resolved.id))
        })
        .unwrap_or_else(|| "jcode login".to_string())
}

fn ensure_external_api_key_auth_allowed_for_explicit_choice(env_key: &str) -> Result<()> {
    if direct_api_key_configured_for_env(env_key) {
        return Ok(());
    }
    let Some(source) = auth::external::preferred_unconsented_api_key_source_for_env(env_key) else {
        return Ok(());
    };
    let path = source.path()?;
    let provider_name = provider_label_for_api_key_env(env_key);
    let login_hint = provider_login_hint_for_api_key_env(env_key);
    if !can_prompt_for_external_auth() {
        anyhow::bail!(external_auth_blocked_message(
            &provider_name,
            source.display_name(),
            &path,
            &login_hint,
        ));
    }
    if prompt_to_trust_external_auth(&provider_name, source.display_name(), &path)? {
        auth::external::trust_external_auth_source(source)?;
        return Ok(());
    }
    anyhow::bail!(
        "Skipped trusting external {} credentials. Run `{}` to authenticate jcode directly.",
        provider_name,
        login_hint
    )
}

fn direct_api_key_configured_for_env(env_key: &str) -> bool {
    let env_key = env_key.trim();
    if env_key.is_empty() {
        return false;
    }
    if std::env::var(env_key)
        .ok()
        .map(|key| !key.trim().is_empty())
        .unwrap_or(false)
    {
        return true;
    }

    crate::provider_catalog::openai_compatible_profiles()
        .iter()
        .filter_map(|profile| {
            let resolved = resolve_openai_compatible_profile(*profile);
            (resolved.api_key_env == env_key).then_some(resolved.env_file)
        })
        .any(|env_file| direct_env_file_contains_key(env_key, &env_file))
}

fn direct_env_file_contains_key(env_key: &str, env_file: &str) -> bool {
    if !crate::provider_catalog::is_safe_env_file_name(env_file) {
        return false;
    }
    let Some(config_dir) = crate::storage::app_config_dir().ok() else {
        return false;
    };
    let path = config_dir.join(env_file);
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };
    let prefix = format!("{}=", env_key);
    content.lines().any(|line| {
        line.strip_prefix(&prefix)
            .map(|key| !key.trim().trim_matches('"').trim_matches('\'').is_empty())
            .unwrap_or(false)
    })
}

fn maybe_prompt_for_generic_oauth_source(
    provider_name: &str,
    source: Option<auth::external::ExternalAuthSource>,
    login_hint: &str,
    auto: bool,
    validation: impl Fn() -> bool,
) -> Result<bool> {
    let Some(source) = source else {
        return Ok(false);
    };
    let path = source.path()?;
    if !can_prompt_for_external_auth() {
        if auto {
            crate::logging::warn(&external_auth_blocked_message(
                provider_name,
                source.display_name(),
                &path,
                login_hint,
            ));
            return Ok(false);
        }
        anyhow::bail!(external_auth_blocked_message(
            provider_name,
            source.display_name(),
            &path,
            login_hint,
        ));
    }
    if prompt_to_trust_external_auth(provider_name, source.display_name(), &path)? {
        auth::external::trust_external_auth_source(source)?;
        return Ok(if auto { validation() } else { true });
    }
    Ok(false)
}

fn ensure_openai_auth_allowed_for_explicit_choice() -> Result<()> {
    if auth::codex::load_credentials().is_ok() {
        return Ok(());
    }

    if maybe_prompt_for_generic_oauth_source(
        "OpenAI/Codex",
        auth::external::preferred_unconsented_openai_oauth_source(),
        "jcode login --provider openai",
        false,
        || auth::codex::load_credentials().is_ok(),
    )? {
        return Ok(());
    }

    if !auth::codex::has_unconsented_legacy_credentials() {
        return Ok(());
    }

    let path = auth::codex::legacy_auth_file_path()?;

    if !can_prompt_for_external_auth() {
        anyhow::bail!(external_auth_blocked_message(
            "OpenAI/Codex",
            "Codex",
            &path,
            "jcode login --provider openai"
        ));
    }

    if prompt_to_trust_external_auth("OpenAI/Codex", "Codex", &path)? {
        auth::codex::trust_legacy_auth_for_future_use()?;
        return Ok(());
    }

    anyhow::bail!(
        "Skipped trusting existing ~/.codex/auth.json credentials. Run `jcode login --provider openai` to authenticate jcode directly."
    )
}

fn ensure_claude_auth_allowed_for_explicit_choice() -> Result<()> {
    if auth::claude::load_credentials().is_ok() {
        return Ok(());
    }

    if maybe_prompt_for_generic_oauth_source(
        "Claude",
        auth::external::preferred_unconsented_anthropic_oauth_source(),
        "jcode login --provider claude",
        false,
        || auth::claude::load_credentials().is_ok(),
    )? {
        return Ok(());
    }

    let Some(source) = auth::claude::has_unconsented_external_auth() else {
        return Ok(());
    };
    let path = source.path()?;
    if !can_prompt_for_external_auth() {
        anyhow::bail!(external_auth_blocked_message(
            "Claude",
            source.display_name(),
            &path,
            "jcode login --provider claude"
        ));
    }
    if prompt_to_trust_external_auth("Claude", source.display_name(), &path)? {
        auth::claude::trust_external_auth_source(source)?;
        return Ok(());
    }
    anyhow::bail!(
        "Skipped trusting external Claude credentials. Run `jcode login --provider claude` to authenticate jcode directly."
    )
}

fn ensure_gemini_auth_allowed_for_explicit_choice() -> Result<()> {
    // An official Gemini Developer API key (GEMINI_API_KEY) authenticates
    // directly against generativelanguage.googleapis.com and needs no OAuth
    // consent flow, so allow it without further prompting.
    if auth::gemini::has_api_key() {
        return Ok(());
    }
    if auth::gemini::load_tokens().is_ok() {
        return Ok(());
    }

    if maybe_prompt_for_generic_oauth_source(
        "Gemini",
        auth::external::preferred_unconsented_gemini_oauth_source(),
        "jcode login --provider gemini",
        false,
        || auth::gemini::load_tokens().is_ok(),
    )? {
        return Ok(());
    }

    if !auth::gemini::has_unconsented_cli_auth() {
        return Ok(());
    }
    let path = auth::gemini::gemini_cli_oauth_path()?;
    if !can_prompt_for_external_auth() {
        anyhow::bail!(external_auth_blocked_message(
            "Gemini",
            "Gemini CLI",
            &path,
            "jcode login --provider gemini"
        ));
    }
    if prompt_to_trust_external_auth("Gemini", "Gemini CLI", &path)? {
        auth::gemini::trust_cli_auth_for_future_use()?;
        return Ok(());
    }
    anyhow::bail!(
        "Skipped trusting Gemini CLI credentials. Run `jcode login --provider gemini` to authenticate jcode directly."
    )
}

fn ensure_antigravity_auth_allowed_for_explicit_choice() -> Result<()> {
    if auth::antigravity::load_tokens().is_ok() {
        return Ok(());
    }

    if maybe_prompt_for_generic_oauth_source(
        "Antigravity",
        auth::external::preferred_unconsented_antigravity_oauth_source(),
        "jcode login --provider antigravity",
        false,
        || auth::antigravity::load_tokens().is_ok(),
    )? {
        return Ok(());
    }

    Ok(())
}

fn ensure_copilot_auth_allowed_for_explicit_choice() -> Result<()> {
    if auth::copilot::load_github_token().is_ok() {
        return Ok(());
    }
    let Some(source) = auth::copilot::has_unconsented_external_auth() else {
        return Ok(());
    };
    let path = source.path();
    if !can_prompt_for_external_auth() {
        anyhow::bail!(external_auth_blocked_message(
            "GitHub Copilot",
            source.display_name(),
            &path,
            "jcode login --provider copilot"
        ));
    }
    if prompt_to_trust_external_auth("GitHub Copilot", source.display_name(), &path)? {
        auth::copilot::trust_external_auth_source(source)?;
        return Ok(());
    }
    anyhow::bail!(
        "Skipped trusting external Copilot credentials. Run `jcode login --provider copilot` to authenticate jcode directly."
    )
}

fn ensure_cursor_auth_allowed_for_explicit_choice() -> Result<()> {
    if auth::cursor::has_cursor_native_auth() || auth::cursor::has_cursor_api_key() {
        return Ok(());
    }
    let Some(source) = auth::cursor::has_unconsented_external_auth() else {
        return Ok(());
    };
    let path = source.path()?;
    if !can_prompt_for_external_auth() {
        anyhow::bail!(external_auth_blocked_message(
            "Cursor",
            source.display_name(),
            &path,
            "jcode login --provider cursor"
        ));
    }
    if prompt_to_trust_external_auth("Cursor", source.display_name(), &path)? {
        auth::cursor::trust_external_auth_source(source)?;
        return Ok(());
    }
    anyhow::bail!(
        "Skipped trusting external Cursor credentials. Run `jcode login --provider cursor` to authenticate jcode directly."
    )
}

pub fn select_initial_model_provider(provider_key: &str) {
    crate::provider::activation::select_initial_runtime_provider_key(provider_key);
}

pub fn clear_initial_model_provider() {
    crate::provider::activation::clear_initial_runtime_provider();
}

/// A CLI provider choice for a dual-auth backend is also a credential choice.
/// Pin it through the provider's credential-mode API
/// so `--provider anthropic-api` cannot remain in Auto mode and prefer a stored
/// Claude OAuth credential over `ANTHROPIC_API_KEY` (and likewise for OpenAI).
fn explicit_credential_mode(choice: &ProviderChoice) -> Option<provider::CredentialMode> {
    match choice {
        ProviderChoice::AnthropicApi | ProviderChoice::OpenaiApi => {
            Some(provider::CredentialMode::ApiKey)
        }
        _ => None,
    }
}

fn disable_subscription_runtime_mode() {
    crate::subscription_catalog::clear_runtime_env();
}

fn inherited_jcode_subscription_disabled<T>() -> Result<T> {
    disable_subscription_runtime_mode();
    anyhow::bail!(
        "{}",
        crate::subscription_catalog::INHERITED_SUBSCRIPTION_DISABLED_MESSAGE
    )
}

fn disable_subscription_runtime_mode_preserving_active_provider_profile() {
    if std::env::var_os("JCODE_PROVIDER_PROFILE_ACTIVE").is_some()
        || std::env::var_os("JCODE_NAMED_PROVIDER_PROFILE").is_some()
    {
        crate::env::remove_var(crate::subscription_catalog::JCODE_SUBSCRIPTION_ACTIVE_ENV);
    } else {
        disable_subscription_runtime_mode();
    }
}

pub fn apply_login_provider_profile_env(provider: LoginProviderDescriptor) {
    match provider.target {
        LoginProviderTarget::OpenAiCompatible(profile) => {
            force_apply_openai_compatible_profile_env(Some(profile));
            // Bootstrap login still spawns the daemon with `--provider auto`. Mark the
            // just-selected compatible provider as active so the child process does
            // not clear these inherited runtime vars before credential detection.
            crate::env::set_var("JCODE_PROVIDER_PROFILE_ACTIVE", "1");
        }
        LoginProviderTarget::AutoImport | LoginProviderTarget::Google => {}
        _ => {
            // A later non-compatible login selection must not inherit a stale
            // compatible-provider profile from an earlier bootstrap/login path.
            force_apply_openai_compatible_profile_env(None);
        }
    }
}

fn resolved_profile_default_model(profile: OpenAiCompatibleProfile) -> Option<String> {
    resolve_openai_compatible_profile(profile).default_model
}

pub async fn login_and_bootstrap_provider(
    provider: LoginProviderDescriptor,
    account_label: Option<&str>,
) -> Result<Arc<dyn provider::Provider>> {
    if provider.target == LoginProviderTarget::Jcode {
        return inherited_jcode_subscription_disabled();
    }

    run_login_provider(
        provider,
        account_label,
        crate::cli::login::LoginOptions::default(),
    )
    .await?;
    eprintln!();

    let runtime: Arc<dyn provider::Provider> = match provider.target {
        LoginProviderTarget::AutoImport => {
            disable_subscription_runtime_mode();
            Arc::new(provider::MultiProvider::new())
        }
        LoginProviderTarget::Jcode => inherited_jcode_subscription_disabled()?,
        LoginProviderTarget::Claude | LoginProviderTarget::ClaudeApiKey => {
            disable_subscription_runtime_mode();
            Arc::new(provider::MultiProvider::new())
        }
        LoginProviderTarget::OpenAi => {
            disable_subscription_runtime_mode();
            Arc::new(provider::MultiProvider::with_preference(true))
        }
        LoginProviderTarget::OpenAiApiKey => {
            disable_subscription_runtime_mode();
            select_initial_model_provider("openai");
            Arc::new(provider::MultiProvider::with_preference(true))
        }
        LoginProviderTarget::OpenRouter => {
            disable_subscription_runtime_mode();
            Arc::new(provider::MultiProvider::new())
        }
        LoginProviderTarget::Bedrock => {
            disable_subscription_runtime_mode();
            select_initial_model_provider("bedrock");
            Arc::new(provider::MultiProvider::new())
        }
        LoginProviderTarget::Azure => {
            disable_subscription_runtime_mode();
            let model = crate::provider::activation::apply_azure_openai_runtime()?;
            let multi = provider::MultiProvider::new();
            if let Some(model) = model {
                let _ = multi.set_model(&model);
            }
            Arc::new(multi)
        }
        LoginProviderTarget::OpenAiCompatible(profile) => {
            disable_subscription_runtime_mode();
            apply_openai_compatible_profile_env(Some(profile));
            let multi = provider::MultiProvider::new();
            let resolved = resolve_openai_compatible_profile(profile);
            crate::provider::activation::apply_openai_compatible_runtime(
                resolved.default_model.clone(),
            )?;
            if let Some(model) = resolved.default_model.as_deref() {
                let _ = multi.set_model(model);
            }
            Arc::new(multi)
        }
        LoginProviderTarget::Cursor => {
            disable_subscription_runtime_mode();
            clear_initial_model_provider();
            crate::env::set_var("JCODE_ACTIVE_PROVIDER", "cursor");
            Arc::new(jcode_provider_cursor_runtime::CursorCliProvider::new())
        }
        LoginProviderTarget::Copilot => {
            disable_subscription_runtime_mode();
            Arc::new(provider::MultiProvider::new())
        }
        LoginProviderTarget::Gemini => {
            disable_subscription_runtime_mode();
            clear_initial_model_provider();
            crate::env::set_var("JCODE_ACTIVE_PROVIDER", "gemini");
            Arc::new(jcode_provider_gemini_runtime::GeminiProvider::new())
        }
        LoginProviderTarget::Antigravity => {
            disable_subscription_runtime_mode();
            clear_initial_model_provider();
            crate::env::set_var("JCODE_ACTIVE_PROVIDER", "antigravity");
            Arc::new(jcode_provider_antigravity_runtime::AntigravityProvider::new())
        }
        LoginProviderTarget::Google => {
            anyhow::bail!("Google login cannot be used as a model provider bootstrap");
        }
    };

    Ok(runtime)
}

pub fn save_named_api_key(env_file: &str, key_name: &str, key: &str) -> Result<()> {
    if !is_safe_env_key_name(key_name) {
        anyhow::bail!("Invalid API key variable name: {}", key_name);
    }
    if !is_safe_env_file_name(env_file) {
        anyhow::bail!("Invalid env file name: {}", env_file);
    }

    let config_dir = crate::storage::app_config_dir()?;
    let file_path = config_dir.join(env_file);
    crate::storage::upsert_env_file_value(&file_path, key_name, Some(key))?;

    crate::env::set_var(key_name, key);
    Ok(())
}

pub async fn init_provider(
    choice: &ProviderChoice,
    model: Option<&str>,
) -> Result<Arc<dyn provider::Provider>> {
    init_provider_with_options(choice, model, true, true).await
}

pub async fn init_provider_quiet(
    choice: &ProviderChoice,
    model: Option<&str>,
) -> Result<Arc<dyn provider::Provider>> {
    init_provider_with_options(choice, model, false, true).await
}

pub async fn init_provider_for_validation(
    choice: &ProviderChoice,
    model: Option<&str>,
) -> Result<Arc<dyn provider::Provider>> {
    init_provider_with_options(choice, model, false, false).await
}

#[allow(deprecated)]
/// Env var names that carry a provider credential and must be invisible while we
/// probe what the *product store* holds.
///
/// Pattern-matched rather than enumerated, deliberately: a hand-kept list of 40+
/// provider variables goes stale the first time a provider is added, and a stale
/// mask silently re-opens ambient discovery. Suffix matching stays correct for
/// providers that do not exist yet.
fn is_provider_credential_env_name(name: &str) -> bool {
    const SUFFIXES: &[&str] = &["_API_KEY", "_AUTH_TOKEN", "_ACCESS_TOKEN", "_API_TOKEN"];
    // Names that carry a credential without a conforming suffix.
    const EXACT: &[&str] = &[
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "AWS_BEARER_TOKEN_BEDROCK",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    ];
    EXACT.contains(&name) || SUFFIXES.iter().any(|s| name.ends_with(s))
}

/// Run `probe` with every provider credential env var temporarily removed, then
/// restore the environment exactly as it was.
///
/// This is how we answer the only question that matters for `auto`: *would this
/// credential exist if the environment were empty?* If yes, the operator stored
/// it here via `login`, and arming a route is them acting. If no, it is ambient —
/// a shell profile, a CI runner, a parent process — and the README promises we do
/// not invent a route from it.
///
/// An earlier attempt gated on "the product store directory has any file in it",
/// which a leftover `bedrock.env` from an unrelated experiment satisfied — so an
/// ambient `ANTHROPIC_API_KEY` armed an Anthropic route on the strength of an
/// unrelated file. Masking the inputs is the check that cannot be fooled that way.
fn with_provider_credential_env_masked<T>(probe: impl FnOnce() -> T) -> T {
    let saved: Vec<(String, String)> = std::env::vars()
        .filter(|(name, _)| is_provider_credential_env_name(name))
        .collect();
    for (name, _) in &saved {
        crate::env::remove_var(name);
    }
    let result = probe();
    for (name, value) in saved {
        crate::env::set_var(&name, value);
    }
    result
}

/// Resolve `--provider auto` from credentials the operator explicitly stored via
/// `login`. Does **not** import untrusted external app credentials, does **not**
/// select a config default, and does **not** arm from ambient process env keys.
/// Returns `None` when nothing is stored so the caller stays on the inert shell.
async fn try_resolve_auto_from_local_credentials(
    show_init_messages: bool,
) -> Result<Option<Arc<dyn provider::Provider>>> {
    // AuthStatus::check short-circuits to empty while deferred is set. Clear it
    // only for this local probe; re-set if nothing usable is found.
    let was_deferred = std::env::var_os("JCODE_DEFERRED_AUTH_BOOTSTRAP").is_some();
    crate::env::remove_var("JCODE_DEFERRED_AUTH_BOOTSTRAP");

    super::startup::register_external_provider_runtimes();

    // Probe with ambient provider credentials masked, so only what `login` wrote
    // to the product store can answer. This is the line that keeps "auto startup
    // stays empty until explicit selection" true.
    let status = with_provider_credential_env_masked(|| {
        auth::AuthStatus::invalidate_cached_status();
        auth::AuthStatus::check()
    });
    // The cache was populated under the mask; drop it so later callers see the
    // real environment again.
    auth::AuthStatus::invalidate_cached_status();

    if !status.has_any_available() {
        if was_deferred {
            crate::env::set_var("JCODE_DEFERRED_AUTH_BOOTSTRAP", "1");
        }
        return Ok(None);
    }

    // Local credentials exist — arm a real MultiProvider and leave deferred off
    // so subsequent AuthStatus probes and model routes see the same truth.
    let multi = provider::MultiProvider::from_auth_status(status);
    if multi.model_routes().is_empty() {
        // Available probe without constructible routes (edge cases): stay inert.
        if was_deferred {
            crate::env::set_var("JCODE_DEFERRED_AUTH_BOOTSTRAP", "1");
        }
        return Ok(None);
    }

    crate::env::set_var("JCODE_ACTIVE_PROVIDER", multi.name().to_lowercase());
    if show_init_messages {
        output::stderr_info(&format!(
            "Using local credentials via auto (active: {}). Pass --provider <name> to pin explicitly.",
            multi.name()
        ));
    }
    Ok(Some(Arc::new(multi)))
}

async fn init_provider_with_options(
    choice: &ProviderChoice,
    model: Option<&str>,
    show_init_messages: bool,
    _allow_login_bootstrap: bool,
) -> Result<Arc<dyn provider::Provider>> {
    if *choice == ProviderChoice::Jcode {
        return inherited_jcode_subscription_disabled();
    }
    if *choice != ProviderChoice::Auto {
        crate::env::remove_var("JCODE_DEFERRED_AUTH_BOOTSTRAP");
    }

    // Provider construction resolves concrete runtimes through the base
    // crate's external-runtime registry (composition-root pattern). The
    // binary's normal path registers them in `startup::run()`, but this
    // function is also entered directly by validation/login/test flows that
    // never run startup. Registration is idempotent, so do it here too;
    // otherwise Auto-init silently loses registry-backed runtimes (e.g. the
    // OpenRouter/OpenAI-compatible factory) and their model-picker routes.
    super::startup::register_external_provider_runtimes();

    if let Ok(profile_name) = std::env::var("JCODE_PROVIDER_PROFILE_NAME")
        && !profile_name.trim().is_empty()
    {
        crate::provider_catalog::apply_named_provider_profile_env(profile_name.trim())?;
        crate::env::set_var("JCODE_PROVIDER_PROFILE_ACTIVE", "1");
    }

    if std::env::var_os("JCODE_PROVIDER_PROFILE_ACTIVE").is_none()
        && std::env::var_os("JCODE_NAMED_PROVIDER_PROFILE").is_none()
    {
        if let Some(profile) = profile_for_choice(choice) {
            apply_openai_compatible_profile_env(Some(profile));
        } else {
            apply_openai_compatible_profile_env(None);
        }
    }

    let init_notice = |message: &str| {
        if show_init_messages {
            output::stderr_info(message);
        }
    };

    let provider: Arc<dyn provider::Provider> = match choice {
        ProviderChoice::Jcode => inherited_jcode_subscription_disabled()?,
        ProviderChoice::Claude => {
            disable_subscription_runtime_mode();
            ensure_claude_auth_allowed_for_explicit_choice()?;
            init_notice("Using Claude as the initial provider (use /model to switch)");
            select_initial_model_provider("claude");
            Arc::new(provider::MultiProvider::with_preference(false))
        }
        ProviderChoice::AnthropicApi => {
            disable_subscription_runtime_mode();
            ensure_external_api_key_auth_allowed_for_explicit_choice("ANTHROPIC_API_KEY")?;
            init_notice("Using Anthropic API key as the initial provider (use /model to switch)");
            select_initial_model_provider("claude");
            Arc::new(provider::MultiProvider::with_preference(false))
        }
        ProviderChoice::ClaudeSubprocess => {
            disable_subscription_runtime_mode();
            ensure_claude_auth_allowed_for_explicit_choice()?;
            crate::logging::warn(
                "Using --provider claude-subprocess is deprecated and will be removed. Prefer `--provider claude`.",
            );
            crate::env::set_var("JCODE_USE_CLAUDE_CLI", "1");
            init_notice(
                "Using deprecated Claude subprocess transport as the initial provider (legacy compatibility mode)",
            );
            select_initial_model_provider("claude");
            Arc::new(provider::MultiProvider::with_preference(false))
        }
        ProviderChoice::Openai => {
            disable_subscription_runtime_mode();
            ensure_openai_auth_allowed_for_explicit_choice()?;
            init_notice("Using OpenAI as the initial provider (use /model to switch)");
            select_initial_model_provider("openai");
            Arc::new(provider::MultiProvider::with_preference(true))
        }
        ProviderChoice::OpenaiApi => {
            disable_subscription_runtime_mode();
            ensure_external_api_key_auth_allowed_for_explicit_choice("OPENAI_API_KEY")?;
            init_notice("Using OpenAI API key as the initial provider (use /model to switch)");
            select_initial_model_provider("openai");
            Arc::new(provider::MultiProvider::with_preference(true))
        }
        ProviderChoice::Cursor => {
            disable_subscription_runtime_mode();
            ensure_cursor_auth_allowed_for_explicit_choice()?;
            init_notice("Using Cursor native HTTPS provider (experimental)");
            clear_initial_model_provider();
            crate::env::set_var("JCODE_ACTIVE_PROVIDER", "cursor");
            Arc::new(jcode_provider_cursor_runtime::CursorCliProvider::new())
        }
        ProviderChoice::Copilot => {
            disable_subscription_runtime_mode();
            ensure_copilot_auth_allowed_for_explicit_choice()?;
            init_notice("Using GitHub Copilot API as the initial provider (use /model to switch)");
            select_initial_model_provider("copilot");
            Arc::new(provider::MultiProvider::new())
        }
        ProviderChoice::Gemini => {
            disable_subscription_runtime_mode();
            ensure_gemini_auth_allowed_for_explicit_choice()?;
            if auth::gemini::has_api_key() {
                init_notice(
                    "Using Gemini provider (official Gemini Developer API key, generativelanguage.googleapis.com)",
                );
            } else {
                init_notice("Using Gemini provider (native Google Code Assist OAuth)");
            }
            clear_initial_model_provider();
            crate::env::set_var("JCODE_ACTIVE_PROVIDER", "gemini");
            Arc::new(jcode_provider_gemini_runtime::GeminiProvider::new())
        }
        ProviderChoice::Openrouter => {
            disable_subscription_runtime_mode();
            ensure_external_api_key_auth_allowed_for_explicit_choice("OPENROUTER_API_KEY")?;
            init_notice("Using OpenRouter as the initial provider (use /model to switch)");
            select_initial_model_provider("openrouter");
            Arc::new(provider::MultiProvider::new())
        }
        ProviderChoice::Bedrock => {
            disable_subscription_runtime_mode();
            init_notice("Using AWS Bedrock as the initial provider (use /model to switch)");
            select_initial_model_provider("bedrock");
            Arc::new(provider::MultiProvider::new())
        }
        ProviderChoice::Azure => {
            disable_subscription_runtime_mode();
            let model = crate::provider::activation::apply_azure_openai_runtime()?;
            init_notice("Using Azure OpenAI as the initial provider (use /model to switch)");
            let multi = provider::MultiProvider::new();
            if let Some(model) = model {
                let _ = multi.set_model(&model);
            }
            Arc::new(multi)
        }
        ProviderChoice::Opencode
        | ProviderChoice::OpencodeGo
        | ProviderChoice::Zai
        | ProviderChoice::Ai302
        | ProviderChoice::Baseten
        | ProviderChoice::Cortecs
        | ProviderChoice::Comtegra
        | ProviderChoice::Deepseek
        | ProviderChoice::Fpt
        | ProviderChoice::Firmware
        | ProviderChoice::HuggingFace
        | ProviderChoice::MoonshotAi
        | ProviderChoice::Kimi
        | ProviderChoice::Nebius
        | ProviderChoice::Scaleway
        | ProviderChoice::Stackit
        | ProviderChoice::Groq
        | ProviderChoice::Mistral
        | ProviderChoice::Perplexity
        | ProviderChoice::TogetherAi
        | ProviderChoice::Deepinfra
        | ProviderChoice::Fireworks
        | ProviderChoice::Minimax
        | ProviderChoice::Xai
        | ProviderChoice::NvidiaNim
        | ProviderChoice::XiaomiMimo
        | ProviderChoice::Celeris
        | ProviderChoice::Lmstudio
        | ProviderChoice::Ollama
        | ProviderChoice::Chutes
        | ProviderChoice::Cerebras
        | ProviderChoice::AlibabaCodingPlan
        | ProviderChoice::GeminiApi
        | ProviderChoice::OpenaiCompatible => {
            disable_subscription_runtime_mode();
            let profile = profile_for_choice(choice)
                .ok_or_else(|| anyhow::anyhow!("missing provider profile for choice"))?;
            if std::env::var_os("JCODE_NAMED_PROVIDER_PROFILE").is_none() {
                // An explicit `--provider <compatible>` selection should win over
                // any stale active-profile marker inherited from a previous
                // bootstrap/login flow. Named provider profiles still take
                // precedence when explicitly configured.
                force_apply_openai_compatible_profile_env(Some(profile));
            }
            let mut runtime_model_hint = None;
            let display_name = if let Ok(named) = std::env::var("JCODE_NAMED_PROVIDER_PROFILE") {
                if let Some(profile) = crate::config::config().providers.get(&named) {
                    runtime_model_hint = profile.default_model.clone();
                }
                named
            } else {
                let resolved = resolve_openai_compatible_profile(profile);
                if resolved.requires_api_key {
                    ensure_external_api_key_auth_allowed_for_explicit_choice(
                        &resolved.api_key_env,
                    )?;
                }
                runtime_model_hint = resolved.default_model.clone();
                resolved.display_name
            };
            init_notice(&format!(
                "Using {} via OpenAI-compatible API as the initial provider",
                display_name
            ));
            crate::provider::activation::apply_openai_compatible_runtime(runtime_model_hint)?;
            if std::env::var_os("JCODE_NAMED_PROVIDER_PROFILE").is_some() {
                let profile_name = std::env::var("JCODE_NAMED_PROVIDER_PROFILE")?;
                let cfg = crate::config::config();
                let profile = cfg.providers.get(&profile_name).ok_or_else(|| {
                    anyhow::anyhow!("Unknown provider profile '{}'", profile_name)
                })?;
                Arc::new(
                    jcode_provider_openrouter_runtime::OpenRouterProvider::new_named_openai_compatible(
                        &profile_name,
                        profile,
                    )?,
                )
            } else {
                Arc::new(jcode_provider_openrouter_runtime::OpenRouterProvider::new()?)
            }
        }
        ProviderChoice::Antigravity => {
            disable_subscription_runtime_mode();
            ensure_antigravity_auth_allowed_for_explicit_choice()?;
            init_notice("Using Antigravity provider (experimental)");
            clear_initial_model_provider();
            crate::env::set_var("JCODE_ACTIVE_PROVIDER", "antigravity");
            Arc::new(jcode_provider_antigravity_runtime::AntigravityProvider::new())
        }
        ProviderChoice::Google => {
            disable_subscription_runtime_mode();
            init_notice(
                "Note: Google/Gmail is not a model provider. Using auto-detect for model provider.",
            );
            init_notice(
                "Gmail credentials can be configured with `jcode login google`; the gmail tool is enabled by default in the full tool profile.",
            );
            clear_initial_model_provider();
            Arc::new(provider::MultiProvider::new())
        }
        ProviderChoice::Auto => {
            disable_subscription_runtime_mode_preserving_active_provider_profile();
            clear_initial_model_provider();
            // P1-A: auto resolves credentials already in the local product store.
            // Still refuses untrusted external import and ambient config-only
            // routes (see try_resolve_auto_from_local_credentials + tests).
            if let Some(provider) =
                try_resolve_auto_from_local_credentials(show_init_messages).await?
            {
                return Ok(provider);
            }
            crate::env::set_var("JCODE_DEFERRED_AUTH_BOOTSTRAP", "1");
            if show_init_messages {
                output::stderr_info(
                    "No local provider credentials yet. Login once, then bare `omnis-code` works without --provider:\n  omnis-code login claude\n  omnis-code login openai\n  omnis-code auth status",
                );
            }
            let multi = provider::MultiProvider::from_auth_status(auth::AuthStatus::default());
            crate::env::set_var("JCODE_ACTIVE_PROVIDER", multi.name().to_lowercase());
            Arc::new(multi)
        }
    };

    if let Some(mode) = explicit_credential_mode(choice) {
        provider.set_credential_mode(mode).map_err(|err| {
            anyhow::anyhow!(
                "Failed to select the credential route for --provider {}: {err}",
                choice.as_arg_value()
            )
        })?;
    }

    if std::env::var_os("JCODE_PROVIDER_PROFILE_ACTIVE").is_none()
        && std::env::var_os("JCODE_NAMED_PROVIDER_PROFILE").is_none()
        && model.is_none()
        && let Some(profile) = profile_for_choice(choice)
        && let Some(default_model) = resolved_profile_default_model(profile)
        && provider.set_model(&default_model).is_ok()
    {
        let resolved = resolve_openai_compatible_profile(profile);
        init_notice(&format!(
            "Using default model for {}: {}",
            resolved.display_name, default_model
        ));
    }

    if let Some(model_name) = model {
        if let Err(e) = provider.set_model(model_name) {
            init_notice(&format!(
                "Warning: failed to set model '{}': {}",
                model_name, e
            ));
        } else {
            init_notice(&format!("Using model: {}", model_name));
        }
    }

    Ok(provider)
}

pub async fn init_provider_and_registry(
    choice: &ProviderChoice,
    model: Option<&str>,
) -> Result<(Arc<dyn provider::Provider>, tool::Registry)> {
    let provider = init_provider(choice, model).await?;
    let registry = tool::Registry::new(provider.clone()).await;
    Ok((provider, registry))
}

pub async fn init_provider_and_registry_for_validation(
    choice: &ProviderChoice,
    model: Option<&str>,
) -> Result<(Arc<dyn provider::Provider>, tool::Registry)> {
    let provider = init_provider_for_validation(choice, model).await?;
    let registry = tool::Registry::new(provider.clone()).await;
    Ok((provider, registry))
}

#[cfg(test)]
#[path = "provider_init_tests.rs"]
mod tests;
