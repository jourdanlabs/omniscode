use super::{EventStream, Provider};
use crate::message::{Message, ToolDefinition};
use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;

/// Compatibility type for the inherited managed Jcode provider.
///
/// The public constructor and every executable provider action fail closed.
/// Keeping the type avoids destabilizing downstream source compatibility while
/// making it impossible for a direct/internal caller to reactivate the managed
/// account and subscription transport.
pub struct JcodeProvider;

impl JcodeProvider {
    pub fn new() -> Result<Self> {
        anyhow::bail!(crate::subscription_catalog::INHERITED_SUBSCRIPTION_DISABLED_MESSAGE)
    }

    fn disabled<T>() -> Result<T> {
        anyhow::bail!(crate::subscription_catalog::INHERITED_SUBSCRIPTION_DISABLED_MESSAGE)
    }
}

#[async_trait]
impl Provider for JcodeProvider {
    async fn complete(
        &self,
        _messages: &[Message],
        _tools: &[ToolDefinition],
        _system: &str,
        _resume_session_id: Option<&str>,
    ) -> Result<EventStream> {
        Self::disabled()
    }

    async fn complete_split(
        &self,
        _messages: &[Message],
        _tools: &[ToolDefinition],
        _system_static: &str,
        _system_dynamic: &str,
        _resume_session_id: Option<&str>,
    ) -> Result<EventStream> {
        Self::disabled()
    }

    fn name(&self) -> &str {
        "inherited-jcode-provider-disabled"
    }

    fn model(&self) -> String {
        String::new()
    }

    fn set_model(&self, _model: &str) -> Result<()> {
        Self::disabled()
    }

    fn available_models(&self) -> Vec<&'static str> {
        Vec::new()
    }

    fn available_models_display(&self) -> Vec<String> {
        Vec::new()
    }

    fn available_models_for_switching(&self) -> Vec<String> {
        Vec::new()
    }

    fn model_routes(&self) -> Vec<super::ModelRoute> {
        Vec::new()
    }

    async fn prefetch_models(&self) -> Result<()> {
        Self::disabled()
    }

    fn set_reasoning_effort(&self, _effort: &str) -> Result<()> {
        Self::disabled()
    }

    fn set_service_tier(&self, _service_tier: &str) -> Result<()> {
        Self::disabled()
    }

    fn set_transport(&self, _transport: &str) -> Result<()> {
        Self::disabled()
    }

    async fn native_compact(
        &self,
        _messages: &[Message],
        _existing_summary_text: Option<&str>,
        _existing_openai_encrypted_content: Option<&str>,
    ) -> Result<super::NativeCompactionResult> {
        Self::disabled()
    }

    fn context_window(&self) -> usize {
        0
    }

    fn fork(&self) -> Arc<dyn Provider> {
        Arc::new(Self)
    }

    fn switch_active_provider_to(&self, _provider: &str) -> Result<()> {
        Self::disabled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor_refuses_without_activating_hostile_runtime_env() {
        let _guard = crate::storage::lock_test_env();
        crate::env::set_var("JCODE_RUNTIME_PROVIDER", "sentinel");
        crate::env::set_var("JCODE_ACTIVE_PROVIDER", "sentinel");
        crate::env::set_var("JCODE_SUBSCRIPTION_ACTIVE", "1");

        let error = match JcodeProvider::new() {
            Ok(_) => panic!("inherited provider construction must refuse"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            crate::subscription_catalog::INHERITED_SUBSCRIPTION_DISABLED_MESSAGE
        );
        assert_eq!(
            std::env::var("JCODE_RUNTIME_PROVIDER").as_deref(),
            Ok("sentinel")
        );
        assert_eq!(
            std::env::var("JCODE_ACTIVE_PROVIDER").as_deref(),
            Ok("sentinel")
        );
        assert_eq!(
            std::env::var("JCODE_SUBSCRIPTION_ACTIVE").as_deref(),
            Ok("1")
        );

        crate::env::remove_var("JCODE_RUNTIME_PROVIDER");
        crate::env::remove_var("JCODE_ACTIVE_PROVIDER");
        crate::env::remove_var("JCODE_SUBSCRIPTION_ACTIVE");
    }

    #[tokio::test]
    async fn provider_impl_is_inert_even_for_an_internal_instance() {
        let provider = JcodeProvider;
        assert!(provider.available_models().is_empty());
        assert!(provider.available_models_display().is_empty());
        assert!(provider.model_routes().is_empty());
        assert!(provider.set_model("hostile").is_err());
        assert!(provider.prefetch_models().await.is_err());
        assert!(provider.complete(&[], &[], "hostile", None).await.is_err());
        assert!(
            provider
                .complete_split(&[], &[], "hostile", "hostile", None)
                .await
                .is_err()
        );
        assert!(provider.switch_active_provider_to("openrouter").is_err());
    }
}
