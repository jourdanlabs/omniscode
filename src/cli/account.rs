use anyhow::Result;

pub(crate) async fn run_login(_no_browser: bool) -> Result<()> {
    anyhow::bail!(
        "{}",
        crate::subscription_catalog::INHERITED_SUBSCRIPTION_DISABLED_MESSAGE
    )
}

pub(crate) async fn run_status(_json: bool) -> Result<()> {
    anyhow::bail!(
        "{}",
        crate::subscription_catalog::INHERITED_SUBSCRIPTION_DISABLED_MESSAGE
    )
}

pub(crate) fn run_manage() -> Result<()> {
    anyhow::bail!(
        "{}",
        crate::subscription_catalog::INHERITED_SUBSCRIPTION_DISABLED_MESSAGE
    )
}

pub(crate) async fn run_logout() -> Result<()> {
    anyhow::bail!(
        "{}",
        crate::subscription_catalog::INHERITED_SUBSCRIPTION_DISABLED_MESSAGE
    )
}
