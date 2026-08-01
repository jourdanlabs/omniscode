//! Compatibility boundary for inherited discovery attribution.
//!
//! OMNIS KEY Local Integrity V1 does not tag MCP connections, meter calls, or
//! report discovery activity. These entry points remain so downstream MCP and
//! tool code can keep a stable interface without ambient tracking or network
//! behavior.

use serde::{Deserialize, Serialize};

/// A setup parsed from a user-configured third-party catalog response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredSetup {
    pub sponsor: String,
    pub command: String,
    pub args: Vec<String>,
}

/// Discovery responses are not retained for attribution or metering.
pub fn record_discovered_setups(_setups: Vec<DiscoveredSetup>) {}

/// MCP connections are never tagged by discovery history.
pub fn on_server_connected(_server_name: &str, _command: &str, _args: &[String]) -> Option<String> {
    None
}

/// MCP calls are never metered.
pub fn on_tool_call(_server_name: &str, _is_error: bool) {}

/// No server carries inherited discovery attribution.
pub fn is_tagged(_server_name: &str) -> bool {
    false
}

/// Shutdown performs no discovery report or network activity.
pub fn flush_now() {}

#[cfg(test)]
pub(crate) fn reset_for_tests() {}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct UsageReport {
    pub sponsor: String,
    pub day: String,
    pub connects: u64,
    pub calls: u64,
    pub errors: u64,
}

#[cfg(all(test, unix))]
pub(crate) fn drain_pending_for_tests() -> Vec<UsageReport> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inherited_attribution_and_metering_are_inert() {
        record_discovered_setups(vec![DiscoveredSetup {
            sponsor: "example".into(),
            command: "example-mcp".into(),
            args: vec!["--stdio".into()],
        }]);
        assert_eq!(
            on_server_connected("example", "example-mcp", &["--stdio".into()]),
            None
        );
        on_tool_call("example", false);
        assert!(!is_tagged("example"));
        flush_now();
    }
}
