//! User-configured third-party catalog constants.
//!
//! Optional third-party discovery is disabled unless the user supplies an
//! explicit endpoint. OMNIS KEY ships no hosted directory, endorsement
//! program, or attribution service.
//!
//! Design constraints:
//! - Discovery is off by default.
//! - An explicit non-Jcode endpoint and `[sponsors] enabled = true` are both
//!   required.
//! - The category list below is a shipped constant, so building the tool schema
//!   never requires a network request.
//! - Tools within a category live server-side and are fetched on demand by
//!   `discover_tools`. If the request fails, the tool fails plainly. There is
//!   no cache and no offline fallback.
//! - Requests carry only discovery fields (category, query, tool, and reason),
//!   never session content.

/// Public source location for the fork's catalog boundary.
pub const DISCOVERY_CATALOG_SOURCE_URL: &str = "https://github.com/jourdanlabs/omniscode";

/// Inert compatibility boundary for inherited discovery attribution.
pub mod provenance;

/// Internal marker used to render the first discovery disclosure in a session.
pub const DISCOVERY_DISCLOSURE_TAG: &str = "(third-party catalog disclosure)";

/// First-use-per-session disclosure detail rendered inline with discovery.
pub const DISCOVERY_DISCLOSURE_NOTICE: &str =
    "This result came from the user-configured discovery endpoint.";

/// Categories in which discoverable tools exist. Shipped as a constant so the
/// tool schema never depends on the network. The tools within each category are
/// served by the discovery endpoint.
pub const DISCOVERY_CATEGORIES: &[&str] = &[
    "payments",
    "code-review",
    "databases",
    "browser-automation",
    "deployment",
    "observability",
    "authentication",
    "security",
    "storage",
    "analytics",
    "web-search",
    "web-data",
    "financial-data",
    "cloud-infrastructure",
    "compliance-and-privacy",
    "integration-platforms",
    "email-messaging",
    "ai-models",
    "other",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories_are_nonempty_and_lowercase() {
        assert!(!DISCOVERY_CATEGORIES.is_empty());
        for cat in DISCOVERY_CATEGORIES {
            assert!(!cat.is_empty());
            assert_eq!(cat.to_ascii_lowercase(), *cat);
            assert!(!cat.contains(' '), "categories are slugs: {cat}");
        }
    }

    #[test]
    fn categories_match_the_public_discovery_taxonomy() {
        assert_eq!(
            DISCOVERY_CATEGORIES,
            &[
                "payments",
                "code-review",
                "databases",
                "browser-automation",
                "deployment",
                "observability",
                "authentication",
                "security",
                "storage",
                "analytics",
                "web-search",
                "web-data",
                "financial-data",
                "cloud-infrastructure",
                "compliance-and-privacy",
                "integration-platforms",
                "email-messaging",
                "ai-models",
                "other",
            ]
        );
    }

    #[test]
    fn discovery_is_disabled_by_default() {
        let config = crate::config::Config::default();
        assert!(!config.sponsors.enabled);
        assert!(config.sponsors.endpoint.is_empty());
    }
}
