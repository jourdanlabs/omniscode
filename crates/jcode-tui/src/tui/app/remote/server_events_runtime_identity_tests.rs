use super::{
    parse_release_semver, rate_limit_notice, server_release_is_older_than_client,
    should_defer_history_for_runtime_identity_with_allow,
};

#[test]
fn runtime_identity_gate_defers_stale_server_history_by_default() {
    assert!(should_defer_history_for_runtime_identity_with_allow(
        Some(true),
        false,
        false
    ));
    assert!(!should_defer_history_for_runtime_identity_with_allow(
        Some(false),
        false,
        false
    ));
    assert!(!should_defer_history_for_runtime_identity_with_allow(
        None, false, false
    ));
}

#[test]
fn runtime_identity_gate_allows_explicit_mismatch_escape_hatch() {
    assert!(!should_defer_history_for_runtime_identity_with_allow(
        Some(true),
        false,
        true
    ));
    assert!(!should_defer_history_for_runtime_identity_with_allow(
        None, true, true
    ));
}

#[test]
fn client_detected_older_server_always_defers() {
    assert!(should_defer_history_for_runtime_identity_with_allow(
        None, true, false
    ));
    assert!(should_defer_history_for_runtime_identity_with_allow(
        Some(false),
        true,
        false
    ));
    assert!(!should_defer_history_for_runtime_identity_with_allow(
        Some(false),
        false,
        false
    ));
}

#[test]
fn parse_release_semver_refuses_unorderable_dev_builds() {
    assert_eq!(parse_release_semver("v0.17.0 (d741696f)"), Some((0, 17, 0)));
    assert_eq!(parse_release_semver("0.14.2"), Some((0, 14, 2)));
    assert_eq!(parse_release_semver("v0.18.4-dev (102e9750, dirty)"), None);
    assert_eq!(parse_release_semver("v0.14.2-dev (38452185, dirty)"), None);
    assert_eq!(parse_release_semver("unknown"), None);
}

#[test]
fn server_release_older_than_client_is_selfdev_safe() {
    assert!(server_release_is_older_than_client(
        Some("v0.14.2 (38452185)"),
        "v0.17.0 (d741696f)"
    ));
    assert!(!server_release_is_older_than_client(
        Some("v0.17.0"),
        "v0.17.0"
    ));
    assert!(!server_release_is_older_than_client(
        Some("v0.18.0"),
        "v0.17.0"
    ));
    assert!(!server_release_is_older_than_client(
        Some("v0.14.2-dev (abc, dirty)"),
        "v0.17.0"
    ));
    assert!(!server_release_is_older_than_client(
        Some("v0.14.2"),
        "v0.17.0-dev (abc, dirty)"
    ));
    assert!(!server_release_is_older_than_client(None, "v0.17.0"));
}

#[test]
fn rate_limit_notice_has_no_subscription_pitch() {
    let notice = rate_limit_notice(42);
    assert_eq!(
        notice,
        "⏳ Rate limit hit. Will auto-retry in 42 seconds..."
    );
    assert!(!notice.contains("/subscribe"));
    assert!(!notice.contains("/login jcode"));
    assert!(!notice.to_ascii_lowercase().contains("subscription"));
}
