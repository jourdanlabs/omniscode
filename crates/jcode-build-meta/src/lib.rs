//! Compile-time version metadata for jcode.
//!
//! The build script (`build.rs`) computes git- and version-derived values and
//! emits them via `cargo:rustc-env`. Runtime environment variables are never
//! allowed to alter release identity in OMNIS KEY Local Integrity V1.

/// Compile-time human-readable version string, e.g. `v0.14.6-dev (abc1234)`.
pub const VERSION: &str = env!("JCODE_VERSION");
/// Short git hash of the build commit, e.g. `abc1234` (or `unknown`).
pub const GIT_HASH: &str = env!("JCODE_GIT_HASH");
/// Commit date/time of the build commit (or `unknown`).
pub const GIT_DATE: &str = env!("JCODE_GIT_DATE");
/// `git describe --tags --always` output (may be empty).
pub const GIT_TAG: &str = env!("JCODE_GIT_TAG");
/// Compile-time auto-incrementing build semver (dev) or explicit release semver.
pub const SEMVER: &str = env!("JCODE_SEMVER");
/// Compile-time base semver taken from the root `Cargo.toml` package version.
pub const BASE_SEMVER: &str = env!("JCODE_BASE_SEMVER");
/// Compile-time semver used for update comparisons.
pub const UPDATE_SEMVER: &str = env!("JCODE_UPDATE_SEMVER");
/// Encoded changelog (record/unit separated). See build.rs for the format.
pub const CHANGELOG: &str = env!("JCODE_CHANGELOG");
/// Compile-time root crate package version.
pub const PKG_VERSION: &str = env!("JCODE_PKG_VERSION");

/// Runtime release overrides are disabled; release identity is compile-time only.
pub fn runtime_release_semver() -> Option<&'static str> {
    None
}

/// Human-readable compile-time version.
pub fn version() -> &'static str {
    VERSION
}

/// Compile-time git hash.
pub fn git_hash() -> &'static str {
    GIT_HASH
}

/// Compile-time git date.
pub fn git_date() -> &'static str {
    GIT_DATE
}

/// Compile-time git tag.
pub fn git_tag() -> &'static str {
    GIT_TAG
}

/// Compile-time build semver.
pub fn semver() -> &'static str {
    SEMVER
}

/// Compile-time base semver.
pub fn base_semver() -> &'static str {
    BASE_SEMVER
}

/// Compile-time update-comparison semver.
pub fn update_semver() -> &'static str {
    UPDATE_SEMVER
}

/// Compile-time package version.
pub fn pkg_version() -> &'static str {
    PKG_VERSION
}

/// Whether this process should behave as a release build.
pub fn is_release_build() -> bool {
    option_env!("JCODE_RELEASE_BUILD").is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_runtime_release_env_cannot_override_compile_time_identity() {
        let hostile = [
            ("JCODE_RUNTIME_RELEASE_SEMVER", "99.88.77"),
            ("JCODE_RUNTIME_RELEASE_GIT_HASH", "attacker"),
            ("JCODE_RUNTIME_RELEASE_GIT_DATE", "2099-01-01"),
            ("JCODE_RUNTIME_RELEASE_GIT_TAG", "v99.88.77"),
        ];
        let saved = hostile
            .iter()
            .map(|(name, _)| (*name, std::env::var(name).ok()))
            .collect::<Vec<_>>();

        for (name, value) in hostile {
            // SAFETY: this test binary has no other tests that inspect these
            // retired variables, and every value is restored below.
            unsafe { std::env::set_var(name, value) };
        }

        assert_eq!(runtime_release_semver(), None);
        assert_eq!(version(), VERSION);
        assert_eq!(git_hash(), GIT_HASH);
        assert_eq!(git_date(), GIT_DATE);
        assert_eq!(git_tag(), GIT_TAG);
        assert_eq!(semver(), SEMVER);
        assert_eq!(base_semver(), BASE_SEMVER);
        assert_eq!(update_semver(), UPDATE_SEMVER);
        assert_eq!(pkg_version(), PKG_VERSION);
        assert_eq!(
            is_release_build(),
            option_env!("JCODE_RELEASE_BUILD").is_some()
        );

        for (name, value) in saved {
            match value {
                Some(value) => {
                    // SAFETY: restores the process state saved above.
                    unsafe { std::env::set_var(name, value) };
                }
                None => {
                    // SAFETY: restores the process state saved above.
                    unsafe { std::env::remove_var(name) };
                }
            }
        }
    }
}
