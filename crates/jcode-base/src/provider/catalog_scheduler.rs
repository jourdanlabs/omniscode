//! Read-only catalog cache coordination.
//!
//! Inherited background catalog discovery is disabled for OMNIS KEY Local
//! Integrity V1. Route construction may read an existing cache, but it never
//! starts a timer, schedules a provider request, or writes refreshed state.

/// Invalidate every memoized route catalog in the process after an explicit
/// provider action updates state.
pub fn bump_catalog_generation() {
    super::CATALOG_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}
