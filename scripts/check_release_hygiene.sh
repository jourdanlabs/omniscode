#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

fail=0

active_workflows=$(find .github/workflows -type f \( -name '*.yml' -o -name '*.yaml' \) -print | LC_ALL=C sort)
if [ "$active_workflows" != ".github/workflows/ci.yml" ]; then
  printf 'release-hygiene error: expected only .github/workflows/ci.yml, found:\n%s\n' \
    "$active_workflows" >&2
  fail=1
fi

if grep -En '(^|[[:space:]])(release|deployment|schedule):|tags:|secrets\.|permissions:[[:space:]]*write|contents:[[:space:]]*write' \
  .github/workflows/ci.yml >/dev/null 2>&1; then
  printf 'release-hygiene error: active CI contains a publication trigger, secret, or write permission\n' >&2
  fail=1
fi

for forbidden in \
  RELEASING.md \
  TELEMETRY.md \
  telemetry-worker \
  scripts/quick-release.sh \
  scripts/generate_release_notes.sh \
  scripts/install.sh \
  scripts/install.ps1 \
  scripts/install_release.sh \
  scripts/update_packages.sh \
  scripts/desktop2_mutation_sweep.sh \
  scripts/desktop2_visual_check.sh \
  scripts/desktop_gallery_golden.py \
  scripts/desktop_journey_e2e.sh \
  scripts/desktop_perf_report.py \
  scripts/desktop_reload_window_e2e.sh \
  scripts/desktop_visual_report.py \
  scripts/repro/tls-bad-record-mac \
  scripts/widget_quality.py \
  crates/jcode-desktop \
  crates/jcode-desktop2 \
  crates/jcode-harness-api-server \
  docs/DESKTOP2_VISUAL_CHECKLIST.md \
  docs/DESKTOP_CODEBASE_ARCHITECTURE.md \
  docs/DESKTOP_SINGLE_SESSION_DESIGN.md \
  docs/DESKTOP_SUPERAPP_WORKSPACE.md \
  docs/FINDING_SLOWNESS.md \
  docs/HARNESS_API_AND_DESKTOP_REWRITE.md \
  docs/IOS_APP.md \
  docs/plans/DESKTOP_BUILD_OUT_PLAN.md \
  ios \
  tests/desktop-gallery-golden \
  packaging; do
  if [ -f "$forbidden" ] || [ -L "$forbidden" ] ||
     { [ -d "$forbidden" ] && find "$forbidden" -type f -print -quit | grep -q .; }; then
    printf 'release-hygiene error: quarantined path remains active: %s\n' "$forbidden" >&2
    fail=1
  fi
done

if find assets/demos assets/readme docs/images -type f -print -quit 2>/dev/null | grep -q .; then
  printf 'release-hygiene error: nonessential inherited media remains in the candidate tree\n' >&2
  fail=1
fi

if git grep -En '^[[:space:]]*@main([[:space:]]|$)' -- '*.swift' >/dev/null 2>&1; then
  printf 'release-hygiene error: a Swift application entrypoint remains in the candidate tree\n' >&2
  fail=1
fi

[ "$fail" -eq 0 ] || exit 1
printf 'release hygiene verified: active_workflows=1 publication_paths=0 telemetry_deployment=0 non_v1_executable_trees=0\n'
