# Dependency Security Triage

Last reviewed: 2026-07-29

This file tracks the current `cargo audit` findings for jcode and the intended
remediation path. It is not an allowlist. At the pinned advisory-database
commit, the unsuppressed scan reports zero vulnerabilities and four
informational unmaintained warnings. The current
`config/security/advisory_exceptions.json` proposal set is empty.

If a future precisely scoped, expiring proposal is added, it remains a builder
proposal rather than a reviewed exception. The security preflight rejects an
expired, future-proposed, malformed, duplicate, stale, or unlisted tuple and
retains `PENDING_INDEPENDENT_REVIEW` plus its named HOLD. With an empty proposal
set, the preflight instead requires an unsuppressed exit status of zero and an
exactly empty vulnerability list.

## Current advisories

| Advisory | Crate | Dependency path | Affected area in jcode | Triage | Planned action |
|---|---|---|---|---|---|
| `RUSTSEC-2025-0141` | `bincode` | `syntect -> bincode` | Markdown/code highlighting in the TUI | Unmaintained transitive dependency. No direct exposure in the provider/auth flow. | Track `syntect` upgrades or replace `syntect` if upstream does not move off `bincode` soon. |
| `RUSTSEC-2024-0436` | `paste` | `jcode-embedding -> tokenizers -> paste` | Tokenizer/model support | Unmaintained transitive proc macro. The upgraded `tract-*` stack no longer contributes this dependency. | Upgrade or replace the tokenizer stack when it moves off `paste`. |
| `RUSTSEC-2026-0192` | `ttf-parser` 0.25.1 | terminal font stack | Font parsing | Unmaintained transitive version. | Migrate the coordinated terminal font stack to a maintained parser. |
| `RUSTSEC-2026-0206` | `rustybuzz` 0.20.1 | terminal font stack | Font shaping | Unmaintained transitive version. | Migrate to a maintained shaping stack such as upstream `harfrust` support. |

## Priority order

1. Unmaintained font, `bincode`, and `paste` dependencies.

## Notes

- None of the advisories above were introduced by the provider-auth refactor.
- `RUSTSEC-2026-0217` was removed by upgrading the coordinated `tract-*`
  stack to 0.22.3.
- `RUSTSEC-2026-0190` and `RUSTSEC-2026-0097` were removed by compatible
  lockfile upgrades to `anyhow` 1.0.103 and `rand` 0.8.6.
- The locked `rustls-webpki` 0.103.13 is outside the affected ranges for
  `RUSTSEC-2026-0049`, `RUSTSEC-2026-0098`, `RUSTSEC-2026-0099`, and
  `RUSTSEC-2026-0104`; those obsolete proposals were removed.
- The locked PDF path is `jcode-pdf -> pdf-extract 0.12.0 -> lopdf 0.42.0`,
  so the obsolete `RUSTSEC-2026-0187` proposal was removed.
- The pinned `RUSTSEC-2026-0141` advisory marks `lettre >= 0.11.22` patched.
  The locked version is 0.11.22, so the stale proposal was removed.
- The provider/auth hardening work should continue independently of these dependency upgrades.
- `RUSTSEC-2024-0320` (`yaml-rust`) was removed from the dependency graph on 2026-03-05 by trimming `syntect` features to built-in syntax/theme dumps instead of YAML loading.
- `scripts/security_preflight.sh` runs an unsuppressed audit before applying
  any proposed ignore. An empty proposal set requires exactly zero
  vulnerabilities. A nonempty set requires every proposed ID to match the
  exact configured package and locked version in the complete observed
  vulnerability set. The script records that mapping as pending in retained
  evidence, fails closed on every other vulnerability, and embeds every
  informational warning ID/package/version in the retained report. The builder
  does not approve its own proposals or call the warning set clean.
- Before changing dependency versions, run:
  - `cargo check`
  - `cargo test -j 1`
  - `scripts/security_preflight.sh`
