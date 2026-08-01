# Changelog

This file records OMNIS KEY changes. Historical jcode release-note data was
removed from the V1 candidate tree; upstream history remains available in Git.

## [Unreleased]

- No public release or tag has been created.

## [0.1.0] — candidate

- Added bounded, idempotent, hash-linked local receipt storage and refusal.
- Bound terminal safety decisions to durable receipt obligations with
  fail-closed reconciliation.
- Added an experimental, inactive signed checkpoint source kernel.
- Added the non-publishable `omnis-key` local-integrity CLI and fixture-only
  offline demonstration.
- Disabled inherited ambient telemetry, discovery, updater, account, support,
  install, and release behavior for the candidate.
- Replaced upstream product/release surfaces with OMNIS identity, attribution,
  read-only CI, fail-closed security/archive evidence, and governance files.

Version `0.1.0` is a developer preview, not a semantic-version `1.0.0`
stability promise.
