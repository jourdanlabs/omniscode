# Security policy

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting** flow for this repository:

`https://github.com/jourdanlabs/omniscode/security/advisories/new`

Do not open a public issue for an undisclosed vulnerability. This project does
not publish an unverified security email address.

Include the affected commit, platform, minimal reproduction, expected refusal,
actual behavior, and whether private data or a network/filesystem boundary was
crossed. Use synthetic fixtures; never include a real credential, key, ledger,
receipt, customer, or operator artifact.

## Supported versions

No production-supported version exists yet. Security work is evaluated against
the exact immutable candidate identified by its commit and tree. The `0.1.0`
developer preview is source-only.

## Scope and claim ceiling

High-priority reports include:

- receipt parser or chain acceptance of malformed, partial, inconsistent,
  replay-conflicting, reordered, orphaned, drifted, or mismatched bytes;
- safety decision/outbox/receipt atomicity failures;
- canonical state-path ownership, mode, symlink, or ACL bypasses;
- unexpected network or filesystem effects in an offline integrity command;
- inherited updater, telemetry, discovery, account, install, release, or
  support behavior reachable from a distributed executable;
- secret-scan, archive, manifest, provenance, or license fail-open behavior.

V1 does not claim evidence truth, encrypted state, hostile same-UID rollback
resistance, or detection of rollback to an internally valid prefix without a
separately retained checkpoint. The checkpoint authority is experimental
source and is not installed or active.

## Disclosure

Please allow maintainers time to reproduce and prepare a source fix before
public disclosure. A fix is not released until it is independently reviewed
against a new exact candidate identity.
