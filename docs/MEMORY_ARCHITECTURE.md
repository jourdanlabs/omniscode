# Inherited Memory Subsystem

**Status:** upstream implementation reference; outside the OMNIS KEY Local
Integrity V1 claim.

The inherited jcode tree contains local memory types, graph storage, embedding
code, retrieval code, and optional provider-backed helper paths. This document
does not claim that those paths are deployed, production-ready, complete,
private, non-blocking, or validated for a particular model or performance
level.

OMNIS KEY Local Integrity V1 is scoped to the receipt and safety-state
proposition in [`OPEN_SOURCE_V1_RELEASE_SPEC.md`](./OPEN_SOURCE_V1_RELEASE_SPEC.md).
The inherited memory subsystem is not part of that integrity proposition, the
fixture-only demo, or the release evidence claim.

## Source map

The source, rather than this note, is authoritative:

- `crates/jcode-memory-types/` defines memory and graph data types.
- `crates/jcode-base/src/memory.rs` and
  `crates/jcode-base/src/memory_agent.rs` contain inherited storage and
  retrieval integration.
- `crates/jcode-base/src/embedding_backend.rs` contains embedding-backend
  selection.
- `crates/jcode-app-core/src/agent/` contains agent-turn integration.

Any provider-backed memory operation is an inherited provider behavior, not an
offline OMNIS integrity operation. Public V1 verification requires minimal
startup to make zero ambient network attempts; explicit provider use remains a
separate user action.

## Privacy boundary

Memory content may be persisted locally in human-readable form. Do not place
credentials, secrets, private keys, or other sensitive material in memory
content. The public V1 makes no claim that inherited filtering is exhaustive,
that stored content is encrypted, or that a separately retained copy detects
same-user deletion or rollback.

No private soul, memory, operator, customer, credential, ledger, receipt,
trust, or activation artifact belongs in this repository or its fixtures.
