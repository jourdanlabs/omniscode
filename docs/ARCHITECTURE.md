# OMNIS KEY V1 architecture

## Product boundary

OMNIS KEY V1 adds a narrow local-integrity path to the inherited jcode agent
chassis. The local receipt path is designed to start before inherited logging,
configuration migration, hooks/plugins, telemetry, updater, provider
registration, or other ambient startup.

```text
terminal permission decision
        |
        v
atomic safety decision + receipt obligation
        |
        v
pending outbox obligation
        |
        +---- receipt publication failed ---> remains pending
        |
        v
bounded local receipt append
        |
        v
exact receipt/safety reconciliation
```

## Receipt chain

Each framed record is independently bounded before allocation. Canonical bytes
bind its sequence, predecessor, event identity, kind, subject, evidence digest,
and fixed `local-record` claim ceiling. Append is idempotent for an exact event
replay and refuses an event-ID collision with different content.

Verification starts from existing bytes and refuses malformed frames, partial
records, internal inconsistency, reordered records, and hash-link mismatch. It
does not silently reseed an invalid ledger.

An empty ledger is not positive evidence. Public status is
`EMPTY / NOT YET EVIDENCED`.

## Safety binding

A terminal ambient-permission decision and its receipt obligation are one
atomic state transition. Receipt publication is a later, idempotent step.
Failure leaves the exact obligation pending. Reconciliation accepts only the
matching receipt and refuses orphaned, drifted, or mismatched state.

## State boundary

Public receipt commands use one canonical, user-local state root. Creation
requires a private `0700` directory and `0600` files owned by the invoking
user. Reviewed path components must not be symlinks or carry unexpected ACLs.
Read-only commands do not create locks, migrate config, or create a ledger.

Stored fields are plaintext. Event IDs and subjects must not contain secrets.

## Experimental checkpoint kernel

The macOS checkpoint source contains a signed protocol, store, daemon, and
client designed for a separately owned authority. No installer, service
account, key, launchd definition, or activation is included. Without an active
separately retained checkpoint, valid-prefix rollback remains locally
undetected.

## Inherited chassis

Providers, TUI, sessions, tools, memory, swarm, and most internal `jcode`
namespaces are inherited. Desktop and iOS applications and their build/test
harnesses are quarantined and absent from the V1 source tree. The retained
chassis does not expand the OMNIS receipt claim. See `docs/UPSTREAM.md`.
