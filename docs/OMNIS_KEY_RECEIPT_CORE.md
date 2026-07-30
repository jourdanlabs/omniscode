# OMNIS Key Receipt Core (Foundation)

The OMNIS KEY receipt core is a bounded local provenance primitive. It records
a cited SHA-256 evidence digest, a fixed claim ceiling, and a hash-linked
predecessor. The engine lives in `jcode-base` so lower-layer state machines can
emit receipts without depending on the CLI. The canonical public entrypoint is
`omnis-key`; the inherited `jcode omnis` spelling is only a compatibility
alias.

It is intentionally **not** an action executor, permission grant, provider
call, autonomy loop, or external-evidence verifier. A successful `verify`
means only that the receipt bytes currently present form a consistent local
chain. It does not detect a coordinated rollback without a separately managed
external checkpoint.

On Unix, the local writer serializes cooperating processes with a
crash-released file lock, refuses symlinked ledger, lock, and intermediate
directory paths, hardens private files through their opened handles, and
publishes each append through a same-directory, fsynced, atomic copy-on-write
replacement. Stable event IDs make the append idempotent for durable outbox
reconciliation. Those controls prevent accidental duplicates, partial
authoritative tails, or statically redirected writes; they do not defend
against an adversarial process running as the same UID. Windows crash-atomic
state replacement and handle-level reparse protection are not claimed by this
increment.

```text
omnis-key receipts record --event-id source-review:ce8dff \
  source.review "candidate ce8dff" \
  --evidence-sha256 <64-hex-digest>
omnis-key receipts verify
```

The public recorder always uses the claim ceiling `local-record`; callers
cannot select or override it. Public V1 commands also cannot override the
canonical user-local ledger path.

Safety decisions now emit a `LocalRecord` receipt only after the decision and
its durable outbox event commit through one atomic Unix state replacement.
That observation does not authorize or execute the requested action. Anchored
verification remains a distinct, fail-closed mode backed by an independently
owned checkpoint authority; it never silently falls back to this local-only
mode.

## Safety decision observation

The ambient permission queue now uses one authoritative
`safety/state.v1.json` transition protected by a crash-released interprocess
lock. A terminal transition atomically:

1. removes exactly one pending request;
2. stores the complete original request and a distinct
   `approved` / `denied` / `expired` decision;
3. stores an OMNIS outbox event whose evidence digest binds both records.

Only after that state commit does the outbox append
`safety.permission.<outcome>` with a `local-record` ceiling. The stable
decision event ID makes a retry return the existing receipt instead of
duplicating it. If receipt writing fails, the decision remains committed, the
outbox remains pending, and the caller receives
`SAFETY_DECISION_COMMITTED_RECEIPT_PENDING`.

Every safety reconciliation and safety-outbox status read verifies both sides
of the binding: acknowledged decisions must match their exact receipt hash,
kind, subject, evidence digest, event ID, and claim ceiling; safety receipts
must correspond to either an acknowledged decision or its still-pending outbox
event. Parseable drift, deleted decision history, and orphaned or miskinded
safety receipts refuse. The generic `omnis-key receipts status` and
`omnis-key receipts verify` commands remain chain-only views and label that
narrower integrity scope in their output.

```text
omnis-key receipts reconcile-safety --json
```

Reconciliation is observational. It does not approve, resume, or execute an
action. Unknown and already-terminal request IDs refuse. Corrupt state is not
reseeded or recovered from a backup implicitly. Existing legacy queue/history
files are imported once, under the same lock, only when they parse and satisfy
the unified-state invariants. If the ambient runner cannot read permission
state, it records the pending count as unknown and raises notification priority
instead of reporting a false zero.
