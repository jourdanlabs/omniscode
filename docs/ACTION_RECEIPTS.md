# Agent action receipts (option B)

> Receipt the *shape and effect* of an action. Never its raw arguments.

## What is receipted

| Tool | Default | Fields (redacted) |
|------|---------|-------------------|
| `edit` | ✅ | target path, content_sha256 before→after, cwd/repo hashes |
| `write` | ✅ | same |
| `bash` | ✅ | `argv_program` (e.g. `node`), `argv_sha256`, `exit_code` — **never** full argv |
| `read` / search | ❌ | opt-in: `--receipt-reads` |

These fields are stored on the ledger line under `"evidence"` and bound by
`evidence_sha256` (not discarded after hashing). `argv_full` is never stored
unless `--receipt-full-argv` is set.

## Fail closed

If the ledger cannot append, the mutation is rolled back (edit/write) or refused
before run (bash preflight). Explicit opt-out: `--no-receipts` / `JCODE_NO_RECEIPTS=1`
(recorded in session policy — not silent).

## Dangerous opt-in

`--receipt-full-argv` / `JCODE_RECEIPT_FULL_ARGV=1` stores the full command string.
**Off by default.** Prints a warning when enabled. Do not use with secrets.

## Secret probe (gate)

```bash
# after an agent bash with a bearer token in argv:
grep -r 'SECRET123' ~/.jcode/   # must be empty under default redaction
```

## Provenance ≠ veracity

Receipts prove **what happened**. Claim Ledger (S1) speaks to falsifiable claims.
Do not blur "receipted" into "verified correct."

## Crate

`jcode-receipts` — agent-facing API + re-exports of `jcode_base::omnis` chain math.
`omnis-key-cli` uses the same append path; demo integrity stays byte-identical.
