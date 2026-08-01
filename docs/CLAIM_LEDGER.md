# Claim Ledger (OMNIS CODE)

> **An agent's claims about your codebase are either grounded in the codebase, or
> visibly refused. Never asserted.**

This is STRATA/CAIRN discipline pointed at **code**, not a port of STRATA's TypeScript
or metric vocabulary. jcode's embeddings stay retrieval-only; this layer **certifies**.

## Stages

1. **EXTRACT** (S2) — LLM allowed only here  
2. **TYPE** — does a deterministic verifier exist? No → short-circuit  
3. **VERIFY** — real tools only (`jcode-verifiers`). **No model. Ever.**  
4. **RECEIPT** — hash-chained claim ledger  

### Load-bearing rule

Stage 3 contains no model call. Enforced by `jcode-verifiers` having zero provider
dependencies (`tests/no_provider_deps.rs`).

### SAMMICH short-circuit

When a claim cannot be typed as verifiable, **do not** emit a failed verification
field. Emit **no verification field at all**.  
*"We checked and couldn't confirm"* ≠ *"this was never checkable."*

## Frozen verdicts

| Verdict | Meaning |
|---------|---------|
| `CERTIFIED` | Verifier proved true |
| `REFUTED` | Verifier proved **false** |
| `REFUSED_NO_VERIFIER` | No deterministic verifier for this shape |
| `REFUSED_UNRESOLVED` | Verifier ran, could not decide |
| `UNGROUNDED` | Not a falsifiable claim |

`REFUSED_*` and `UNGROUNDED` are **integrity wins**. Metrics that punish them
manufacture dishonesty (same lesson as the Jiffy outcome ledger).

## S1 verifiers (shipped)

| Claim | Tool |
|-------|------|
| Files changed only set S | `git diff --name-only` + untracked |
| Build passes | command exit code |
| Tests pass | command exit code |

## Refusal rows (demo — product surface)

These are intentional and shippable **before** harder verifiers:

- "this is faster" → `REFUSED_NO_VERIFIER` (we do not benchmark)
- "matches the spec" → `REFUSED_NO_VERIFIER` (spec not machine-readable)
- "this is secure now" → `REFUSED_NO_VERIFIER` (absence unprovable)
- "more idiomatic" → `UNGROUNDED`

```bash
omnis-key claims verify --refuse-demo
```

## CLI

```bash
omnis-key claims status --json
omnis-key claims verify --files-changed a.rs,b.rs --repo .
omnis-key claims verify --build-command cargo,check
omnis-key claims verify --test-command cargo,test,--lib
omnis-key claims verify --claims-strict …   # exit 2 on any REFUTED
```

## Crates

- `jcode-claims` — types, typing, pipeline, claim ledger  
- `jcode-verifiers` — stage 3 only (no providers)  
- `jcode-omnis` — existing receipt authority (unchanged this slice)  
- `jcode-embedding` — untouched  

## What this does **not** claim

This proves **specific falsifiable claims**. It does not prove "the code is correct."
That gap stays visible — same provenance-vs-veracity line as OMNIS receipts.
