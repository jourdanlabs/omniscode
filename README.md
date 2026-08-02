# OMNIS CODE

**OMNIS CODE is a real coding agent — provider-agnostic, TUI + CLI — that proves what it did or refuses to say. Ambient auto-discovery is off. **Every mutating action** (edit, write, bash) is receipted in a hash-chained ledger, redacted by default: shape and hashes, never raw secrets. You pick your provider, you authorize the work, and mutations leave a verifiable receipt — or the tool fails closed.**

MIT. Upstream attribution in `LICENSE` and `NOTICE.md`.

| Binary | Role |
|--------|------|
| `omnis-code` | The coding agent (TUI + CLI) |
| `omnis-key` | The receipt / integrity engine |

### Claim Ledger (new)

> Every other coding agent tells you what it did. This one proves it — or refuses to say.

Agent claims about the codebase are **certified by real tools** (git, build, tests) or
**visibly refused**. Stage-3 verification never calls a model. See
[`docs/CLAIM_LEDGER.md`](docs/CLAIM_LEDGER.md).

**Refusal is a product feature, not a failure.** Example:

```bash
omnis-key claims verify --refuse-demo
# → REFUSED_NO_VERIFIER  "this is faster"  (we do not benchmark)
# → UNGROUNDED           "more idiomatic"  (not falsifiable)
```

```bash
omnis-key claims verify --files-changed src/lib.rs --claims-strict
omnis-key claims verify --build-command cargo,check
cargo test -p jcode-claims -p jcode-verifiers
```

Nothing about coding was removed. What v1 turns off is the surface a bank would refuse to install.

---

## What v1 does **not** do

- **No auto-update** — no silent binary upgrade or re-exec  
- **No auto-reload** — no ambient server reload fan-out  
- **No ambient credential discovery on startup** — an API key sitting in your environment
  does not create a provider route. A credential **you saved yourself** (`omnis-code login`)
  *does* arm its route on the next start: saving it was the act. What is off is the
  ambient path — env vars and stray credential files inventing routes you never chose  
- **No provider routes before you pick one** — Auto startup stays empty until explicit selection  
- **Checkpoint authority is dark by default** — signing daemon/install/activation is **not** provisioned by these sources; the engine is local receipts first  

The quarantine **is** the product. Say it out loud.

---

## Platforms

**Proven for this release track: macOS (Apple Silicon builder receipts).**  
Linux platform receipts are **not** claimed until retained.

---

## Build & test (supported invocations)

```bash
git clone https://github.com/jourdanlabs/omniscode.git
cd omniscode
cargo build --release -p omnis-key-cli --bin omnis-key
cargo build --release -p jcode --bin jcode

# Required integrity matrix (see docs / release receipts)
cargo test -p jcode-omnis
cargo test -p omnis-key-cli
cargo test -p jcode-base --lib omnis
cargo test -p jcode-base --lib safety
# …
```

**Supported full-package TUI suite:** run `jcode-tui` in isolation:

```bash
cargo test -p jcode-tui --lib
# or: cargo test -p jcode-tui --lib -- --test-threads=1
```

Concurrent full-workspace runs can hit inherited cross-package fixture debt; that is **not** the supported ship path.

---

## Quick path

See [`docs/QUICKSTART.md`](docs/QUICKSTART.md).

```bash
./target/release/omnis-key demo integrity
./target/release/omnis-code login    # explicit provider
./target/release/omnis-code run "…"  # coding turn
./target/release/omnis-key receipts status
```

---

## Dependency notes (honest)

Unsuppressed `cargo audit` reports **zero vulnerabilities** when run under the pinned advisory DB.  
Four **informational unmaintained** crates remain named (not hidden):

| Crate | Status |
|-------|--------|
| `bincode 1.3.3` | unmaintained (informational) |
| `paste 1.0.15` | unmaintained (informational) |
| `rustybuzz 0.20.1` | unmaintained (informational) |
| `ttf-parser 0.25.1` | unmaintained (informational) |

These are **not** the same thing as known vulnerabilities. They are still named.

---

## Named HOLDs that remain visible

- `HOLD-DEMO-SIGKILL-RECLAMATION-CAPABILITY` — after uncatchable SIGKILL, same-UID preplant vs fixture remnant cannot be distinguished; isolation above a shared OS user is the operator bound  
- `INHERITED_CROSS_PACKAGE_TEST_ISOLATION_DEBT` — use isolated TUI invocation above  
- `INHERITED_FLAKY_TEST_PROCESS_TITLE_ORDERING` — `process_title::tests::terminal_session_label_for_id_prefers_todo_title_over_generated_title` is order-dependent and fails intermittently under parallel execution (roughly one run in three). It passes alone and under `--test-threads=1`. Inherited, not introduced by this release; named rather than retried away  
- `INHERITED_WORKSPACE_CLIPPY_DEBT` — `cargo clippy --workspace --all-targets -- -D warnings` reports **26 errors**, all inherited style lints (`needless_return`, `needless_lifetimes`, `type_complexity`) concentrated in `jcode-app-core` and `jcode-setup-hints`. None affect behaviour, and none are in a documented command. The release matrix crates — `jcode-base`, `jcode-omnis`, `omnis-key-cli` — are clippy-clean at `-D warnings`. Counted and named rather than suppressed  
- Public ship pin uses a short orphan release history. Lineage to builder `bad4cb9a` is retained in release notes  

### On the secret scan, said plainly

An earlier cut of this release passed its own secret-scan leg, and that pass was
not earned: four Google OAuth client credentials inherited from upstream were
suppressed by inline `gitleaks:allow` comments, and the scan receipt did not
disclose the suppressions. GitHub's push protection, which does not honor those
comments, rejected the push and named all four.

They are gone. Gemini and Antigravity auth are now bring-your-own-client: set
the documented environment variables, or the provider returns an error naming
the variable to set. There is no embedded fallback, and three tests fail if one
is ever reintroduced. No `gitleaks:allow` remains anywhere in the tree.

It is recorded here because a project that ships receipts does not get to
quietly fix the one time its own receipt overstated a result.

**Two OAuth client IDs remain in the tree, on purpose.** `GITHUB_COPILOT_CLIENT_ID`
(`crates/jcode-base/src/auth/copilot.rs`) and `CURSOR_OAUTH_CLIENT_ID`
(`crates/jcode-base/src/auth/cursor.rs`) are **public device-flow client identifiers with
no accompanying secret** — the category of value that is published in every compatible
client because the flow requires the user to authorize in a browser. That is a different
thing from the four Google credentials above, which carried secrets. The line is drawn on
*is there a secret attached*, not on *does it look like an ID*. Named here so the next
person to grep does not have to guess why one set left and one stayed.


Checkpoint authority activation, LIVE providers, Door publication, and signed RC ceremony are **out of band** for this source pin.

---

## Lineage

MIT. Upstream attribution preserved in full — see `LICENSE` and `NOTICE.md`. JourdanLabs authored the Claim Ledger, the receipt engine, and the V1 quarantine.
