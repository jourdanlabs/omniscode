# OMNIS CODE

**jcode is a real coding agent — provider-agnostic, TUI + CLI. OMNIS CODE ships jcode with all auto-discovery disabled and every action receipted in a hash-chained ledger. You explicitly pick your provider, you explicitly authorize each turn, and every action leaves a verifiable receipt.**

This is a transparently attributed MIT fork of [jcode](https://github.com/1jehuang/jcode) (© Jeremy Huang), with JourdanLabs-authored integrity and receipt work on top. See `LICENSE` and `NOTICE.md`.

| Binary | Role |
|--------|------|
| `jcode` | The coding agent (TUI + CLI) |
| `omnis-key` | The receipt / integrity engine |

Nothing about coding was removed. What v1 turns off is the surface a bank would refuse to install.

---

## What v1 does **not** do

- **No auto-update** — no silent binary upgrade or re-exec  
- **No auto-reload** — no ambient server reload fan-out  
- **No ambient credential discovery on startup** — credentials do not invent routes until you act  
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
./target/release/jcode login    # explicit provider
./target/release/jcode run "…"  # coding turn
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


Checkpoint authority activation, LIVE providers, Door publication, and signed RC ceremony are **out of band** for this source pin.

---

## Lineage

MIT. Upstream jcode attribution preserved. JourdanLabs modifications are for local integrity, receipts, and the V1 quarantine. See `NOTICE.md`.
