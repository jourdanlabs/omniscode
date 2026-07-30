# Contributing to OMNIS KEY

Thank you for helping make the local-integrity contract smaller, clearer, and
harder to fool.

## Start with the boundaries

Read `README.md`, `docs/THREAT_MODEL.md`, and
`docs/OPEN_SOURCE_V1_RELEASE_SPEC.md` before changing an integrity path.

Do not add private identity, memory, operator, customer, credential, key,
ledger, receipt, trust, or activation material. Fixtures must be synthetic and
marked fixture-only. Do not use real provider credentials in tests.

V1 is source-only. Contributions must not add an installer, updater,
telemetry/account/support service, checkpoint activation, publication
automation, provider-spend test, or claim of evidence truth.

## Clone without the removed media history

The repository retains public history, including large upstream media that is
absent from the V1 tree. A partial clone avoids downloading those historical
blobs:

```bash
git clone --filter=blob:none \
  https://github.com/jourdanlabs/omniscode.git
cd omniscode
git remote add upstream https://github.com/1jehuang/jcode.git
git remote set-url --push upstream DISABLED
git remote -v
```

Treat `upstream` as fetch-only. Push work only to a fork or a JourdanLabs
branch for which you are authorized.

## Development

Use a focused branch and keep changes reviewable. Run targeted tests while
iterating, then the release matrix relevant to your change. At minimum:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy -p jcode-omnis --all-targets -- -D warnings
cargo clippy -p omnis-key-cli --all-targets -- -D warnings
cargo test -p jcode-omnis
cargo test -p omnis-key-cli
git diff --check
```

Integrity changes need adversarial tests for malformed, partial, replayed,
reordered, orphaned, drifted, and mismatched state as applicable. Refusal paths
must remain fail-closed. A network-denied test is not proof of zero attempted
networking; use the repository's process instrumentation.

Do not rebaseline an inherited guardrail to hide release growth. See
`docs/UPSTREAM_DEBT.md`.

## Pull requests

Describe:

- the exact behavior and claim ceiling changed;
- tests and commands run, including exit status;
- network and filesystem effects;
- rights/provenance for every added asset or fixture;
- any known limit or named HOLD.

Do not label your own change `CLEAR`. Independent review binds a verdict to an
exact immutable candidate.

By contributing, you agree that your original contribution is offered under
the repository's MIT license and that you have the right to provide it.
