# OMNIS CODE — Quickstart

Stranger path. No fake output.

## 1. Build

```bash
cargo build --release --bin omnis-key --bin jcode
```

## 2. Receipt engine

```bash
./target/release/omnis-key --version
./target/release/omnis-key demo integrity
```

You should see a deterministic integrity demo that exercises the local receipt surface. If a step refuses, the refusal is the product — read the message.

## 3. Provider (explicit)

```bash
./target/release/jcode login
# or set provider credentials via the documented env/config paths for your chosen provider
```

v1 will **not** invent routes from ambient discovery. Pick a provider deliberately.

## 4. One coding turn + receipts

```bash
./target/release/jcode run "write a Rust function that reverses a string"
./target/release/omnis-key receipts status
```

**Honest status for ship-day operators:** if step 4 is not green end-to-end in your environment (provider keys, network, host), steps 1–3 still prove the binary pair and receipt engine. Do not paste fictional receipt output into demos.

## Supported test surface

```bash
cargo test -p jcode-omnis
cargo test -p omnis-key-cli
cargo test -p jcode-tui --lib
```

See the root README for the full required matrix and HOLDs.
