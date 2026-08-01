//! Build-enforced rule: jcode-verifiers must never depend on LLM / provider crates.

use std::fs;
use std::path::PathBuf;

#[test]
fn cargo_toml_has_no_provider_or_model_dependencies() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let text = fs::read_to_string(&manifest).expect("read Cargo.toml");
    let forbidden = [
        "jcode-provider",
        "jcode-base",
        "jcode-app-core",
        "jcode-tui",
        "openai",
        "anthropic",
        "reqwest",
        "async-openai",
        "rig-core",
        "candle-",
    ];
    for needle in forbidden {
        assert!(
            !text.contains(needle),
            "jcode-verifiers must not depend on `{needle}` — stage 3 is deterministic tools only"
        );
    }
    // Allowed stack is intentionally tiny.
    assert!(text.contains("serde"));
    assert!(text.contains("thiserror"));
}

#[test]
fn lib_docs_state_no_model_rule() {
    let lib = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
    let text = fs::read_to_string(lib).expect("lib.rs");
    assert!(
        text.contains("no model call") || text.contains("NO model"),
        "crate docs must state the no-model rule in plain language"
    );
}
