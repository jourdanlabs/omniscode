//! CLAIM LEDGER CLI surface — `omnis-key claims …`
//!
//! S1: verify structured claims with deterministic verifiers + hash-chained receipts.

use jcode_claims::{
    ClaimEvaluateOptions, ClaimInput, ClaimKind, ClaimLedger, ClaimVerdict, VERDICT_VOCABULARY,
    evaluate_claims,
};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;

use crate::output;

pub(crate) fn default_claim_ledger_path() -> anyhow::Result<PathBuf> {
    let home = std::env::var_os("JCODE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".jcode")))
        .ok_or_else(|| anyhow::anyhow!("cannot resolve JCODE_HOME or HOME"))?;
    Ok(home.join("state/omnis-key/claim-ledger.jsonl"))
}

pub(crate) fn status(json: bool, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let path = match default_claim_ledger_path() {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(stderr, "claim ledger path error: {e}");
            return 3;
        }
    };
    if !path.exists() {
        return output::emit::<()>(
            json,
            "claims status",
            false,
            "EMPTY_NOT_YET_EVIDENCED",
            None,
            3,
            (stdout, stderr),
        );
    }
    let ledger = match ClaimLedger::open(&path) {
        Ok(l) => l,
        Err(e) => {
            let _ = writeln!(stderr, "open ledger: {e}");
            return 3;
        }
    };
    let entries = match ledger.entries() {
        Ok(e) => e,
        Err(e) => {
            let _ = writeln!(stderr, "read ledger: {e}");
            return 3;
        }
    };
    let valid = ledger.verify_chain().unwrap_or(false);
    if !valid {
        return output::emit::<()>(
            json,
            "claims status",
            false,
            "CLAIM_CHAIN_INVALID",
            None,
            3,
            (stdout, stderr),
        );
    }
    #[derive(serde::Serialize)]
    struct StatusData {
        path: String,
        entry_count: usize,
        head_sha256: Option<String>,
        verdict_vocabulary: &'static [&'static str],
        thesis: &'static str,
    }
    let head = entries.last().map(|e| e.entry_hash.clone());
    let data = StatusData {
        path: path.display().to_string(),
        entry_count: entries.len(),
        head_sha256: head,
        verdict_vocabulary: VERDICT_VOCABULARY,
        thesis: jcode_claims::THESIS,
    };
    if entries.is_empty() {
        return output::emit(
            json,
            "claims status",
            false,
            "EMPTY_NOT_YET_EVIDENCED",
            Some(&data),
            3,
            (stdout, stderr),
        );
    }
    output::emit(
        json,
        "claims status",
        true,
        "CLAIM_CHAIN_VALID",
        Some(&data),
        0,
        (stdout, stderr),
    )
}

pub(crate) struct VerifyArgs {
    pub files_changed: Option<String>,
    pub base: Option<String>,
    pub build_command: Option<Vec<String>>,
    pub test_command: Option<Vec<String>>,
    pub refuse_demo: bool,
    pub claim_json: Option<String>,
    pub repo: PathBuf,
    pub ledger: Option<PathBuf>,
    pub claims_strict: bool,
    pub json: bool,
}

pub(crate) fn verify(args: VerifyArgs, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let mut inputs: Vec<ClaimInput> = Vec::new();

    if let Some(raw) = args.claim_json {
        if let Ok(one) = serde_json::from_str::<ClaimInput>(&raw) {
            inputs.push(one);
        } else if let Ok(many) = serde_json::from_str::<Vec<ClaimInput>>(&raw) {
            inputs.extend(many);
        } else {
            let _ = writeln!(stderr, "invalid --claim-json");
            return 2;
        }
    }

    if let Some(list) = args.files_changed {
        let declared: BTreeSet<String> = list
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        inputs.push(ClaimInput {
            id: format!("files-{}", inputs.len() + 1),
            kind: ClaimKind::FilesChanged {
                declared,
                base: args.base.clone(),
            },
            surface: Some("files-changed claim".into()),
        });
    }

    if let Some(command) = args.build_command {
        inputs.push(ClaimInput {
            id: format!("build-{}", inputs.len() + 1),
            kind: ClaimKind::BuildPasses { command },
            surface: Some("build passes".into()),
        });
    }

    if let Some(command) = args.test_command {
        inputs.push(ClaimInput {
            id: format!("tests-{}", inputs.len() + 1),
            kind: ClaimKind::TestsPass { command },
            surface: Some("tests pass".into()),
        });
    }

    if args.refuse_demo {
        inputs.push(ClaimInput {
            id: "demo-faster".into(),
            kind: ClaimKind::PerformanceFaster {
                note: Some(
                    "we do not benchmark; speed claims are REFUSED_NO_VERIFIER (demo refusal)"
                        .into(),
                ),
            },
            surface: Some("this is faster".into()),
        });
        inputs.push(ClaimInput {
            id: "demo-idiomatic".into(),
            kind: ClaimKind::MoreIdiomatic {
                note: Some("idiomatic is not falsifiable; UNGROUNDED (demo)".into()),
            },
            surface: Some("this is more idiomatic".into()),
        });
    }

    if inputs.is_empty() {
        let _ = writeln!(
            stderr,
            "no claims provided. Examples:\n  omnis-key claims verify --files-changed a.rs,b.rs\n  omnis-key claims verify --build-command cargo,check\n  omnis-key claims verify --refuse-demo\n  omnis-key claims verify --claim-json '{{\"id\":\"c1\",\"kind\":{{\"kind\":\"performance_faster\"}}}}'"
        );
        return 2;
    }

    let ledger = args.ledger.or_else(|| default_claim_ledger_path().ok());

    let opts = ClaimEvaluateOptions {
        repo: args.repo,
        ledger,
    };
    let batch = evaluate_claims(inputs, &opts);

    #[derive(serde::Serialize)]
    struct VerifyData<'a> {
        outcomes: &'a [jcode_claims::ClaimOutcome],
        any_refuted: bool,
        certified_count: usize,
        refused_count: usize,
        ungrounded_count: usize,
        claims_strict: bool,
        strict_exit_code: i32,
        thesis: &'static str,
    }
    let data = VerifyData {
        outcomes: &batch.outcomes,
        any_refuted: batch.any_refuted,
        certified_count: batch.certified_count,
        refused_count: batch.refused_count,
        ungrounded_count: batch.ungrounded_count,
        claims_strict: args.claims_strict,
        strict_exit_code: batch.strict_exit_code(),
        thesis: jcode_claims::THESIS,
    };

    if !args.json {
        for o in &batch.outcomes {
            let ver = o.verdict.as_str();
            let mark = match o.verdict {
                ClaimVerdict::Certified => "✓",
                ClaimVerdict::Refuted => "✗",
                ClaimVerdict::RefusedNoVerifier | ClaimVerdict::RefusedUnresolved => "⊘",
                ClaimVerdict::Ungrounded => "·",
            };
            let _ = writeln!(
                stdout,
                "{mark} {ver:<22} {}  {}",
                o.claim_id,
                o.surface.as_deref().unwrap_or(o.kind_name.as_str())
            );
            if let Some(r) = &o.reason {
                let _ = writeln!(stdout, "    reason: {r}");
            }
            if o.verification.is_none()
                && matches!(
                    o.verdict,
                    ClaimVerdict::RefusedNoVerifier
                        | ClaimVerdict::Ungrounded
                        | ClaimVerdict::RefusedUnresolved
                )
            {
                let _ = writeln!(
                    stdout,
                    "    (no verification field — claim was never verifiable / short-circuit)"
                );
            }
        }
        let _ = writeln!(
            stdout,
            "\nsummary: certified={} refused={} ungrounded={} refuted={}",
            batch.certified_count, batch.refused_count, batch.ungrounded_count, batch.any_refuted
        );
    }

    let code = if args.claims_strict {
        batch.strict_exit_code()
    } else if batch.any_refuted {
        0 // non-strict: refutation is information, not process failure
    } else {
        0
    };

    let status_code = if batch.any_refuted {
        "CLAIMS_CONTAIN_REFUTED"
    } else {
        "CLAIMS_EVALUATED"
    };

    if args.json {
        return output::emit(
            true,
            "claims verify",
            !batch.any_refuted || !args.claims_strict,
            status_code,
            Some(&data),
            code,
            (stdout, stderr),
        );
    }

    if args.claims_strict && batch.any_refuted {
        let _ = writeln!(stderr, "claims-strict: REFUTED present — exit 2");
    }
    code
}

/// Parse `cargo,check,--all-targets` style into argv.
pub(crate) fn parse_csv_command(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}
