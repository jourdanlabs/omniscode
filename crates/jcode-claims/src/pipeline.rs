use crate::ledger::{ClaimLedger, ClaimReceipt};
use crate::types::{ClaimInput, ClaimKind, ClaimVerdict, TypedClaim, type_claim};
use jcode_verifiers::{
    VerifierDecision, VerifierResult, verify_build, verify_files_changed, verify_tests,
};
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ClaimEvaluateOptions {
    pub repo: PathBuf,
    pub ledger: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClaimOutcome {
    pub claim_id: String,
    pub verdict: ClaimVerdict,
    pub kind_name: String,
    pub surface: Option<String>,
    /// **Short-circuit:** omitted entirely when the claim was never verifiable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<serde_json::Value>,
    pub reason: Option<String>,
    pub receipt: Option<ClaimReceipt>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClaimsBatchResult {
    pub outcomes: Vec<ClaimOutcome>,
    pub any_refuted: bool,
    pub certified_count: usize,
    pub refused_count: usize,
    pub ungrounded_count: usize,
}

impl ClaimsBatchResult {
    /// `--claims-strict`: non-zero when any claim is REFUTED.
    pub fn strict_exit_code(&self) -> i32 {
        if self.any_refuted { 2 } else { 0 }
    }
}

pub fn evaluate_claim(input: ClaimInput, opts: &ClaimEvaluateOptions) -> ClaimOutcome {
    let typed = type_claim(input);
    match typed {
        TypedClaim::NeverVerifiable {
            id,
            kind_name,
            reason,
            surface,
            verdict,
        } => {
            let receipt = append_receipt(opts, &id, verdict, &kind_name, None);
            ClaimOutcome {
                claim_id: id,
                verdict,
                kind_name,
                surface,
                // 🔴 SAMMICH short-circuit: no verification field at all
                verification: None,
                reason: Some(reason),
                receipt,
            }
        }
        TypedClaim::Verifiable { id, kind, surface } => {
            let (verdict, verification, reason, kind_name) = run_stage3(&kind, &opts.repo);
            let receipt = append_receipt(opts, &id, verdict, &kind_name, verification.clone());
            ClaimOutcome {
                claim_id: id,
                verdict,
                kind_name,
                surface,
                verification,
                reason,
                receipt,
            }
        }
    }
}

pub fn evaluate_claims(inputs: Vec<ClaimInput>, opts: &ClaimEvaluateOptions) -> ClaimsBatchResult {
    let outcomes: Vec<_> = inputs
        .into_iter()
        .map(|c| evaluate_claim(c, opts))
        .collect();
    let any_refuted = outcomes.iter().any(|o| o.verdict.is_refuted());
    let certified_count = outcomes
        .iter()
        .filter(|o| o.verdict == ClaimVerdict::Certified)
        .count();
    let refused_count = outcomes
        .iter()
        .filter(|o| {
            matches!(
                o.verdict,
                ClaimVerdict::RefusedNoVerifier | ClaimVerdict::RefusedUnresolved
            )
        })
        .count();
    let ungrounded_count = outcomes
        .iter()
        .filter(|o| o.verdict == ClaimVerdict::Ungrounded)
        .count();
    ClaimsBatchResult {
        outcomes,
        any_refuted,
        certified_count,
        refused_count,
        ungrounded_count,
    }
}

fn run_stage3(
    kind: &ClaimKind,
    repo: &Path,
) -> (
    ClaimVerdict,
    Option<serde_json::Value>,
    Option<String>,
    String,
) {
    let result = match kind {
        ClaimKind::FilesChanged { declared, base } => {
            verify_files_changed(repo, declared, base.as_deref())
        }
        ClaimKind::BuildPasses { command } => verify_build(repo, command),
        ClaimKind::TestsPass { command } => verify_tests(repo, command),
        other => {
            // Should not reach: typing short-circuits these.
            return (
                ClaimVerdict::RefusedNoVerifier,
                None,
                Some(format!("no stage-3 path for {other:?}")),
                "unknown".into(),
            );
        }
    };

    match result {
        Ok(vr) => map_verifier(vr),
        Err(e) => (
            ClaimVerdict::RefusedUnresolved,
            None,
            Some(e.to_string()),
            kind_name(kind),
        ),
    }
}

fn map_verifier(
    vr: VerifierResult,
) -> (
    ClaimVerdict,
    Option<serde_json::Value>,
    Option<String>,
    String,
) {
    let verdict = match vr.decision {
        VerifierDecision::ProvedTrue => ClaimVerdict::Certified,
        VerifierDecision::ProvedFalse => ClaimVerdict::Refuted,
        VerifierDecision::Unresolved => ClaimVerdict::RefusedUnresolved,
    };
    let name = vr.evidence.verifier.clone();
    let evidence = serde_json::to_value(&vr).ok();
    let reason = vr.bound;
    (verdict, evidence, reason, name)
}

fn kind_name(kind: &ClaimKind) -> String {
    match kind {
        ClaimKind::FilesChanged { .. } => "files_changed".into(),
        ClaimKind::BuildPasses { .. } => "build_passes".into(),
        ClaimKind::TestsPass { .. } => "tests_pass".into(),
        ClaimKind::PerformanceFaster { .. } => "performance_faster".into(),
        ClaimKind::MatchesSpec { .. } => "matches_spec".into(),
        ClaimKind::SecureNow { .. } => "secure_now".into(),
        ClaimKind::MoreIdiomatic { .. } => "more_idiomatic".into(),
        ClaimKind::Prose { .. } => "prose".into(),
    }
}

fn append_receipt(
    opts: &ClaimEvaluateOptions,
    claim_id: &str,
    verdict: ClaimVerdict,
    kind_name: &str,
    verification: Option<serde_json::Value>,
) -> Option<ClaimReceipt> {
    let path = opts.ledger.as_ref()?;
    let ledger = ClaimLedger::open(path).ok()?;
    ledger
        .append(claim_id, verdict, kind_name, verification)
        .ok()
}
