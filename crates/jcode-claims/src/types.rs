use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Frozen verdict set — engine-enforced. Agent cannot author a new one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClaimVerdict {
    /// A deterministic verifier proved the claim.
    Certified,
    /// A verifier proved the claim **false** — say so loudly.
    Refuted,
    /// No deterministic verifier exists for this claim shape.
    RefusedNoVerifier,
    /// Verifier ran and could not decide.
    RefusedUnresolved,
    /// Prose that is not a falsifiable claim.
    Ungrounded,
}

impl ClaimVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Certified => "CERTIFIED",
            Self::Refuted => "REFUTED",
            Self::RefusedNoVerifier => "REFUSED_NO_VERIFIER",
            Self::RefusedUnresolved => "REFUSED_UNRESOLVED",
            Self::Ungrounded => "UNGROUNDED",
        }
    }

    /// Honest refusal / ungrounded are first-class **wins** for product integrity.
    pub fn is_integrity_success(self) -> bool {
        matches!(
            self,
            Self::Certified | Self::RefusedNoVerifier | Self::RefusedUnresolved | Self::Ungrounded
        )
    }

    pub fn is_refuted(self) -> bool {
        matches!(self, Self::Refuted)
    }
}

/// Frozen vocabulary constant for gates and dashboards.
pub const VERDICT_VOCABULARY: &[&str] = &[
    "CERTIFIED",
    "REFUTED",
    "REFUSED_NO_VERIFIER",
    "REFUSED_UNRESOLVED",
    "UNGROUNDED",
];

/// Structured claim shapes known to S1/S2. S1 ships the first three as verifiable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClaimKind {
    /// "I changed only these files"
    FilesChanged {
        declared: BTreeSet<String>,
        #[serde(default)]
        base: Option<String>,
    },
    /// "the build passes"
    BuildPasses { command: Vec<String> },
    /// "tests pass"
    TestsPass { command: Vec<String> },
    /// Explicitly unprovable performance claim — must refuse.
    PerformanceFaster {
        #[serde(default)]
        note: Option<String>,
    },
    /// Spec match without machine-readable spec — refuse.
    MatchesSpec {
        #[serde(default)]
        note: Option<String>,
    },
    /// Security absence claim — refuse.
    SecureNow {
        #[serde(default)]
        note: Option<String>,
    },
    /// Aesthetic / idiomatic — not falsifiable.
    MoreIdiomatic {
        #[serde(default)]
        note: Option<String>,
    },
    /// Free prose that failed to type as a falsifiable claim.
    Prose { text: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimInput {
    pub id: String,
    pub kind: ClaimKind,
    /// Optional human surface string (not used by verifiers).
    #[serde(default)]
    pub surface: Option<String>,
}

/// Result of stage 2 typing. **Short-circuit (SAMMICH):** never-verifiable
/// claims carry **no** verification slot — not a failed verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "typed", rename_all = "snake_case")]
pub enum TypedClaim {
    /// Stage 3 may run.
    Verifiable {
        id: String,
        kind: ClaimKind,
        surface: Option<String>,
    },
    /// Never checkable — **no verification field** will be emitted.
    NeverVerifiable {
        id: String,
        kind_name: String,
        reason: String,
        surface: Option<String>,
        verdict: ClaimVerdict,
    },
}

/// Stage 2: type a claim. No tools, no model.
pub fn type_claim(input: ClaimInput) -> TypedClaim {
    match &input.kind {
        ClaimKind::FilesChanged { declared, .. } if declared.is_empty() => {
            TypedClaim::NeverVerifiable {
                id: input.id,
                kind_name: "files_changed".into(),
                reason: "empty declared file set is not a falsifiable change claim".into(),
                surface: input.surface,
                verdict: ClaimVerdict::Ungrounded,
            }
        }
        ClaimKind::FilesChanged { .. }
        | ClaimKind::BuildPasses { .. }
        | ClaimKind::TestsPass { .. } => TypedClaim::Verifiable {
            id: input.id,
            kind: input.kind,
            surface: input.surface,
        },
        ClaimKind::PerformanceFaster { note } => TypedClaim::NeverVerifiable {
            id: input.id,
            kind_name: "performance_faster".into(),
            reason: note.clone().unwrap_or_else(|| {
                "we do not benchmark; speed claims are REFUSED_NO_VERIFIER".into()
            }),
            surface: input.surface,
            verdict: ClaimVerdict::RefusedNoVerifier,
        },
        ClaimKind::MatchesSpec { note } => TypedClaim::NeverVerifiable {
            id: input.id,
            kind_name: "matches_spec".into(),
            reason: note.clone().unwrap_or_else(|| {
                "spec is not machine-readable in this product; REFUSED_NO_VERIFIER".into()
            }),
            surface: input.surface,
            verdict: ClaimVerdict::RefusedNoVerifier,
        },
        ClaimKind::SecureNow { note } => TypedClaim::NeverVerifiable {
            id: input.id,
            kind_name: "secure_now".into(),
            reason: note.clone().unwrap_or_else(|| {
                "absence of vulnerability is unprovable; REFUSED_NO_VERIFIER".into()
            }),
            surface: input.surface,
            verdict: ClaimVerdict::RefusedNoVerifier,
        },
        ClaimKind::MoreIdiomatic { note } => TypedClaim::NeverVerifiable {
            id: input.id,
            kind_name: "more_idiomatic".into(),
            reason: note
                .clone()
                .unwrap_or_else(|| "idiomatic is not falsifiable; UNGROUNDED".into()),
            surface: input.surface,
            verdict: ClaimVerdict::Ungrounded,
        },
        ClaimKind::Prose { text } => TypedClaim::NeverVerifiable {
            id: input.id,
            kind_name: "prose".into(),
            reason: format!(
                "not a typed falsifiable claim shape: {}",
                text.chars().take(120).collect::<String>()
            ),
            surface: input.surface,
            verdict: ClaimVerdict::Ungrounded,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vocabulary_is_frozen_five() {
        assert_eq!(VERDICT_VOCABULARY.len(), 5);
        assert!(ClaimVerdict::RefusedNoVerifier.is_integrity_success());
        assert!(ClaimVerdict::Refuted.is_refuted());
    }

    #[test]
    fn performance_short_circuits_without_verifier_slot() {
        let t = type_claim(ClaimInput {
            id: "c1".into(),
            kind: ClaimKind::PerformanceFaster { note: None },
            surface: Some("this is faster".into()),
        });
        match t {
            TypedClaim::NeverVerifiable { verdict, .. } => {
                assert_eq!(verdict, ClaimVerdict::RefusedNoVerifier);
            }
            TypedClaim::Verifiable { .. } => panic!("must not be verifiable"),
        }
    }
}
