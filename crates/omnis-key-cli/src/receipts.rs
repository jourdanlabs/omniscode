// Chain primitive shared with the agent via jcode-receipts (re-exports jcode_base::omnis).
use jcode_receipts::{self as omnis, AppendDisposition, ClaimCeiling};
use std::io::Write;
use std::path::PathBuf;

use crate::output::{self, ChainData, ReconcileData, RecordData};

pub(crate) struct ReceiptContext {
    ledger: PathBuf,
}

impl ReceiptContext {
    pub(crate) fn canonical() -> anyhow::Result<Self> {
        Ok(Self {
            ledger: omnis::canonical_ledger_path()?,
        })
    }

    #[cfg(test)]
    pub(crate) fn fixture(ledger: PathBuf) -> Self {
        #[cfg(unix)]
        if let Some(parent) = ledger.parent()
            && parent.exists()
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                .expect("fixture receipt parent must become private");
        }
        Self { ledger }
    }
}

pub(crate) struct RecordInput {
    pub(crate) event_id: String,
    pub(crate) kind: String,
    pub(crate) subject: String,
    pub(crate) evidence_sha256: String,
}

pub(crate) fn status(
    context: &ReceiptContext,
    json: bool,
    command: &str,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let verification = match omnis::verify(&context.ledger) {
        Ok(verification) => verification,
        Err(error) => {
            let code = if receipt_state_is_unsafe(&error) {
                "RECEIPT_STATE_UNSAFE"
            } else {
                "RECEIPT_CHAIN_INVALID"
            };
            return output::emit::<()>(json, command, false, code, None, 3, (stdout, stderr));
        }
    };
    if !verification.valid() {
        return output::emit::<()>(
            json,
            command,
            false,
            "RECEIPT_CHAIN_INVALID",
            None,
            3,
            (stdout, stderr),
        );
    }
    if verification.entries() == 0 {
        let data = ChainData {
            state: "EMPTY",
            entry_count: 0,
            head_sha256: None,
        };
        return output::emit(
            json,
            command,
            false,
            "EMPTY_NOT_YET_EVIDENCED",
            Some(&data),
            3,
            (stdout, stderr),
        );
    }
    let head = match verification
        .head()
        .ok_or_else(|| anyhow::anyhow!("nonempty receipt chain has no head"))
        .and_then(output::bare_sha256)
    {
        Ok(head) => head,
        Err(_) => {
            return output::emit::<()>(
                json,
                command,
                false,
                "RECEIPT_CHAIN_INVALID",
                None,
                3,
                (stdout, stderr),
            );
        }
    };
    let data = ChainData {
        state: "VALID",
        entry_count: verification.entries(),
        head_sha256: Some(head),
    };
    output::emit(
        json,
        command,
        true,
        "RECEIPT_CHAIN_VALID",
        Some(&data),
        0,
        (stdout, stderr),
    )
}

pub(crate) fn record(
    context: &ReceiptContext,
    input: RecordInput,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let outcome = match omnis::append_idempotent(
        &context.ledger,
        &input.event_id,
        &input.kind,
        &input.subject,
        &input.evidence_sha256,
        ClaimCeiling::LocalRecord,
    ) {
        Ok(outcome) => outcome,
        Err(error) => {
            let text = format!("{error:#}");
            let (code, exit) = if text.contains("IDEMPOTENCY_COLLISION") {
                ("RECEIPT_EVENT_CONFLICT", 3)
            } else if receipt_state_is_unsafe_text(&text) {
                ("RECEIPT_STATE_UNSAFE", 3)
            } else if receipt_input_is_invalid(&text) {
                ("INVALID_RECEIPT_INPUT", 2)
            } else {
                ("RECEIPT_STATE_UNSAFE", 3)
            };
            return output::emit::<()>(
                json,
                "receipts.record",
                false,
                code,
                None,
                exit,
                (stdout, stderr),
            );
        }
    };
    let (code, disposition) = match outcome.disposition() {
        AppendDisposition::Appended => ("RECEIPT_APPENDED", "APPENDED"),
        AppendDisposition::Existing => ("RECEIPT_EXISTING", "EXISTING"),
    };
    let receipt_sha256 = match output::bare_sha256(outcome.receipt().receipt_hash()) {
        Ok(hash) => hash,
        Err(_) => {
            return output::emit::<()>(
                json,
                "receipts.record",
                false,
                "RECEIPT_STATE_UNSAFE",
                None,
                3,
                (stdout, stderr),
            );
        }
    };
    let data = RecordData {
        disposition,
        sequence: outcome.receipt().sequence(),
        receipt_sha256,
        claim_ceiling: "local-record",
    };
    output::emit(
        json,
        "receipts.record",
        true,
        code,
        Some(&data),
        0,
        (stdout, stderr),
    )
}

pub(crate) fn reconcile_safety(json: bool, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let reconciliation = match jcode_base::safety::reconcile_receipt_outbox() {
        Ok(reconciliation) => reconciliation,
        Err(error) => {
            let text = format!("{error:#}");
            let code = if safety_receipt_has_drifted(&text) {
                "SAFETY_RECEIPT_DRIFT"
            } else {
                "SAFETY_STATE_INVALID"
            };
            return output::emit::<()>(
                json,
                "receipts.reconcile-safety",
                false,
                code,
                None,
                3,
                (stdout, stderr),
            );
        }
    };
    let data = ReconcileData {
        pending_before: reconciliation.pending_before(),
        appended: reconciliation.appended(),
        existing: reconciliation.existing(),
        pending_after: reconciliation.pending_after(),
    };
    let code = if reconciliation.pending_before() == 0
        && reconciliation.appended() == 0
        && reconciliation.existing() == 0
        && reconciliation.pending_after() == 0
    {
        "SAFETY_ALREADY_RECONCILED"
    } else {
        "SAFETY_RECONCILED"
    };
    output::emit(
        json,
        "receipts.reconcile-safety",
        true,
        code,
        Some(&data),
        0,
        (stdout, stderr),
    )
}

fn receipt_input_is_invalid(text: &str) -> bool {
    [
        "event_id must be",
        "kind must be",
        "subject must be",
        "evidence_sha256 must be",
    ]
    .iter()
    .any(|marker| text.contains(marker))
}

fn receipt_state_is_unsafe(error: &anyhow::Error) -> bool {
    receipt_state_is_unsafe_text(&format!("{error:#}"))
}

fn receipt_state_is_unsafe_text(text: &str) -> bool {
    [
        "SYMLINK",
        "IDENTITY_OR_MODE_DRIFT",
        "EXTENDED_ACL",
        "ACL_INSPECTION",
        "NOT_REGULAR_FILE",
        "NOT_DIRECTORY",
        "TYPE_REFUSED",
        "DIRECTORY_COMPONENT",
        "MISSING_PARENT",
        "LOCK_",
        "open OMNIS receipt",
        "create OMNIS receipt",
        "sync OMNIS receipt",
        "publish OMNIS receipt",
    ]
    .iter()
    .any(|marker| text.contains(marker))
}

fn safety_receipt_has_drifted(text: &str) -> bool {
    [
        "ACKNOWLEDGED_RECEIPT",
        "PENDING_RECEIPT",
        "ORPHANED_OR_MISKINDED_RECEIPT",
        "OUTBOX_RECEIPT_HASH_CONFLICT",
        "OMNIS_RECEIPT_CHAIN",
    ]
    .iter()
    .any(|marker| text.contains(marker))
}
