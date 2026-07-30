use super::*;

fn verify_acked_decision_receipts(state: &SafetyState) -> Result<DecisionReceiptVerification> {
    let ledger = crate::omnis::canonical_ledger_path()?;
    let receipts = crate::omnis::verified_receipts(&ledger)?;
    let mut receipts_by_event = std::collections::HashMap::new();
    for receipt in &receipts {
        if let Some(event_id) = receipt.event_id() {
            receipts_by_event.insert(event_id, receipt);
        }
    }

    let mut expected_safety_events = std::collections::HashMap::new();
    let mut acknowledged_receipts = 0;
    for decision in &state.history {
        let Some(receipt_hash) = decision.omnis_receipt_hash.as_deref() else {
            continue;
        };
        let request = decision
            .request
            .as_ref()
            .context("SAFETY_ACKNOWLEDGED_DECISION_REQUEST_MISSING")?;
        let expected = outbox_for_decision(request, decision)?;
        let receipt = receipts_by_event
            .get(expected.event_id.as_str())
            .context("SAFETY_ACKNOWLEDGED_RECEIPT_MISSING")?;
        if receipt.receipt_hash() != receipt_hash
            || receipt.kind() != expected.kind
            || receipt.subject() != expected.subject
            || receipt.evidence_sha256() != expected.evidence_sha256
            || receipt.claim_ceiling() != crate::omnis::ClaimCeiling::LocalRecord
        {
            bail!(
                "SAFETY_ACKNOWLEDGED_RECEIPT_BINDING_MISMATCH: {}",
                expected.event_id
            )
        }
        expected_safety_events.insert(expected.event_id.clone(), expected);
        acknowledged_receipts += 1;
    }

    for pending in &state.receipt_outbox {
        if let Some(receipt) = receipts_by_event.get(pending.event_id.as_str())
            && (receipt.kind() != pending.kind
                || receipt.subject() != pending.subject
                || receipt.evidence_sha256() != pending.evidence_sha256
                || receipt.claim_ceiling() != crate::omnis::ClaimCeiling::LocalRecord)
        {
            bail!(
                "SAFETY_PENDING_RECEIPT_BINDING_MISMATCH: {}",
                pending.event_id
            )
        }
        expected_safety_events.insert(pending.event_id.clone(), pending.clone());
    }

    for receipt in &receipts {
        let safety_kind = receipt.kind().starts_with("safety.permission.");
        let safety_event = receipt
            .event_id()
            .is_some_and(|event_id| event_id.starts_with("safety-decision:"));
        if safety_kind || safety_event {
            let event_id = receipt
                .event_id()
                .context("SAFETY_RECEIPT_EVENT_ID_MISSING")?;
            if !safety_kind || !safety_event || !expected_safety_events.contains_key(event_id) {
                bail!("SAFETY_ORPHANED_OR_MISKINDED_RECEIPT: {}", event_id)
            }
        }
    }

    Ok(DecisionReceiptVerification {
        valid: true,
        acknowledged_receipts,
        ledger_entries: receipts.len(),
        integrity_scope: "local-cross-file-binding-only; deletion and rollback require an external checkpoint",
    })
}

/// Verify that every acknowledged safety decision is bound to the exact
/// decision receipt currently present in the local OMNIS ledger.
pub fn verify_decision_receipts() -> Result<DecisionReceiptVerification> {
    read_state(verify_acked_decision_receipts)
}

/// Reconcile every durably committed safety-decision outbox event into the
/// bounded local OMNIS ledger. Exact event IDs make restart replay idempotent.
pub fn reconcile_receipt_outbox() -> Result<ReceiptReconciliation> {
    let pending_before = receipt_outbox_status()?.pending();
    let mut appended = 0;
    let mut existing = 0;
    loop {
        let pending = read_state(|state| {
            verify_acked_decision_receipts(state)?;
            Ok(state.receipt_outbox.first().cloned())
        })?;
        let Some(pending) = pending else {
            let pending_after = receipt_outbox_status()?.pending();
            return Ok(ReceiptReconciliation {
                pending_before,
                appended,
                existing,
                pending_after,
            });
        };
        let ledger = crate::omnis::canonical_ledger_path()?;
        let outcome = crate::omnis::append_idempotent(
            &ledger,
            &pending.event_id,
            &pending.kind,
            &pending.subject,
            &pending.evidence_sha256,
            crate::omnis::ClaimCeiling::LocalRecord,
        )?;
        let receipt_hash = outcome.receipt().receipt_hash().to_string();
        let acknowledged = mutate_state(|state| {
            let Some(position) = state
                .receipt_outbox
                .iter()
                .position(|event| event.event_id == pending.event_id)
            else {
                let already_acknowledged = state.history.iter().any(|decision| {
                    decision.decision_id.as_deref() == Some(&pending.decision_id)
                        && decision.omnis_receipt_hash.as_deref() == Some(&receipt_hash)
                });
                if already_acknowledged {
                    return Ok(false);
                }
                bail!("SAFETY_OUTBOX_EVENT_DISAPPEARED: {}", pending.event_id)
            };
            if state.receipt_outbox[position] != pending {
                bail!("SAFETY_OUTBOX_EVENT_DRIFT: {}", pending.event_id)
            }
            let decision = state
                .history
                .iter_mut()
                .find(|decision| decision.decision_id.as_deref() == Some(&pending.decision_id))
                .context("SAFETY_OUTBOX_DECISION_MISSING")?;
            if let Some(existing) = decision.omnis_receipt_hash.as_deref()
                && existing != receipt_hash
            {
                bail!("SAFETY_OUTBOX_RECEIPT_HASH_CONFLICT: {}", pending.event_id)
            }
            decision.omnis_receipt_hash = Some(receipt_hash.clone());
            state.receipt_outbox.remove(position);
            Ok(true)
        })?;
        if acknowledged {
            match outcome.disposition() {
                crate::omnis::AppendDisposition::Appended => appended += 1,
                crate::omnis::AppendDisposition::Existing => existing += 1,
            }
        }
    }
}

pub fn flush_receipt_outbox() -> Result<usize> {
    Ok(reconcile_receipt_outbox()?.acknowledged())
}

pub fn receipt_outbox_status() -> Result<ReceiptOutboxStatus> {
    read_state(|state| {
        let verification = verify_acked_decision_receipts(state)?;
        Ok(ReceiptOutboxStatus {
            pending: state.receipt_outbox.len(),
            oldest_event_id: state
                .receipt_outbox
                .first()
                .map(|event| event.event_id.clone()),
            acknowledged_receipts: verification.acknowledged_receipts,
            integrity_scope: "local-safety-decision-observation-only; no execution or approval authority",
        })
    })
}
