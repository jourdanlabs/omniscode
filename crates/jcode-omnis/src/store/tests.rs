use super::*;
use crate::crypto::{encode_public_key, generate_test_identity};
use crate::model::{PROTOCOL, ReceiptLinkWitness};
use std::os::unix::fs::symlink;

const AUTHORITY_ID: &str = "jourdanlabs.omnis-checkpoint-authority.test.v1";
const LEDGER_ID: &str = "jourdanlabs.jcode.omnis.test-receipts.v1";
const LEDGER_PATH: &str = "/Users/test/.jcode/state/omnis-key/receipts.jsonl";

struct Fixture {
    _temp: tempfile::TempDir,
    config: StoreConfig,
    peer_uid: u32,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let canonical_temp = temp.path().canonicalize().unwrap();
        let authority_root = canonical_temp.join("authority");
        let records_dir = authority_root.join("records");
        let signing_key_path = authority_root.join("authority.ed25519.pk8");
        let trust_public_key_path = canonical_temp.join("authority.ed25519.pub");
        fs::create_dir(&authority_root).unwrap();
        fs::set_permissions(&authority_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(&records_dir).unwrap();
        fs::set_permissions(&records_dir, fs::Permissions::from_mode(0o700)).unwrap();

        let (private_key, identity) = generate_test_identity();
        write_exact_mode(&signing_key_path, &private_key, 0o400);
        write_exact_mode(
            &trust_public_key_path,
            &encode_public_key(identity.public_key_bytes()).unwrap(),
            0o444,
        );

        let service_uid = unsafe { libc::geteuid() };
        let service_primary_gid = unsafe { libc::getegid() };
        assert_ne!(service_uid, 0, "store tests must not run as root");
        assert_ne!(service_primary_gid, 0, "store tests require a non-root GID");
        let peer_uid = service_uid.checked_add(1).unwrap();
        Self {
            _temp: temp,
            peer_uid,
            config: StoreConfig {
                paths: StorePaths {
                    authority_root,
                    records_dir,
                    signing_key_path,
                    trust_public_key_path,
                },
                authority_id: AUTHORITY_ID.to_string(),
                service_uid,
                service_primary_gid,
                trust_owner_uid: service_uid,
                trust_owner_gid: service_primary_gid,
                allowed_peer_uid: peer_uid,
                allowed_ledger_id: LEDGER_ID.to_string(),
                allowed_receipt_ledger_path: LEDGER_PATH.to_string(),
            },
        }
    }

    fn open(&self) -> AuthorityStore {
        AuthorityStore::open(self.config.clone()).unwrap()
    }

    fn record_path(&self, sequence: u64) -> PathBuf {
        self.config
            .paths
            .records_dir
            .join(record_filename(sequence))
    }
}

fn write_exact_mode(path: &Path, bytes: &[u8], mode: u32) {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn replace_exact_mode(path: &Path, bytes: &[u8], mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn digest(number: u64) -> String {
    format!("sha256:{number:064x}")
}

fn genesis(request_id: &str, observed: u64) -> AnchorRequest {
    let continuity = (1..=observed)
        .map(|sequence| ReceiptLinkWitness {
            sequence,
            parent_hash: (sequence > 1).then(|| digest(sequence - 1)),
            receipt_hash: digest(sequence),
        })
        .collect();
    AnchorRequest {
        protocol: PROTOCOL.to_string(),
        request_id: request_id.to_string(),
        ledger_id: LEDGER_ID.to_string(),
        receipt_ledger_path: LEDGER_PATH.to_string(),
        prior_checkpoint_hash: None,
        observed_receipt_sequence: observed,
        observed_receipt_head: digest(observed),
        continuity,
    }
}

fn extension(request_id: &str, previous: &SignedCheckpoint, observed: u64) -> AnchorRequest {
    let start = previous.record.observed_receipt_sequence + 1;
    let continuity = (start..=observed)
        .map(|sequence| ReceiptLinkWitness {
            sequence,
            parent_hash: Some(if sequence == start {
                previous.record.observed_receipt_head.clone()
            } else {
                digest(sequence - 1)
            }),
            receipt_hash: digest(sequence),
        })
        .collect();
    AnchorRequest {
        protocol: PROTOCOL.to_string(),
        request_id: request_id.to_string(),
        ledger_id: LEDGER_ID.to_string(),
        receipt_ledger_path: LEDGER_PATH.to_string(),
        prior_checkpoint_hash: Some(previous.record_hash.clone()),
        observed_receipt_sequence: observed,
        observed_receipt_head: digest(observed),
        continuity,
    }
}

fn assert_refused(result: Result<impl std::fmt::Debug>, marker: &str) {
    let error = result.unwrap_err().to_string();
    assert!(
        error.contains(marker),
        "expected refusal containing {marker:?}, found {error:?}"
    );
}

fn append_two(fixture: &Fixture) -> AuthorityStore {
    let store = fixture.open();
    let first = store
        .anchor_at(fixture.peer_uid, &genesis("anchor:1", 2), 1)
        .unwrap()
        .checkpoint;
    store
        .anchor_at(fixture.peer_uid, &extension("anchor:2", &first, 4), 2)
        .unwrap();
    store
}

#[test]
fn restart_replays_only_the_exact_request_without_rewriting() {
    let fixture = Fixture::new();
    let request = genesis("anchor:restart", 2);
    let first = fixture
        .open()
        .anchor_at(fixture.peer_uid, &request, 101)
        .unwrap();
    assert_eq!(first.disposition, AppendDisposition::Appended);
    let record_path = fixture.record_path(1);
    let before = fs::read(&record_path).unwrap();

    let reopened = fixture.open();
    let replay = reopened.anchor_at(fixture.peer_uid, &request, 999).unwrap();
    assert_eq!(replay.disposition, AppendDisposition::Existing);
    assert_eq!(replay.checkpoint, first.checkpoint);
    assert_eq!(fs::read(record_path).unwrap(), before);
    assert_eq!(reopened.latest().unwrap(), Some(first.checkpoint));
}

#[test]
fn request_id_drift_is_a_collision_even_when_both_requests_are_valid() {
    let fixture = Fixture::new();
    let store = fixture.open();
    store
        .anchor_at(fixture.peer_uid, &genesis("anchor:collision", 1), 1)
        .unwrap();
    assert_refused(
        store.anchor_at(fixture.peer_uid, &genesis("anchor:collision", 2), 2),
        "OMNIS_CHECKPOINT_REQUEST_ID_COLLISION",
    );
}

#[test]
fn alternate_receipt_path_cannot_use_the_activated_ledger_identity() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let mut request = genesis("anchor:alternate-path", 1);
    request.receipt_ledger_path = "/tmp/attacker/receipts.jsonl".to_string();
    assert_refused(
        store.anchor_at(fixture.peer_uid, &request, 1),
        "OMNIS_CHECKPOINT_RECEIPT_LEDGER_PATH_MISMATCH",
    );
    assert!(
        fixture
            .config
            .paths
            .records_dir
            .read_dir()
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn lookup_is_absent_or_exact_and_revalidates_the_full_chain() {
    let fixture = Fixture::new();
    let store = fixture.open();
    assert!(store.lookup_request("anchor:absent").unwrap().is_none());
    let expected = store
        .anchor_at(fixture.peer_uid, &genesis("anchor:recover", 1), 1)
        .unwrap()
        .checkpoint;
    assert_eq!(
        store.lookup_request("anchor:recover").unwrap(),
        Some(expected)
    );
    assert!(store.lookup_request("anchor:absent").unwrap().is_none());

    let record = fixture.record_path(1);
    let mut bytes = fs::read(&record).unwrap();
    let index = bytes
        .windows(b"anchor:recover".len())
        .position(|window| window == b"anchor:recover")
        .unwrap();
    bytes[index] = b'x';
    replace_exact_mode(&record, &bytes, 0o400);
    assert_refused(
        store.lookup_request("anchor:recover"),
        "OMNIS_CHECKPOINT_REQUEST_RECORD_BINDING_MISMATCH",
    );
}

#[test]
fn checkpoint_clock_may_hold_but_never_move_backward() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let first = store
        .anchor_at(fixture.peer_uid, &genesis("anchor:clock-1", 1), 100)
        .unwrap()
        .checkpoint;
    let equal = store
        .anchor_at(
            fixture.peer_uid,
            &extension("anchor:clock-2", &first, 2),
            100,
        )
        .unwrap()
        .checkpoint;
    assert_refused(
        store.anchor_at(
            fixture.peer_uid,
            &extension("anchor:clock-rollback", &equal, 3),
            99,
        ),
        "OMNIS_CHECKPOINT_CLOCK_ROLLBACK_REFUSED",
    );
    assert!(!fixture.record_path(3).exists());
}

#[test]
fn no_advance_checkpoint_fork_and_receipt_fork_are_refused() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let first = store
        .anchor_at(fixture.peer_uid, &genesis("anchor:base", 2), 1)
        .unwrap()
        .checkpoint;

    let no_advance = AnchorRequest {
        protocol: PROTOCOL.to_string(),
        request_id: "anchor:no-advance".to_string(),
        ledger_id: LEDGER_ID.to_string(),
        receipt_ledger_path: LEDGER_PATH.to_string(),
        prior_checkpoint_hash: Some(first.record_hash.clone()),
        observed_receipt_sequence: 2,
        observed_receipt_head: digest(2),
        continuity: vec![ReceiptLinkWitness {
            sequence: 2,
            parent_hash: Some(digest(1)),
            receipt_hash: digest(2),
        }],
    };
    assert_refused(
        store.anchor_at(fixture.peer_uid, &no_advance, 2),
        "OMNIS_CHECKPOINT_RECEIPT_NO_ADVANCE",
    );

    let mut checkpoint_fork = extension("anchor:checkpoint-fork", &first, 3);
    checkpoint_fork.prior_checkpoint_hash = Some(digest(999));
    assert_refused(
        store.anchor_at(fixture.peer_uid, &checkpoint_fork, 2),
        "OMNIS_CHECKPOINT_FORK_OR_ROLLBACK_REFUSED",
    );

    let mut receipt_fork = extension("anchor:receipt-fork", &first, 3);
    receipt_fork.continuity[0].parent_hash = Some(digest(777));
    assert_refused(
        store.anchor_at(fixture.peer_uid, &receipt_fork, 2),
        "OMNIS_CHECKPOINT_RECEIPT_CONTINUITY_FORK",
    );

    let mut path_drift = extension("anchor:path-drift", &first, 3);
    path_drift.receipt_ledger_path =
        "/Users/test/.jcode/state/omnis-key/other-receipts.jsonl".to_string();
    assert_refused(
        store.anchor_at(fixture.peer_uid, &path_drift, 2),
        "OMNIS_CHECKPOINT_RECEIPT_LEDGER_PATH_MISMATCH",
    );
}

#[test]
fn signed_checkpoint_for_another_authority_is_refused() {
    let fixture = Fixture::new();
    let store = fixture.open();
    store
        .anchor_at(fixture.peer_uid, &genesis("anchor:authority", 1), 1)
        .unwrap();
    let path = fixture.record_path(1);
    let payload = exact_json_line(&fs::read(&path).unwrap()).unwrap().to_vec();
    let mut stored: StoredCheckpoint = serde_json::from_slice(&payload).unwrap();
    let key = fs::read(&fixture.config.paths.signing_key_path).unwrap();
    let identity = SigningIdentity::from_pkcs8(&key).unwrap();
    stored.checkpoint.record.authority_id =
        "jourdanlabs.omnis-checkpoint-authority.other.v1".to_string();
    stored.checkpoint = identity.sign(stored.checkpoint.record).unwrap();
    let mut bytes = serde_json::to_vec(&stored).unwrap();
    bytes.push(b'\n');
    replace_exact_mode(&path, &bytes, 0o400);

    assert_refused(store.latest(), "OMNIS_CHECKPOINT_AUTHORITY_ID_MISMATCH");
}

#[test]
fn signature_or_record_mutation_is_refused() {
    let fixture = Fixture::new();
    let store = fixture.open();
    store
        .anchor_at(fixture.peer_uid, &genesis("anchor:mutation", 1), 1)
        .unwrap();
    let path = fixture.record_path(1);
    let mut bytes = fs::read(&path).unwrap();
    let marker = b"\"signature_ed25519\":\"";
    let start = bytes
        .windows(marker.len())
        .position(|window| window == marker)
        .unwrap()
        + marker.len();
    bytes[start] = if bytes[start] == b'0' { b'1' } else { b'0' };
    replace_exact_mode(&path, &bytes, 0o400);

    assert_refused(store.latest(), "OMNIS_CHECKPOINT_SIGNATURE_INVALID");
}

#[test]
fn filename_gap_and_reorder_are_refused() {
    let gap_fixture = Fixture::new();
    let gap_store = append_two(&gap_fixture);
    fs::rename(gap_fixture.record_path(2), gap_fixture.record_path(3)).unwrap();
    assert_refused(gap_store.latest(), "OMNIS_CHECKPOINT_SEQUENCE_GAP");

    let reorder_fixture = Fixture::new();
    let reorder_store = append_two(&reorder_fixture);
    let first_path = reorder_fixture.record_path(1);
    let second_path = reorder_fixture.record_path(2);
    let first = fs::read(&first_path).unwrap();
    let second = fs::read(&second_path).unwrap();
    replace_exact_mode(&first_path, &second, 0o400);
    replace_exact_mode(&second_path, &first, 0o400);
    assert_refused(
        reorder_store.latest(),
        "OMNIS_CHECKPOINT_FILENAME_SEQUENCE_MISMATCH",
    );
}

#[test]
fn partial_record_is_refused_without_reseed_or_overwrite() {
    let fixture = Fixture::new();
    let store = fixture.open();
    store
        .anchor_at(fixture.peer_uid, &genesis("anchor:partial", 1), 1)
        .unwrap();
    let path = fixture.record_path(1);
    let original = fs::read(&path).unwrap();
    let partial = original[..original.len() / 2].to_vec();
    replace_exact_mode(&path, &partial, 0o400);

    assert_refused(store.latest(), "OMNIS_CHECKPOINT_RECORD_PARTIAL");
    assert_eq!(fs::read(path).unwrap(), partial);
}

#[test]
fn exclusive_publish_collision_preserves_existing_bytes() {
    let fixture = Fixture::new();
    let store = fixture.open();
    store
        .anchor_at(fixture.peer_uid, &genesis("anchor:publish", 1), 1)
        .unwrap();
    let stored = store.load_chain().unwrap().remove(0);
    let path = fixture.record_path(1);
    let before = fs::read(&path).unwrap();

    assert!(!publish_record(&fixture.config, 1, &stored).unwrap());
    assert_eq!(fs::read(path).unwrap(), before);

    let victim = fixture
        .config
        .paths
        .authority_root
        .join("publish-collision-victim");
    write_exact_mode(&victim, b"must-not-change", 0o400);
    let planted_final = fixture.record_path(2);
    symlink(&victim, &planted_final).unwrap();
    assert!(!publish_record(&fixture.config, 2, &stored).unwrap());
    assert_eq!(fs::read(victim).unwrap(), b"must-not-change");
    assert!(
        fs::symlink_metadata(planted_final)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn symlinked_trust_leaf_is_refused_even_when_target_bytes_match() {
    let fixture = Fixture::new();
    let trust = fixture.config.paths.trust_public_key_path.clone();
    let target = trust.with_extension("real");
    fs::rename(&trust, &target).unwrap();
    symlink(&target, &trust).unwrap();

    assert_refused(
        AuthorityStore::open(fixture.config.clone()),
        "OMNIS_CHECKPOINT_PATH_SYMLINK_REFUSED",
    );
}

#[test]
fn intermediate_authority_symlink_is_refused() {
    let fixture = Fixture::new();
    let authority = fixture.config.paths.authority_root.clone();
    let real_authority = authority.with_extension("real");
    fs::rename(&authority, &real_authority).unwrap();
    symlink(&real_authority, &authority).unwrap();

    assert_refused(
        AuthorityStore::open(fixture.config.clone()),
        "OMNIS_CHECKPOINT_PATH_SYMLINK_REFUSED",
    );
}

#[test]
fn private_key_must_match_the_separately_supplied_trust_key() {
    let fixture = Fixture::new();
    let (_, other_identity) = generate_test_identity();
    replace_exact_mode(
        &fixture.config.paths.trust_public_key_path,
        &encode_public_key(other_identity.public_key_bytes()).unwrap(),
        0o444,
    );

    assert_refused(
        AuthorityStore::open(fixture.config.clone()),
        "OMNIS_CHECKPOINT_TRUST_KEY_MISMATCH",
    );
}

#[test]
fn stale_partial_temp_is_never_promoted_or_recovered() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let first = store
        .anchor_at(fixture.peer_uid, &genesis("anchor:temp", 1), 1)
        .unwrap()
        .checkpoint;
    let stale = fixture
        .config
        .paths
        .records_dir
        .join(".checkpoint-tmp-00000000000000000002-999999-1");
    write_exact_mode(&stale, b"{partial", 0o400);

    assert_eq!(store.latest().unwrap(), Some(first));
    assert_eq!(fs::read(stale).unwrap(), b"{partial");
    assert!(!fixture.record_path(2).exists());
}

#[test]
fn record_mode_drift_refuses_before_reading_payload() {
    let fixture = Fixture::new();
    let store = fixture.open();
    store
        .anchor_at(fixture.peer_uid, &genesis("anchor:mode", 1), 1)
        .unwrap();
    fs::set_permissions(fixture.record_path(1), fs::Permissions::from_mode(0o600)).unwrap();

    assert_refused(store.latest(), "OMNIS_CHECKPOINT_RECORD_MODE_MISMATCH");
}

#[test]
fn coherent_tail_deletion_requires_an_external_high_water_witness() {
    let fixture = Fixture::new();
    let store = append_two(&fixture);
    let first: StoredCheckpoint = serde_json::from_slice(
        exact_json_line(&fs::read(fixture.record_path(1)).unwrap()).unwrap(),
    )
    .unwrap();
    fs::remove_file(fixture.record_path(2)).unwrap();

    assert_eq!(store.latest().unwrap(), Some(first.checkpoint));
}
