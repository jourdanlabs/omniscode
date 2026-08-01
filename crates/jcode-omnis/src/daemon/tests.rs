use super::*;
use std::thread;

#[cfg(target_os = "macos")]
fn socket_fixture(root: &Path) -> (DaemonConfig, ActivationManifest) {
    let identity = process_identity().unwrap();
    assert!(!identity.groups.contains(&0));
    let config = DaemonConfig::explicit_test(root, identity.uid, identity.gid, true);
    fs::create_dir_all(&config.records_path).unwrap();
    fs::set_permissions(&config.authority_root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&config.records_path, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir_all(config.socket_path.parent().unwrap()).unwrap();
    fs::set_permissions(
        config.socket_path.parent().unwrap(),
        fs::Permissions::from_mode(0o770),
    )
    .unwrap();
    let activation = ActivationManifest {
        schema_version: 1,
        protocol: ACTIVATION_PROTOCOL.to_string(),
        service_uid: identity.uid,
        service_primary_gid: identity.gid,
        service_groups: identity.groups,
        allowed_client_uid: identity.uid,
        allowed_ledger_id: "ledger:test".to_string(),
        receipt_ledger_path: root.join("receipts.jsonl").display().to_string(),
        socket_path: config.socket_path.display().to_string(),
        records_path: config.records_path.display().to_string(),
        private_key_path: config.private_key_path.display().to_string(),
        trust_public_key_path: config.trust_public_key_path.display().to_string(),
    };
    validate_activation(&config, &activation).unwrap();
    (config, activation)
}

#[test]
#[cfg(unix)]
fn real_unix_peer_credentials_bind_the_connecting_uid() {
    let (left, right) = UnixStream::pair().unwrap();
    let expected = unsafe { libc::geteuid() };
    assert_eq!(peer_credentials(&left).unwrap().uid, expected);
    assert_eq!(peer_credentials(&right).unwrap().uid, expected);
}

#[test]
#[cfg(target_os = "macos")]
fn controlled_object_with_extended_acl_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("authority-object");
    fs::write(&path, b"controlled").unwrap();
    assert_no_extended_acl(&path).unwrap();

    let status = std::process::Command::new("/bin/chmod")
        .env_clear()
        .args(["+a", "everyone deny write"])
        .arg(&path)
        .status()
        .unwrap();
    assert!(status.success());
    assert!(
        assert_no_extended_acl(&path)
            .unwrap_err()
            .to_string()
            .contains("EXTENDED_ACL_REFUSED")
    );
}

#[test]
#[cfg(target_os = "macos")]
fn explicit_temp_socket_refuses_unreviewed_leaf_and_serves_one_peer() {
    let temp = tempfile::tempdir().unwrap();
    let identity = process_identity().unwrap();
    assert!(!identity.groups.contains(&0));
    let config = DaemonConfig::explicit_test(temp.path(), identity.uid, identity.gid, true);
    fs::create_dir_all(config.socket_path.parent().unwrap()).unwrap();
    fs::set_permissions(
        config.socket_path.parent().unwrap(),
        fs::Permissions::from_mode(0o770),
    )
    .unwrap();
    let activation = ActivationManifest {
        schema_version: 1,
        protocol: ACTIVATION_PROTOCOL.to_string(),
        service_uid: identity.uid,
        service_primary_gid: identity.gid,
        service_groups: identity.groups,
        allowed_client_uid: identity.uid,
        allowed_ledger_id: "ledger:test".to_string(),
        receipt_ledger_path: temp.path().join("receipts.jsonl").display().to_string(),
        socket_path: config.socket_path.display().to_string(),
        records_path: config.records_path.display().to_string(),
        private_key_path: config.private_key_path.display().to_string(),
        trust_public_key_path: config.trust_public_key_path.display().to_string(),
    };
    validate_activation(&config, &activation).unwrap();

    fs::write(&config.socket_path, b"occupied").unwrap();
    assert!(
        bind_listener(&config, &activation)
            .unwrap_err()
            .to_string()
            .contains("LEAF_TYPE_REFUSED")
    );
    fs::remove_file(&config.socket_path).unwrap();

    let listener = bind_listener(&config, &activation).unwrap();
    let socket = config.socket_path.clone();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let peer = peer_credentials(&stream).unwrap();
        assert_eq!(peer.uid, activation.allowed_client_uid);
        let request: Request = read_frame(&mut stream).unwrap();
        request.validate_envelope().unwrap();
        write_frame(
            &mut stream,
            &Response::success(
                request.request_id(),
                Success::Status {
                    authority_id: AUTHORITY_ID.to_string(),
                    ledger_id: activation.allowed_ledger_id,
                    receipt_ledger_path: activation.receipt_ledger_path,
                    signing_key_id: format!("sha256:{}", "a".repeat(64)),
                    latest: None,
                },
            ),
        )
        .unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });

    let client = crate::client::CheckpointClient::new(socket, identity.uid, identity.gid).unwrap();
    let status = client.status("status:test").unwrap();
    assert!(matches!(status, Success::Status { latest: None, .. }));
    server.join().unwrap();
}

#[test]
#[cfg(target_os = "macos")]
fn run_lock_is_nonblocking_and_outlives_listener_binding() {
    let temp = tempfile::tempdir().unwrap();
    let (config, activation) = socket_fixture(temp.path());
    let first = bind_authority_listener(&config, &activation).unwrap();
    let error = bind_authority_listener(&config, &activation)
        .err()
        .expect("second authority must refuse without blocking");
    assert!(
        error
            .to_string()
            .contains("OMNIS_CHECKPOINT_AUTHORITY_ALREADY_RUNNING")
    );
    drop(first);

    // Dropping the authority releases the directory lock but leaves the
    // normal Unix-domain socket leaf. Restart must recover that stale leaf.
    let restarted = bind_authority_listener(&config, &activation).unwrap();
    drop(restarted);
}

#[test]
#[cfg(target_os = "macos")]
fn stale_socket_restart_recovers_but_active_listener_refuses() {
    let temp = tempfile::tempdir().unwrap();
    let (config, activation) = socket_fixture(temp.path());

    let first = bind_listener(&config, &activation).unwrap();
    let first_leaf = inspect_socket_leaf(&config, &activation, &config.socket_path).unwrap();
    let active_error = bind_listener(&config, &activation).unwrap_err();
    assert!(
        active_error
            .to_string()
            .contains("OMNIS_SOCKET_ACTIVE_LISTENER_REFUSED")
    );
    assert_eq!(
        inspect_socket_leaf(&config, &activation, &config.socket_path).unwrap(),
        first_leaf
    );

    drop(first);
    let restarted = bind_listener(&config, &activation).unwrap();
    let restarted_leaf = inspect_socket_leaf(&config, &activation, &config.socket_path).unwrap();
    assert_ne!(restarted_leaf.inode, first_leaf.inode);
    drop(restarted);
}

#[test]
#[cfg(target_os = "macos")]
fn restart_recovers_identity_bound_quarantine_left_by_a_crash() {
    let temp = tempfile::tempdir().unwrap();
    let (config, activation) = socket_fixture(temp.path());
    let first = bind_listener(&config, &activation).unwrap();
    drop(first);
    let reviewed = inspect_socket_leaf(&config, &activation, &config.socket_path).unwrap();
    let residue = config
        .socket_path
        .parent()
        .unwrap()
        .join(quarantine_name(reviewed));
    rename_exclusive(&config.socket_path, &residue).unwrap();
    sync_directory(config.socket_path.parent().unwrap()).unwrap();

    let restarted = bind_listener(&config, &activation).unwrap();
    assert!(!residue.exists());
    assert!(config.socket_path.exists());
    drop(restarted);
}

#[test]
#[cfg(target_os = "macos")]
fn stale_socket_symlink_wrong_owner_and_wrong_mode_are_preserved_and_refused() {
    let temp = tempfile::tempdir().unwrap();
    let (config, activation) = socket_fixture(temp.path());

    fs::write(temp.path().join("decoy"), b"not a socket").unwrap();
    std::os::unix::fs::symlink(temp.path().join("decoy"), &config.socket_path).unwrap();
    let error = bind_listener(&config, &activation).unwrap_err();
    assert!(error.to_string().contains("LEAF_TYPE_REFUSED"));
    assert!(
        fs::symlink_metadata(&config.socket_path)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    fs::remove_file(&config.socket_path).unwrap();

    let stale = bind_listener(&config, &activation).unwrap();
    drop(stale);
    fs::set_permissions(&config.socket_path, fs::Permissions::from_mode(0o600)).unwrap();
    let error = bind_listener(&config, &activation).unwrap_err();
    assert!(error.to_string().contains("LEAF_IDENTITY_OR_MODE_REFUSED"));
    assert_eq!(
        fs::symlink_metadata(&config.socket_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    fs::set_permissions(&config.socket_path, fs::Permissions::from_mode(0o660)).unwrap();

    let mut wrong_owner_activation = activation.clone();
    wrong_owner_activation.service_uid = activation.service_uid.checked_add(1).unwrap();
    let error = bind_listener(&config, &wrong_owner_activation).unwrap_err();
    assert!(error.to_string().contains("LEAF_IDENTITY_OR_MODE_REFUSED"));
    assert!(fs::symlink_metadata(&config.socket_path).is_ok());
}

#[test]
#[cfg(target_os = "macos")]
fn quarantine_refuses_a_socket_swapped_after_review_and_never_binds() {
    let temp = tempfile::tempdir().unwrap();
    let (config, activation) = socket_fixture(temp.path());

    let original = bind_listener(&config, &activation).unwrap();
    drop(original);
    let reviewed = inspect_socket_leaf(&config, &activation, &config.socket_path).unwrap();
    let displaced = temp.path().join("reviewed-stale.sock");
    fs::rename(&config.socket_path, &displaced).unwrap();
    let replacement = UnixListener::bind(&config.socket_path).unwrap();
    fs::set_permissions(&config.socket_path, fs::Permissions::from_mode(0o660)).unwrap();
    drop(replacement);

    let error =
        quarantine_reviewed_socket(&config, &activation, &config.socket_path, Some(reviewed))
            .unwrap_err();
    assert!(error.to_string().contains("QUARANTINE_IDENTITY_MISMATCH"));
    assert!(!config.socket_path.exists());
    assert!(displaced.exists());
    let quarantined = fs::read_dir(config.socket_path.parent().unwrap())
        .unwrap()
        .filter_map(|entry| entry.ok())
        .any(|entry| entry.file_name().to_string_lossy().starts_with(".okcs-"));
    assert!(quarantined);
    let restart_error = bind_listener(&config, &activation).unwrap_err();
    assert!(
        restart_error
            .to_string()
            .contains("QUARANTINE_RESIDUE_IDENTITY_MISMATCH")
    );
}

#[test]
#[cfg(target_os = "macos")]
fn activation_reload_is_bound_to_exact_startup_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let identity = process_identity().unwrap();
    assert!(!identity.groups.contains(&0));
    let config = DaemonConfig::explicit_test(temp.path(), identity.uid, identity.gid, true);
    let activation = ActivationManifest {
        schema_version: 1,
        protocol: ACTIVATION_PROTOCOL.to_string(),
        service_uid: identity.uid,
        service_primary_gid: identity.gid,
        service_groups: identity.groups,
        allowed_client_uid: identity.uid,
        allowed_ledger_id: "ledger:test".to_string(),
        receipt_ledger_path: temp.path().join("receipts.jsonl").display().to_string(),
        socket_path: config.socket_path.display().to_string(),
        records_path: config.records_path.display().to_string(),
        private_key_path: config.private_key_path.display().to_string(),
        trust_public_key_path: config.trust_public_key_path.display().to_string(),
    };
    fs::write(
        &config.activation_path,
        serde_json::to_vec(&activation).unwrap(),
    )
    .unwrap();
    fs::set_permissions(&config.activation_path, fs::Permissions::from_mode(0o444)).unwrap();
    let startup = load_activation(&config).unwrap();

    fs::set_permissions(&config.activation_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(
        &config.activation_path,
        serde_json::to_vec_pretty(&activation).unwrap(),
    )
    .unwrap();
    fs::set_permissions(&config.activation_path, fs::Permissions::from_mode(0o444)).unwrap();
    let live = load_activation(&config).unwrap();
    assert_eq!(startup.manifest, live.manifest);
    assert_ne!(startup, live);
}
