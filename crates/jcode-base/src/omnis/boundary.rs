use anyhow::{Context, Result, bail};
use std::fs;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

pub(crate) fn validate_existing_directory_ancestor(path: &Path) -> Result<()> {
    let mut cursor = path;
    loop {
        match fs::symlink_metadata(cursor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!(
                    "OMNIS_RECEIPT_DIRECTORY_SYMLINK_REFUSED: {}",
                    cursor.display()
                )
            }
            Ok(metadata) if !metadata.is_dir() => {
                bail!(
                    "OMNIS_RECEIPT_DIRECTORY_COMPONENT_NOT_DIRECTORY: {}",
                    cursor.display()
                )
            }
            Ok(_) => {
                #[cfg(unix)]
                {
                    let canonical = fs::canonicalize(cursor)?;
                    if !super::paths_equivalent(cursor, &canonical) {
                        bail!(
                            "OMNIS_RECEIPT_DIRECTORY_SYMLINK_REFUSED: {} -> {}",
                            cursor.display(),
                            canonical.display()
                        )
                    }
                }
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                cursor = cursor
                    .parent()
                    .context("OMNIS_RECEIPT_DIRECTORY_HAS_NO_EXISTING_ANCESTOR")?;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspect OMNIS receipt directory {}", cursor.display())
                });
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn has_extended_acl(path: &Path) -> Result<bool> {
    use std::os::unix::ffi::OsStrExt;

    let attributes = xattr::list(path)
        .with_context(|| format!("OMNIS_RECEIPT_ACL_INSPECTION_FAILED: {}", path.display()))?;
    Ok(attributes.into_iter().any(|attribute| {
        matches!(
            attribute.as_os_str().as_bytes(),
            b"system.posix_acl_access" | b"system.posix_acl_default"
        )
    }))
}

#[cfg(target_os = "macos")]
fn has_extended_acl(path: &Path) -> Result<bool> {
    use std::ffi::{CString, c_char, c_int, c_void};
    use std::os::unix::ffi::OsStrExt;

    unsafe extern "C" {
        fn acl_get_file(path: *const c_char, acl_type: c_int) -> *mut c_void;
        fn acl_free(object: *mut c_void) -> c_int;
    }

    const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;
    let encoded =
        CString::new(path.as_os_str().as_bytes()).context("OMNIS_RECEIPT_ACL_PATH_CONTAINS_NUL")?;
    let acl = unsafe { acl_get_file(encoded.as_ptr(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            return Ok(false);
        }
        bail!("OMNIS_RECEIPT_ACL_INSPECTION_FAILED: {}", path.display())
    }
    let free_result = unsafe { acl_free(acl) };
    if free_result != 0 {
        bail!("OMNIS_RECEIPT_ACL_INSPECTION_FAILED: {}", path.display())
    }
    Ok(true)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn has_extended_acl(path: &Path) -> Result<bool> {
    bail!(
        "OMNIS_RECEIPT_ACL_INSPECTION_UNSUPPORTED: {}",
        path.display()
    )
}

#[cfg(unix)]
pub fn validate_private_directory(path: &Path, code: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("{code}_INSPECTION_FAILED: {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("{code}_TYPE_REFUSED: {}", path.display())
    }
    if !identity_and_mode_match(
        metadata.uid(),
        metadata.permissions().mode(),
        unsafe { libc::geteuid() },
        0o700,
    ) {
        bail!("{code}_IDENTITY_OR_MODE_DRIFT: {}", path.display())
    }
    if has_extended_acl(path)? {
        bail!("{code}_EXTENDED_ACL_REFUSED: {}", path.display())
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn validate_private_directory(path: &Path, code: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("{code}_INSPECTION_FAILED: {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("{code}_TYPE_REFUSED: {}", path.display())
    }
    Ok(())
}

#[cfg(unix)]
pub fn validate_private_file(path: &Path, code: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("{code}_INSPECTION_FAILED: {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{code}_TYPE_REFUSED: {}", path.display())
    }
    if !identity_and_mode_match(
        metadata.uid(),
        metadata.permissions().mode(),
        unsafe { libc::geteuid() },
        0o600,
    ) {
        bail!("{code}_IDENTITY_OR_MODE_DRIFT: {}", path.display())
    }
    if has_extended_acl(path)? {
        bail!("{code}_EXTENDED_ACL_REFUSED: {}", path.display())
    }
    Ok(())
}

#[cfg(unix)]
fn identity_and_mode_match(
    actual_uid: u32,
    actual_mode: u32,
    expected_uid: u32,
    expected_mode: u32,
) -> bool {
    actual_uid == expected_uid && actual_mode & 0o7777 == expected_mode
}

#[cfg(not(unix))]
pub fn validate_private_file(path: &Path, code: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("{code}_INSPECTION_FAILED: {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{code}_TYPE_REFUSED: {}", path.display())
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn concrete_wrong_owned_ledger_is_refused_without_mutation() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let effective_uid = unsafe { libc::geteuid() };
        let temporary;
        let ledger = if effective_uid == 0 {
            temporary = Some(tempfile::tempdir().unwrap());
            let path = temporary.as_ref().unwrap().path().join("receipts.jsonl");
            std::fs::write(&path, b"fixture-only wrong-owner ledger\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let encoded = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            let wrong_uid = 65_534;
            assert_eq!(
                unsafe { libc::chown(encoded.as_ptr(), wrong_uid, u32::MAX) },
                0,
                "privileged fixture must install a concrete wrong owner"
            );
            assert_eq!(std::fs::symlink_metadata(&path).unwrap().uid(), wrong_uid);
            path
        } else {
            temporary = None;
            #[cfg(target_os = "macos")]
            let path = std::path::PathBuf::from("/private/etc/hosts");
            #[cfg(not(target_os = "macos"))]
            let path = std::path::PathBuf::from("/etc/hosts");
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            assert!(metadata.is_file());
            assert_ne!(
                metadata.uid(),
                effective_uid,
                "system fixture must have a concretely different owner"
            );
            path
        };

        let original = std::fs::read(&ledger).unwrap();
        let error = super::super::verify(&ledger).unwrap_err().to_string();
        assert!(
            error.contains("IDENTITY_OR_MODE_DRIFT"),
            "wrong-owned receipt ledger produced the wrong refusal: {error}"
        );
        assert_eq!(std::fs::read(&ledger).unwrap(), original);
        drop(temporary);
    }

    #[cfg(unix)]
    #[test]
    fn wrong_owner_or_mode_is_never_accepted_as_private() {
        let uid = unsafe { libc::geteuid() };
        assert!(super::identity_and_mode_match(uid, 0o600, uid, 0o600));
        assert!(!super::identity_and_mode_match(
            uid.saturating_add(1),
            0o600,
            uid,
            0o600
        ));
        assert!(!super::identity_and_mode_match(uid, 0o644, uid, 0o600));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn concrete_extended_acl_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        const ACL_XATTR_VERSION: u32 = 0x0002;
        const ACL_USER_OBJ: u16 = 0x0001;
        const ACL_USER: u16 = 0x0002;
        const ACL_GROUP_OBJ: u16 = 0x0004;
        const ACL_MASK: u16 = 0x0010;
        const ACL_OTHER: u16 = 0x0020;
        const ACL_UNDEFINED_ID: u32 = u32::MAX;

        fn push_entry(bytes: &mut Vec<u8>, tag: u16, permissions: u16, id: u32) {
            bytes.extend_from_slice(&tag.to_le_bytes());
            bytes.extend_from_slice(&permissions.to_le_bytes());
            bytes.extend_from_slice(&id.to_le_bytes());
        }

        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("controlled");
        std::fs::write(&path, b"fixture-only").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        super::validate_private_file(&path, "OMNIS_TEST_FILE").unwrap();

        let current_uid = unsafe { libc::geteuid() };
        let named_uid = if current_uid == u32::MAX {
            current_uid - 1
        } else {
            current_uid + 1
        };
        let mut acl = ACL_XATTR_VERSION.to_le_bytes().to_vec();
        push_entry(&mut acl, ACL_USER_OBJ, 0o6, ACL_UNDEFINED_ID);
        push_entry(&mut acl, ACL_USER, 0, named_uid);
        push_entry(&mut acl, ACL_GROUP_OBJ, 0, ACL_UNDEFINED_ID);
        push_entry(&mut acl, ACL_MASK, 0, ACL_UNDEFINED_ID);
        push_entry(&mut acl, ACL_OTHER, 0, ACL_UNDEFINED_ID);
        xattr::set(&path, "system.posix_acl_access", &acl)
            .expect("Linux test filesystem must support a concrete POSIX ACL fixture");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(xattr::list(&path).unwrap().any(|attribute| {
            attribute.as_os_str() == std::ffi::OsStr::new("system.posix_acl_access")
        }));

        let original = std::fs::read(&path).unwrap();
        assert!(
            super::validate_private_file(&path, "OMNIS_TEST_FILE")
                .unwrap_err()
                .to_string()
                .contains("EXTENDED_ACL_REFUSED")
        );
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn concrete_extended_acl_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("controlled");
        std::fs::write(&path, b"fixture-only").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        super::validate_private_file(&path, "OMNIS_TEST_FILE").unwrap();

        let status = std::process::Command::new("/bin/chmod")
            .env_clear()
            .args(["+a", "everyone deny write"])
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(
            super::validate_private_file(&path, "OMNIS_TEST_FILE")
                .unwrap_err()
                .to_string()
                .contains("EXTENDED_ACL_REFUSED")
        );
    }
}
