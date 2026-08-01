use serde::Serialize;
use serde_json::Value;
use std::io::Write;

use crate::{COMPATIBILITY_BASE_NAME, COMPATIBILITY_BASE_VERSION, PRODUCT_VERSION};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Envelope<'a> {
    schema_version: u8,
    command: &'a str,
    ok: bool,
    code: &'a str,
    data: Value,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VersionData {
    product_version: &'static str,
    compatibility_base_name: &'static str,
    compatibility_base_version: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ChainData {
    pub(crate) state: &'static str,
    pub(crate) entry_count: usize,
    pub(crate) head_sha256: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecordData {
    pub(crate) disposition: &'static str,
    pub(crate) sequence: u64,
    pub(crate) receipt_sha256: String,
    pub(crate) claim_ceiling: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReconcileData {
    pub(crate) pending_before: usize,
    pub(crate) appended: usize,
    pub(crate) existing: usize,
    pub(crate) pending_after: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CheckpointAnchorData {
    pub(crate) disposition: &'static str,
    pub(crate) checkpoint_sequence: u64,
    pub(crate) checkpoint_sha256: String,
    pub(crate) observed_receipt_sequence: u64,
    pub(crate) observed_receipt_head_sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CheckpointVerifyData {
    pub(crate) checkpoint_sequence: u64,
    pub(crate) checkpoint_sha256: String,
    pub(crate) observed_receipt_sequence: u64,
    pub(crate) observed_receipt_head_sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DemoData {
    pub(crate) fixture_only: bool,
    pub(crate) first_append: &'static str,
    pub(crate) exact_replay: &'static str,
    pub(crate) valid_chain: bool,
    pub(crate) tampered_copy_refused: bool,
    pub(crate) tamper_refusal_code: &'static str,
    pub(crate) execution_authorized: bool,
}

pub(crate) fn emit_version(stdout: &mut dyn Write) -> i32 {
    emit_json(
        stdout,
        "version",
        true,
        "VERSION",
        &VersionData {
            product_version: PRODUCT_VERSION,
            compatibility_base_name: COMPATIBILITY_BASE_NAME,
            compatibility_base_version: COMPATIBILITY_BASE_VERSION,
        },
    )
}

pub(crate) fn emit<T: Serialize>(
    json: bool,
    command: &str,
    ok: bool,
    code: &str,
    data: Option<&T>,
    exit: i32,
    streams: (&mut dyn Write, &mut dyn Write),
) -> i32 {
    let (stdout, stderr) = streams;
    if json {
        let data = match data {
            Some(data) => match serde_json::to_value(data) {
                Ok(data) => data,
                Err(_) => return 3,
            },
            None => Value::Null,
        };
        return if emit_envelope(stdout, command, ok, code, data) == 0 {
            exit
        } else {
            3
        };
    }
    let rendered = match data {
        Some(data) => match serde_json::to_string(data) {
            Ok(data) => format!("{code} {data}\n"),
            Err(_) => return 3,
        },
        None => format!("{code}\n"),
    };
    let write = if ok {
        stdout.write_all(rendered.as_bytes())
    } else {
        stderr.write_all(rendered.as_bytes())
    };
    match write {
        Ok(()) => exit,
        Err(_) => 3,
    }
}

fn emit_json<T: Serialize>(
    stdout: &mut dyn Write,
    command: &str,
    ok: bool,
    code: &str,
    data: &T,
) -> i32 {
    let data = match serde_json::to_value(data) {
        Ok(data) => data,
        Err(_) => return 3,
    };
    emit_envelope(stdout, command, ok, code, data)
}

fn emit_envelope(stdout: &mut dyn Write, command: &str, ok: bool, code: &str, data: Value) -> i32 {
    let envelope = Envelope {
        schema_version: 1,
        command,
        ok,
        code,
        data,
    };
    match serde_json::to_writer(&mut *stdout, &envelope)
        .and_then(|()| stdout.write_all(b"\n").map_err(serde_json::Error::io))
    {
        Ok(()) => 0,
        Err(_) => 3,
    }
}

pub(crate) fn bare_sha256(value: &str) -> anyhow::Result<String> {
    let raw = value
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow::anyhow!("digest prefix missing"))?;
    if raw.len() != 64
        || !raw.bytes().all(|byte| byte.is_ascii_hexdigit())
        || raw.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        anyhow::bail!("digest is not canonical lowercase SHA-256")
    }
    Ok(raw.to_string())
}
