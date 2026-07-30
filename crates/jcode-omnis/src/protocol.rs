use crate::model::{AnchorRequest, AppendDisposition, SignedCheckpoint};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fmt;
use std::io::{Read, Write};

pub const IPC_PROTOCOL: &str = "jourdanlabs.omnis-checkpoint-ipc.v1";
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Status {
        protocol: String,
        request_id: String,
    },
    Anchor {
        protocol: String,
        request: AnchorRequest,
    },
    Lookup {
        protocol: String,
        request_id: String,
    },
}

impl Request {
    pub fn status(request_id: impl Into<String>) -> Result<Self, FrameError> {
        let request_id = request_id.into();
        validate_request_id(&request_id)?;
        Ok(Self::Status {
            protocol: IPC_PROTOCOL.to_string(),
            request_id,
        })
    }

    pub fn anchor(request: AnchorRequest) -> Self {
        Self::Anchor {
            protocol: IPC_PROTOCOL.to_string(),
            request,
        }
    }

    pub fn lookup(request_id: impl Into<String>) -> Result<Self, FrameError> {
        let request_id = request_id.into();
        validate_request_id(&request_id)?;
        Ok(Self::Lookup {
            protocol: IPC_PROTOCOL.to_string(),
            request_id,
        })
    }

    pub fn protocol(&self) -> &str {
        match self {
            Self::Status { protocol, .. }
            | Self::Anchor { protocol, .. }
            | Self::Lookup { protocol, .. } => protocol,
        }
    }

    pub fn request_id(&self) -> &str {
        match self {
            Self::Status { request_id, .. } | Self::Lookup { request_id, .. } => request_id,
            Self::Anchor { request, .. } => &request.request_id,
        }
    }

    pub fn validate_envelope(&self) -> Result<(), FrameError> {
        if self.protocol() != IPC_PROTOCOL {
            return Err(FrameError::new(
                "PROTOCOL_MISMATCH",
                "checkpoint IPC protocol does not match",
            ));
        }
        if let Self::Anchor { request, .. } = self {
            crate::model::validate_anchor_request(request)
                .map_err(|error| FrameError::new("INVALID_ANCHOR_REQUEST", error.to_string()))?;
        }
        validate_request_id(self.request_id())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Success {
    Status {
        authority_id: String,
        ledger_id: String,
        receipt_ledger_path: String,
        signing_key_id: String,
        latest: Option<SignedCheckpoint>,
    },
    Anchor {
        disposition: AppendDisposition,
        checkpoint: SignedCheckpoint,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Ok {
        protocol: String,
        request_id: String,
        result: Box<Success>,
    },
    LookupOk {
        protocol: String,
        request_id: String,
        checkpoint: Option<Box<SignedCheckpoint>>,
    },
    Error {
        protocol: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
        error: ErrorBody,
    },
}

impl Response {
    pub fn success(request_id: impl Into<String>, result: Success) -> Self {
        Self::Ok {
            protocol: IPC_PROTOCOL.to_string(),
            request_id: request_id.into(),
            result: Box::new(result),
        }
    }

    pub fn error(
        request_id: Option<String>,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::Error {
            protocol: IPC_PROTOCOL.to_string(),
            request_id,
            error: ErrorBody {
                code: code.into(),
                message: message.into(),
                retryable: false,
            },
        }
    }

    pub fn lookup_success(
        request_id: impl Into<String>,
        checkpoint: Option<SignedCheckpoint>,
    ) -> Self {
        Self::LookupOk {
            protocol: IPC_PROTOCOL.to_string(),
            request_id: request_id.into(),
            checkpoint: checkpoint.map(Box::new),
        }
    }

    pub fn protocol(&self) -> &str {
        match self {
            Self::Ok { protocol, .. }
            | Self::LookupOk { protocol, .. }
            | Self::Error { protocol, .. } => protocol,
        }
    }

    pub fn request_id(&self) -> Option<&str> {
        match self {
            Self::Ok { request_id, .. } | Self::LookupOk { request_id, .. } => Some(request_id),
            Self::Error { request_id, .. } => request_id.as_deref(),
        }
    }
}

#[derive(Debug)]
pub struct FrameError {
    code: &'static str,
    message: String,
}

impl FrameError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for FrameError {}

pub fn write_frame<W: Write, T: Serialize>(writer: &mut W, value: &T) -> Result<(), FrameError> {
    let payload = serde_json::to_vec(value)
        .map_err(|error| FrameError::new("JSON_ENCODE_FAILED", error.to_string()))?;
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err(FrameError::new(
            "FRAME_TOO_LARGE",
            format!("checkpoint frame must contain 1..={MAX_FRAME_BYTES} JSON bytes"),
        ));
    }
    writer
        .write_all(&payload)
        .and_then(|_| writer.write_all(b"\n"))
        .and_then(|_| writer.flush())
        .map_err(|error| FrameError::new("FRAME_WRITE_FAILED", error.to_string()))
}

pub fn read_frame<R: Read, T: DeserializeOwned>(reader: &mut R) -> Result<T, FrameError> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_FRAME_BYTES + 2) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| FrameError::new("FRAME_READ_FAILED", error.to_string()))?;
    if bytes.len() > MAX_FRAME_BYTES + 1 {
        return Err(FrameError::new(
            "FRAME_TOO_LARGE",
            format!("checkpoint frame exceeds {MAX_FRAME_BYTES} JSON bytes"),
        ));
    }
    if bytes.last() != Some(&b'\n') {
        return Err(FrameError::new(
            "FRAME_TERMINATION_REQUIRED",
            "checkpoint frame must end with exactly one newline",
        ));
    }
    let payload = &bytes[..bytes.len() - 1];
    if payload.is_empty() {
        return Err(FrameError::new(
            "EMPTY_FRAME",
            "checkpoint frame JSON cannot be empty",
        ));
    }
    if payload.contains(&b'\n') || payload.contains(&b'\r') {
        return Err(FrameError::new(
            "MULTIPLE_FRAMES_REFUSED",
            "checkpoint connection accepts exactly one newline-delimited JSON value",
        ));
    }
    serde_json::from_slice(payload)
        .map_err(|error| FrameError::new("INVALID_JSON", error.to_string()))
}

fn validate_request_id(request_id: &str) -> Result<(), FrameError> {
    if request_id.is_empty()
        || request_id.len() > 256
        || !request_id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'/')
        })
    {
        return Err(FrameError::new(
            "INVALID_REQUEST_ID",
            "request_id must be 1-256 bounded ASCII identity characters",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DEFAULT_LEDGER_ID, PROTOCOL, ReceiptLinkWitness};

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn anchor_request() -> AnchorRequest {
        AnchorRequest {
            protocol: PROTOCOL.to_string(),
            request_id: "anchor:test/1".to_string(),
            ledger_id: DEFAULT_LEDGER_ID.to_string(),
            receipt_ledger_path: "/Users/test/.jcode/state/omnis-key/receipts.jsonl".to_string(),
            prior_checkpoint_hash: None,
            observed_receipt_sequence: 1,
            observed_receipt_head: digest('a'),
            continuity: vec![ReceiptLinkWitness {
                sequence: 1,
                parent_hash: None,
                receipt_hash: digest('a'),
            }],
        }
    }

    #[test]
    fn status_round_trip_is_one_bounded_frame() {
        let request = Request::status("status:one").unwrap();
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &request).unwrap();
        assert_eq!(bytes.iter().filter(|byte| **byte == b'\n').count(), 1);
        let decoded: Request = read_frame(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded, request);

        let lookup = Request::lookup("anchor:recover").unwrap();
        let mut lookup_bytes = Vec::new();
        write_frame(&mut lookup_bytes, &lookup).unwrap();
        let decoded_lookup: Request = read_frame(&mut lookup_bytes.as_slice()).unwrap();
        assert_eq!(decoded_lookup, lookup);

        let response = Response::lookup_success("anchor:recover", None);
        let mut response_bytes = Vec::new();
        write_frame(&mut response_bytes, &response).unwrap();
        let decoded_response: Response = read_frame(&mut response_bytes.as_slice()).unwrap();
        assert_eq!(decoded_response, response);
    }

    #[test]
    fn missing_extra_and_oversized_frames_refuse() {
        let mut missing = br#"{"op":"status"}"#.as_slice();
        assert_eq!(
            read_frame::<_, Request>(&mut missing).unwrap_err().code(),
            "FRAME_TERMINATION_REQUIRED"
        );

        let mut extra = b"{\"op\":\"status\"}\n{\"op\":\"status\"}\n".as_slice();
        assert_eq!(
            read_frame::<_, Request>(&mut extra).unwrap_err().code(),
            "MULTIPLE_FRAMES_REFUSED"
        );

        let mut oversized = vec![b'a'; MAX_FRAME_BYTES + 1];
        oversized.push(b'\n');
        assert_eq!(
            read_frame::<_, Request>(&mut oversized.as_slice())
                .unwrap_err()
                .code(),
            "FRAME_TOO_LARGE"
        );
    }

    #[test]
    fn anchor_validates_ipc_and_checkpoint_protocols_independently() {
        let request = Request::anchor(anchor_request());
        request.validate_envelope().unwrap();

        let mut wrong_ipc = request.clone();
        let Request::Anchor { protocol, .. } = &mut wrong_ipc else {
            unreachable!()
        };
        *protocol = PROTOCOL.to_string();
        assert_eq!(
            wrong_ipc.validate_envelope().unwrap_err().code(),
            "PROTOCOL_MISMATCH"
        );

        let mut wrong_checkpoint = request;
        let Request::Anchor {
            request: checkpoint,
            ..
        } = &mut wrong_checkpoint
        else {
            unreachable!()
        };
        checkpoint.protocol = IPC_PROTOCOL.to_string();
        assert_eq!(
            wrong_checkpoint.validate_envelope().unwrap_err().code(),
            "INVALID_ANCHOR_REQUEST"
        );
    }

    #[test]
    fn maximum_valid_continuity_stays_inside_the_wire_frame() {
        let hash = digest('a');
        let mut prior = digest('b');
        let link_count = crate::model::MAX_CONTINUITY_LINKS as u64;
        let first_sequence = u64::MAX - link_count + 1;
        let continuity = (first_sequence..=u64::MAX)
            .map(|sequence| {
                let receipt_hash = hash.clone();
                let witness = ReceiptLinkWitness {
                    sequence,
                    parent_hash: Some(prior.clone()),
                    receipt_hash: receipt_hash.clone(),
                };
                prior = receipt_hash;
                witness
            })
            .collect();
        let request = Request::anchor(AnchorRequest {
            protocol: PROTOCOL.to_string(),
            request_id: "a".repeat(crate::model::MAX_REQUEST_ID_BYTES),
            ledger_id: "l".repeat(crate::model::MAX_LEDGER_ID_BYTES),
            receipt_ledger_path: format!(
                "/{}",
                "p".repeat(crate::model::MAX_LEDGER_PATH_BYTES - 1)
            ),
            prior_checkpoint_hash: Some(digest('b')),
            observed_receipt_sequence: u64::MAX,
            observed_receipt_head: hash,
            continuity,
        });
        request.validate_envelope().unwrap();
        let mut encoded = Vec::new();
        write_frame(&mut encoded, &request).unwrap();
        assert!(encoded.len() <= MAX_FRAME_BYTES + 1);
    }
}
