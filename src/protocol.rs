//! Postgres Wire Protocol Primitives
//!
//! Minimum subset of the Postgres v3 wire protocol needed for the proxy:
//! parse StartupMessages, detect auth completion, inject SET commands,
//! frame messages for transparent forwarding.
//!
//! Reference: https://www.postgresql.org/docs/current/protocol-message-formats.html

use bytes::{Buf, BufMut, BytesMut};
use std::collections::HashMap;
use std::io;

// ─── Constants ──────────────────────────────────────────────────────────────

/// Postgres protocol version 3.0
const PROTOCOL_VERSION_30: i32 = 196608; // 0x00030000

/// SSLRequest magic number
const SSL_REQUEST_CODE: i32 = 80877103;

/// CancelRequest magic number
const CANCEL_REQUEST_CODE: i32 = 80877102;

/// Single byte denying SSL
pub const SSL_DENY: &[u8] = &[b'N'];

/// Backend message types we care about
pub mod backend {
    pub const AUTHENTICATION: u8 = b'R';
    pub const PARAMETER_STATUS: u8 = b'S';
    pub const BACKEND_KEY_DATA: u8 = b'K';
    pub const READY_FOR_QUERY: u8 = b'Z';
    pub const COMMAND_COMPLETE: u8 = b'C';
    pub const ERROR_RESPONSE: u8 = b'E';
    pub const ROW_DESCRIPTION: u8 = b'T';
    pub const DATA_ROW: u8 = b'D';
    pub const EMPTY_QUERY_RESPONSE: u8 = b'I';
}

/// Authentication subtypes
pub mod auth {
    pub const OK: i32 = 0;
    pub const CLEARTEXT_PASSWORD: i32 = 3;
    pub const MD5_PASSWORD: i32 = 5;
    pub const SASL: i32 = 10;
    pub const SASL_CONTINUE: i32 = 11;
    pub const SASL_FINAL: i32 = 12;
}

// ─── Startup Message Types ──────────────────────────────────────────────────

/// What the client sent as its first message.
pub enum StartupType {
    /// SSLRequest — client wants to negotiate TLS.
    SslRequest,
    /// CancelRequest — client wants to cancel a query.
    CancelRequest,
    /// Normal StartupMessage with parameters.
    Startup(StartupMessage),
}

/// Parsed StartupMessage parameters.
pub struct StartupMessage {
    pub params: HashMap<String, String>,
}

// ─── Backend Message ────────────────────────────────────────────────────────

/// A complete message from the Postgres backend.
pub struct BackendMessage {
    /// Message type byte (e.g., b'R' for Authentication)
    pub msg_type: u8,
    /// Complete raw bytes including type and length (for forwarding)
    pub raw: BytesMut,
    /// Payload after the length field
    pub payload: BytesMut,
}

impl BackendMessage {
    /// Is this AuthenticationOk?
    pub fn is_auth_ok(&self) -> bool {
        self.msg_type == backend::AUTHENTICATION
            && self.payload.len() >= 4
            && (&self.payload[..4]).get_i32() == auth::OK
    }

    /// Is this an auth challenge that expects a client response?
    /// (Not AuthOk or SASLFinal, which require no client reply.)
    pub fn is_auth_challenge(&self) -> bool {
        if self.msg_type != backend::AUTHENTICATION || self.payload.len() < 4 {
            return false;
        }
        let subtype = i32::from_be_bytes([
            self.payload[0],
            self.payload[1],
            self.payload[2],
            self.payload[3],
        ]);
        subtype != auth::OK && subtype != auth::SASL_FINAL
    }

    /// Is this ReadyForQuery?
    pub fn is_ready_for_query(&self) -> bool {
        self.msg_type == backend::READY_FOR_QUERY
    }

    /// Is this ErrorResponse?
    pub fn is_error_response(&self) -> bool {
        self.msg_type == backend::ERROR_RESPONSE
    }

    /// Is this ParameterStatus?
    pub fn is_parameter_status(&self) -> bool {
        self.msg_type == backend::PARAMETER_STATUS
    }

    /// Is this BackendKeyData?
    pub fn is_backend_key_data(&self) -> bool {
        self.msg_type == backend::BACKEND_KEY_DATA
    }

    /// Is this RowDescription?
    #[allow(dead_code)]
    pub fn is_row_description(&self) -> bool {
        self.msg_type == backend::ROW_DESCRIPTION
    }

    /// Is this DataRow?
    #[allow(dead_code)]
    pub fn is_data_row(&self) -> bool {
        self.msg_type == backend::DATA_ROW
    }

    /// Return the auth subtype (e.g. OK=0, CLEARTEXT=3, MD5=5, SASL=10).
    /// Returns `None` if this isn't an Authentication message or payload is too short.
    pub fn auth_subtype(&self) -> Option<i32> {
        if self.msg_type != backend::AUTHENTICATION || self.payload.len() < 4 {
            return None;
        }
        Some(i32::from_be_bytes([
            self.payload[0],
            self.payload[1],
            self.payload[2],
            self.payload[3],
        ]))
    }

    /// Extract human-readable error message from an ErrorResponse.
    pub fn error_message(&self) -> String {
        if !self.is_error_response() {
            return String::from("not an error");
        }
        let mut parts = Vec::new();
        let mut offset = 0;
        let data = &self.payload;

        while offset < data.len() {
            let field_type = data[offset];
            if field_type == 0 {
                break;
            }
            offset += 1;

            // Find null terminator
            let str_end = data[offset..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| offset + p)
                .unwrap_or(data.len());

            let value = String::from_utf8_lossy(&data[offset..str_end]).to_string();
            offset = str_end + 1;

            match field_type {
                b'M' => parts.insert(0, value), // Message
                b'D' => parts.push(value),       // Detail
                _ => {}
            }
        }

        if parts.is_empty() {
            String::from("unknown error")
        } else {
            parts.join(": ")
        }
    }
}

// ─── Parsing ────────────────────────────────────────────────────────────────

/// Try to read a complete startup-phase message from the buffer.
///
/// Startup messages have no type byte — they start with Int32 length.
/// Returns `None` if not enough data. Consumes the message from `buf` on success.
pub fn try_read_startup(buf: &mut BytesMut) -> Option<StartupType> {
    if buf.len() < 8 {
        return None;
    }

    let length = i32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if length < 8 || length > 10240 {
        return None; // sanity check
    }
    if buf.len() < length {
        return None; // need more data
    }

    let msg_buf = buf.split_to(length);
    let version = i32::from_be_bytes([msg_buf[4], msg_buf[5], msg_buf[6], msg_buf[7]]);

    match version {
        v if v == SSL_REQUEST_CODE => Some(StartupType::SslRequest),
        v if v == CANCEL_REQUEST_CODE => Some(StartupType::CancelRequest),
        _ => {
            // Parse key-value pairs
            let mut params = HashMap::new();
            let mut offset = 8;

            while offset < length - 1 {
                // Read key
                let key_end = msg_buf[offset..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|p| offset + p);
                let Some(key_end) = key_end else { break };
                let key = String::from_utf8_lossy(&msg_buf[offset..key_end]).to_string();
                offset = key_end + 1;

                // Read value
                let val_end = msg_buf[offset..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|p| offset + p);
                let Some(val_end) = val_end else { break };
                let value = String::from_utf8_lossy(&msg_buf[offset..val_end]).to_string();
                offset = val_end + 1;

                if !key.is_empty() {
                    params.insert(key, value);
                }
            }

            Some(StartupType::Startup(StartupMessage { params }))
        }
    }
}

/// Try to read a complete backend message from the buffer.
///
/// Backend messages: `u8 type | i32 length | payload`
/// Length includes itself (4 bytes) but not the type byte.
/// Returns `None` if not enough data. Consumes the message from `buf` on success.
pub fn try_read_backend_message(buf: &mut BytesMut) -> Option<BackendMessage> {
    if buf.len() < 5 {
        return None;
    }

    let msg_type = buf[0];
    let length = i32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    let total_length = 1 + length; // type byte + length value

    if buf.len() < total_length {
        return None;
    }

    let raw = BytesMut::from(&buf[..total_length]);
    let payload = BytesMut::from(&buf[5..total_length]);
    buf.advance(total_length);

    Some(BackendMessage {
        msg_type,
        raw,
        payload,
    })
}

// ─── Building ───────────────────────────────────────────────────────────────

/// Build a StartupMessage with the given parameters.
pub fn build_startup_message(params: &HashMap<String, String>) -> BytesMut {
    // Calculate size: 4 (length) + 4 (version) + key-value pairs + terminal null
    let mut data_len = 4; // version
    for (key, value) in params {
        data_len += key.len() + 1 + value.len() + 1;
    }
    data_len += 1; // terminal null

    let total_len = 4 + data_len; // 4 for length field
    let mut buf = BytesMut::with_capacity(total_len);

    buf.put_i32(total_len as i32);
    buf.put_i32(PROTOCOL_VERSION_30);

    for (key, value) in params {
        buf.put_slice(key.as_bytes());
        buf.put_u8(0);
        buf.put_slice(value.as_bytes());
        buf.put_u8(0);
    }
    buf.put_u8(0); // terminal null

    buf
}

/// Build a SimpleQuery ('Q') message.
pub fn build_query_message(sql: &str) -> BytesMut {
    let msg_len = 4 + sql.len() + 1; // length field + sql + null
    let mut buf = BytesMut::with_capacity(1 + msg_len);

    buf.put_u8(b'Q');
    buf.put_i32(msg_len as i32);
    buf.put_slice(sql.as_bytes());
    buf.put_u8(0);

    buf
}

/// Build an ErrorResponse ('E') message.
pub fn build_error_response(severity: &str, sqlstate: &str, message: &str) -> BytesMut {
    let fields: Vec<(u8, &str)> = vec![
        (b'S', severity),
        (b'V', severity),
        (b'C', sqlstate),
        (b'M', message),
    ];

    // Calculate fields length
    let fields_len: usize = fields.iter().map(|(_, v)| 1 + v.len() + 1).sum::<usize>() + 1; // +1 terminal null
    let msg_len = 4 + fields_len;

    let mut buf = BytesMut::with_capacity(1 + msg_len);
    buf.put_u8(b'E');
    buf.put_i32(msg_len as i32);

    for (field_type, value) in &fields {
        buf.put_u8(*field_type);
        buf.put_slice(value.as_bytes());
        buf.put_u8(0);
    }
    buf.put_u8(0); // terminal null

    buf
}

/// Build an AuthenticationCleartextPassword request (server → client).
pub fn build_auth_cleartext_request() -> BytesMut {
    // 'R' | int32 len(8) | int32 subtype(3)
    let mut buf = BytesMut::with_capacity(9);
    buf.put_u8(backend::AUTHENTICATION);
    buf.put_i32(8); // length: 4 (len field) + 4 (subtype)
    buf.put_i32(auth::CLEARTEXT_PASSWORD);
    buf
}

/// Build an AuthenticationOk message (server → client).
pub fn build_auth_ok() -> BytesMut {
    let mut buf = BytesMut::with_capacity(9);
    buf.put_u8(backend::AUTHENTICATION);
    buf.put_i32(8);
    buf.put_i32(auth::OK);
    buf
}

/// Try to read a PasswordMessage ('p') from the client buffer.
/// Returns the password string (without null terminator) or None if not enough data.
pub fn try_read_password_message(buf: &mut BytesMut) -> Option<String> {
    if buf.len() < 5 {
        return None;
    }
    if buf[0] != b'p' {
        return None;
    }
    let length = i32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    let total = 1 + length;
    if buf.len() < total {
        return None;
    }
    // Password is between offset 5 and total-1 (strip null terminator)
    let password_end = if total > 5 && buf[total - 1] == 0 {
        total - 1
    } else {
        total
    };
    let password = String::from_utf8_lossy(&buf[5..password_end]).to_string();
    buf.advance(total);
    Some(password)
}

/// Build a PasswordMessage ('p') for sending to the server.
pub fn build_password_message(password: &[u8]) -> BytesMut {
    let msg_len = 4 + password.len() + 1; // length field + password + null
    let mut buf = BytesMut::with_capacity(1 + msg_len);
    buf.put_u8(b'p');
    buf.put_i32(msg_len as i32);
    buf.put_slice(password);
    buf.put_u8(0);
    buf
}

/// Build a SASLInitialResponse message ('p') with mechanism name and initial data.
pub fn build_sasl_initial_response(mechanism: &str, data: &[u8]) -> BytesMut {
    // 'p' | int32 len | mechanism\0 | int32 data_len | data
    let msg_len = 4 + mechanism.len() + 1 + 4 + data.len();
    let mut buf = BytesMut::with_capacity(1 + msg_len);
    buf.put_u8(b'p');
    buf.put_i32(msg_len as i32);
    buf.put_slice(mechanism.as_bytes());
    buf.put_u8(0);
    buf.put_i32(data.len() as i32);
    buf.put_slice(data);
    buf
}

/// Build a SASLResponse message ('p') with response data.
pub fn build_sasl_response(data: &[u8]) -> BytesMut {
    let msg_len = 4 + data.len();
    let mut buf = BytesMut::with_capacity(1 + msg_len);
    buf.put_u8(b'p');
    buf.put_i32(msg_len as i32);
    buf.put_slice(data);
    buf
}

// ─── SQL Escaping ───────────────────────────────────────────────────────────

/// Escape a value as a SQL single-quoted literal.
/// Rejects characters that have no business in a tenant ID.
#[allow(dead_code)]
pub fn escape_literal(value: &str) -> io::Result<String> {
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid tenant ID: disallowed characters in '{value}'"),
        ));
    }
    Ok(format!("'{}'", value.replace('\'', "''")))
}

/// Escape a value as a SQL single-quoted literal for SET commands.
///
/// Unlike `escape_literal()` which restricts characters (for untrusted tenant IDs),
/// this allows any content (resolver results come from the database and may contain
/// array literals like `{a,b,c}`, commas, spaces, etc.). Defense is quote-doubling only.
pub fn escape_set_value(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// Quote an identifier (double-quoted).
pub fn quote_ident(value: &str) -> io::Result<String> {
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid identifier: '{value}'"),
        ));
    }
    Ok(format!("\"{}\"", value.replace('"', "\"\"")))
}
