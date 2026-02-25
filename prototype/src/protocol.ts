/**
 * Pgvpd — Postgres Wire Protocol Primitives
 *
 * Implements the minimum subset of the Postgres v3 wire protocol needed
 * for the proxy to parse StartupMessages, detect auth completion, inject
 * SET commands, and frame messages for transparent forwarding.
 *
 * Reference: https://www.postgresql.org/docs/current/protocol-message-formats.html
 */

// ─── Constants ──────────────────────────────────────────────────────────────

/** Postgres protocol version 3.0 */
export const PROTOCOL_VERSION_30 = 196608; // 0x00030000

/** SSLRequest magic number */
export const SSL_REQUEST_CODE = 80877103; // 0x04D2162F

/** CancelRequest magic number */
export const CANCEL_REQUEST_CODE = 80877102;

/** Single-byte response denying SSL */
export const SSL_DENY = Buffer.from([0x4e]); // 'N'

/** Backend message type bytes */
export const BackendMsg = {
  Authentication: 0x52, // 'R'
  ParameterStatus: 0x53, // 'S'
  BackendKeyData: 0x4b, // 'K'
  ReadyForQuery: 0x5a, // 'Z'
  CommandComplete: 0x43, // 'C'
  RowDescription: 0x54, // 'T'
  DataRow: 0x44, // 'D'
  ErrorResponse: 0x45, // 'E'
  NoticeResponse: 0x4e, // 'N'
  EmptyQueryResponse: 0x49, // 'I'
} as const;

/** Authentication subtypes (first Int32 after 'R' length) */
export const AuthType = {
  Ok: 0,
  CleartextPassword: 3,
  MD5Password: 5,
  SASL: 10,
  SASLContinue: 11,
  SASLFinal: 12,
} as const;

// ─── StartupMessage ─────────────────────────────────────────────────────────

export interface StartupParams {
  /** Key-value pairs from the startup message (user, database, etc.) */
  params: Map<string, string>;
}

/**
 * Parse a StartupMessage buffer into its parameters.
 *
 * StartupMessage format (no type byte):
 *   Int32 length (including itself)
 *   Int32 protocol version (196608 for 3.0)
 *   { String key \0 String value \0 }*
 *   \0  (terminal null)
 */
export function parseStartupMessage(buf: Buffer): StartupParams {
  const params = new Map<string, string>();
  // Skip length (4 bytes) and version (4 bytes)
  let offset = 8;
  const length = buf.readInt32BE(0);

  while (offset < length - 1) {
    // Read key
    const keyEnd = buf.indexOf(0, offset);
    if (keyEnd === -1 || keyEnd >= length) break;
    const key = buf.toString("utf8", offset, keyEnd);
    offset = keyEnd + 1;

    // Read value
    const valEnd = buf.indexOf(0, offset);
    if (valEnd === -1 || valEnd >= length) break;
    const value = buf.toString("utf8", offset, valEnd);
    offset = valEnd + 1;

    if (key) params.set(key, value);
  }

  return { params };
}

/**
 * Build a StartupMessage buffer from parameters.
 *
 * Reconstructs a valid StartupMessage with protocol version 3.0.
 */
export function buildStartupMessage(params: Map<string, string>): Buffer {
  // Calculate payload size: version + key-value pairs + terminal null
  let payloadLen = 4; // protocol version
  for (const [key, value] of params) {
    payloadLen += Buffer.byteLength(key, "utf8") + 1; // key + null
    payloadLen += Buffer.byteLength(value, "utf8") + 1; // value + null
  }
  payloadLen += 1; // terminal null

  const totalLen = 4 + payloadLen; // 4 for length field itself
  const buf = Buffer.alloc(totalLen);
  let offset = 0;

  buf.writeInt32BE(totalLen, offset);
  offset += 4;
  buf.writeInt32BE(PROTOCOL_VERSION_30, offset);
  offset += 4;

  for (const [key, value] of params) {
    offset += buf.write(key, offset, "utf8");
    buf[offset++] = 0;
    offset += buf.write(value, offset, "utf8");
    buf[offset++] = 0;
  }
  buf[offset] = 0; // terminal null

  return buf;
}

// ─── Query Message ──────────────────────────────────────────────────────────

/**
 * Build a SimpleQuery ('Q') message.
 *
 * Format: 'Q' Int32(length) String(query \0)
 */
export function buildQueryMessage(sql: string): Buffer {
  const sqlBytes = Buffer.from(sql, "utf8");
  const msgLen = 4 + sqlBytes.length + 1; // length field + sql + null terminator
  const buf = Buffer.alloc(1 + msgLen);

  buf[0] = 0x51; // 'Q'
  buf.writeInt32BE(msgLen, 1);
  sqlBytes.copy(buf, 5);
  buf[5 + sqlBytes.length] = 0; // null terminator

  return buf;
}

// ─── ErrorResponse ──────────────────────────────────────────────────────────

/**
 * Build an ErrorResponse ('E') message to send to the client.
 *
 * Format: 'E' Int32(length) { Byte1(fieldType) String(value \0) }* \0
 */
export function buildErrorResponse(
  severity: string,
  sqlstate: string,
  message: string,
  detail?: string,
): Buffer {
  const fields: Array<{ type: string; value: string }> = [
    { type: "S", value: severity },
    { type: "V", value: severity }, // non-localized severity
    { type: "C", value: sqlstate },
    { type: "M", value: message },
  ];
  if (detail) {
    fields.push({ type: "D", value: detail });
  }

  // Calculate total field bytes
  let fieldsLen = 0;
  for (const f of fields) {
    fieldsLen += 1 + Buffer.byteLength(f.value, "utf8") + 1; // type byte + value + null
  }
  fieldsLen += 1; // terminal null

  const msgLen = 4 + fieldsLen; // length includes itself
  const buf = Buffer.alloc(1 + msgLen);

  buf[0] = 0x45; // 'E'
  buf.writeInt32BE(msgLen, 1);

  let offset = 5;
  for (const f of fields) {
    buf[offset++] = f.type.charCodeAt(0);
    offset += buf.write(f.value, offset, "utf8");
    buf[offset++] = 0;
  }
  buf[offset] = 0; // terminal null

  return buf;
}

// ─── Message Framer ─────────────────────────────────────────────────────────

/**
 * Parsed backend message (server → client).
 */
export interface BackendMessage {
  /** Message type byte */
  type: number;
  /** Total message length (type byte + length field + payload) */
  totalLength: number;
  /** Raw payload after the length field */
  payload: Buffer;
  /** The complete raw message bytes (for forwarding) */
  raw: Buffer;
}

/**
 * Buffers TCP stream data and extracts complete Postgres protocol messages.
 *
 * TCP is a stream protocol — we may receive partial messages or multiple
 * messages in a single chunk. This class handles reassembly.
 */
export class MessageFramer {
  private buffer: Buffer = Buffer.alloc(0);

  /** Append new data from the TCP stream. */
  push(data: Buffer): void {
    this.buffer = Buffer.concat([this.buffer, data]);
  }

  /** Returns true if there's any buffered data. */
  hasData(): boolean {
    return this.buffer.length > 0;
  }

  /** Return the raw buffer (for forwarding remaining data). */
  remaining(): Buffer {
    return this.buffer;
  }

  /** Drain and return all buffered data, resetting the buffer. */
  drain(): Buffer {
    const data = this.buffer;
    this.buffer = Buffer.alloc(0);
    return data;
  }

  /**
   * Try to read the initial startup-phase message from a client.
   *
   * Startup messages have no type byte — they start with Int32 length.
   * This handles StartupMessage, SSLRequest, and CancelRequest.
   *
   * Returns null if not enough data yet.
   */
  nextStartupMessage(): Buffer | null {
    if (this.buffer.length < 4) return null;

    const length = this.buffer.readInt32BE(0);
    if (length < 4 || length > 10240) return null; // sanity check

    if (this.buffer.length < length) return null;

    const msg = Buffer.from(this.buffer.subarray(0, length));
    this.buffer = this.buffer.subarray(length);
    return msg;
  }

  /**
   * Try to read a complete backend message (server → client).
   *
   * Backend messages: Byte1(type) Int32(length) payload
   * The length field includes itself (4 bytes) but not the type byte.
   *
   * Returns null if not enough data yet.
   */
  nextBackendMessage(): BackendMessage | null {
    if (this.buffer.length < 5) return null;

    const type = this.buffer[0];
    const length = this.buffer.readInt32BE(1); // includes the 4 length bytes
    const totalLength = 1 + length; // type byte + length value

    if (this.buffer.length < totalLength) return null;

    const raw = Buffer.from(this.buffer.subarray(0, totalLength));
    const payload = Buffer.from(this.buffer.subarray(5, totalLength));
    this.buffer = this.buffer.subarray(totalLength);

    return { type, totalLength, payload, raw };
  }
}

// ─── Message Inspection Helpers ─────────────────────────────────────────────

/** Check if a startup-phase buffer is an SSLRequest. */
export function isSSLRequest(buf: Buffer): boolean {
  if (buf.length < 8) return false;
  return buf.readInt32BE(4) === SSL_REQUEST_CODE;
}

/** Check if a startup-phase buffer is a CancelRequest. */
export function isCancelRequest(buf: Buffer): boolean {
  if (buf.length < 8) return false;
  return buf.readInt32BE(4) === CANCEL_REQUEST_CODE;
}

/** Check if a backend message is AuthenticationOk. */
export function isAuthOk(msg: BackendMessage): boolean {
  return (
    msg.type === BackendMsg.Authentication &&
    msg.payload.length >= 4 &&
    msg.payload.readInt32BE(0) === AuthType.Ok
  );
}

/** Check if a backend message is ReadyForQuery. */
export function isReadyForQuery(msg: BackendMessage): boolean {
  return msg.type === BackendMsg.ReadyForQuery;
}

/** Check if a backend message is an ErrorResponse. */
export function isErrorResponse(msg: BackendMessage): boolean {
  return msg.type === BackendMsg.ErrorResponse;
}

/**
 * Extract human-readable error text from an ErrorResponse message.
 */
export function extractErrorMessage(msg: BackendMessage): string {
  const parts: string[] = [];
  let offset = 0;

  while (offset < msg.payload.length) {
    const fieldType = msg.payload[offset];
    if (fieldType === 0) break; // terminal null
    offset++;

    const strEnd = msg.payload.indexOf(0, offset);
    if (strEnd === -1) break;

    const value = msg.payload.toString("utf8", offset, strEnd);
    offset = strEnd + 1;

    if (fieldType === 0x4d) {
      // 'M' = Message
      parts.unshift(value);
    } else if (fieldType === 0x44) {
      // 'D' = Detail
      parts.push(value);
    }
  }

  return parts.join(": ") || "unknown error";
}
