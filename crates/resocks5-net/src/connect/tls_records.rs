//! TLS record-layer walking shared by SNI recovery and ClientHello
//! fragmentation.
//!
//! A TLS record is `type(1) + legacy_version(2) + length(2) + payload`.
//! RFC 8446 §5.1 permits a single handshake message to be split across
//! several *consecutive* Handshake-type records: the message bytes are
//! the logical concatenation of those records' payloads, so a record
//! header sitting mid-message is transport framing, not handshake
//! content. Everything here is bounds-checked and never panics on
//! malformed input.

use std::ops::Range;

/// Content type of a TLS Handshake record.
const HANDSHAKE: u8 = 0x16;

/// The first handshake message of a record stream, reassembled from the
/// payloads of consecutive Handshake-type records.
pub struct AssembledHandshake {
    /// The message bytes: `msg_type(1) + length(3) + body`, contiguous.
    /// Clipped to the bytes actually present when the stream is
    /// truncated, so callers parse the same prefix they would have
    /// before record-layer reassembly existed.
    pub message: Vec<u8>,
    /// `true` when the message length declared in the handshake header
    /// is fully present — the whole message has arrived, across however
    /// many records carried it.
    pub complete: bool,
}

/// Assemble the first handshake message from the TLS record stream at
/// `data`, which must start at a record header.
///
/// Consecutive Handshake-type records are concatenated until the
/// handshake header's declared length is satisfied; any other record
/// type ends the handshake stream. Returns `None` only when `data`
/// holds less than one complete record header.
pub fn assemble_handshake_message(data: &[u8]) -> Option<AssembledHandshake> {
    let records = walk_records(data);
    match records.first() {
        Some(first) if first.content_type == HANDSHAKE => {}
        _ => return None,
    }
    let mut message = Vec::new();
    let mut complete = false;
    for record in records {
        let TlsRecord {
            content_type,
            payload,
        } = record;
        if content_type != HANDSHAKE {
            break; // the handshake stream is interrupted
        }
        message.extend_from_slice(&data[payload]);
        if message.len() >= 4 {
            let declared = 4 + be_u24(&message[1..4]) as usize;
            if message.len() >= declared {
                complete = true;
                break;
            }
        }
    }
    Some(AssembledHandshake { message, complete })
}

/// `true` when the ClientHello at the start of `data` is fully
/// assembled: enough bytes have arrived, across however many TLS
/// records carried them, to satisfy the handshake header's declared
/// length. Callers are expected to have classified `data` as a
/// ClientHello already; a non-ClientHello message is never complete.
pub fn client_hello_is_complete(data: &[u8]) -> bool {
    match assemble_handshake_message(data) {
        Some(assembled) => assembled.complete && assembled.message.first() == Some(&0x01),
        None => false,
    }
}

/// One record parsed from a TLS record-layer stream.
struct TlsRecord {
    content_type: u8,
    /// Byte range of the record's payload within the walked buffer. The
    /// final record's range is clipped to the bytes actually present
    /// when the buffer ends inside its declared payload.
    payload: Range<usize>,
}

/// Parse consecutive TLS records from `data`, which must start at a
/// record header. A trailing partial record — fewer than five header
/// bytes left, or a declared length exceeding the bytes present — is
/// included with its payload clipped to what is actually there.
fn walk_records(data: &[u8]) -> Vec<TlsRecord> {
    let mut records = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let Some(header) = data.get(pos..pos + 5) else {
            break; // partial record header at the tail
        };
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let Some(payload_end) = (pos + 5).checked_add(len) else {
            break; // unreachable for in-memory buffers; refuse rather than wrap
        };
        let payload_end = payload_end.min(data.len());
        records.push(TlsRecord {
            content_type: header[0],
            payload: pos + 5..payload_end,
        });
        pos = payload_end;
    }
    records
}

#[inline]
fn be_u24(b: &[u8]) -> u32 {
    ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut rec = vec![content_type, 0x03, 0x01];
        rec.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        rec.extend_from_slice(payload);
        rec
    }

    #[test]
    fn walks_consecutive_records() {
        let data = [
            0x16u8, 0x03, 0x01, 0x00, 0x02, 0xAA, 0xBB, 0x17, 0x03, 0x03, 0x00, 0x01, 0xCC,
        ];
        let records = walk_records(&data);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].content_type, 0x16);
        assert_eq!(&data[records[0].payload.clone()], &[0xAA, 0xBB]);
        assert_eq!(records[1].content_type, 0x17);
        assert_eq!(&data[records[1].payload.clone()], &[0xCC]);
    }

    #[test]
    fn truncated_payload_is_clipped() {
        let data = [0x16u8, 0x03, 0x01, 0x00, 0x05, 0xAA, 0xBB];
        let records = walk_records(&data);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].payload.len(), 2);
    }

    #[test]
    fn assembles_message_across_two_handshake_records() {
        let mut data = one_record(0x16, &[0x01, 0x00, 0x00, 0x03, 0xAA]);
        data.extend_from_slice(&one_record(0x16, &[0xBB, 0xCC]));
        let assembled = assemble_handshake_message(&data).unwrap();
        assert_eq!(
            assembled.message,
            [0x01, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC]
        );
        assert!(assembled.complete);
    }

    #[test]
    fn non_handshake_record_interrupts_the_message() {
        let mut data = one_record(0x16, &[0x01, 0x00, 0x00, 0x03, 0xAA]);
        data.extend_from_slice(&one_record(0x17, &[0xBB, 0xCC]));
        let assembled = assemble_handshake_message(&data).unwrap();
        assert_eq!(assembled.message, [0x01, 0x00, 0x00, 0x03, 0xAA]);
        assert!(!assembled.complete);
    }

    #[test]
    fn no_first_record_is_none() {
        assert!(assemble_handshake_message(&[]).is_none());
        assert!(assemble_handshake_message(&[0x16, 0x03]).is_none());
    }

    #[test]
    fn empty_first_record_is_incomplete() {
        let mut data = one_record(0x16, &[]);
        data.extend_from_slice(&one_record(0x16, &[0x01, 0x00, 0x00, 0x00]));
        let assembled = assemble_handshake_message(&data).unwrap();
        assert!(assembled.complete);
        assert_eq!(assembled.message, [0x01, 0x00, 0x00, 0x00]);
    }
}
