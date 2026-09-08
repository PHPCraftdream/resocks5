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

use std::{borrow::Cow, ops::Range};

/// Content type of a TLS Handshake record.
const HANDSHAKE: u8 = 0x16;

/// The first handshake message of a record stream, reassembled from the
/// payloads of consecutive Handshake-type records.
pub struct AssembledHandshake {
    /// The message bytes: `msg_type(1) + length(3) + body`, contiguous.
    /// Clipped to the bytes actually present when the stream is
    /// truncated, so callers parse the same prefix they would have
    /// before record-layer reassembly existed.
    /// Bytes from later handshake messages are excluded.
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
/// type ends the handshake stream. Returns `None` if the first record
/// header is incomplete or its type is not Handshake.
pub fn assemble_handshake_message(data: &[u8]) -> Option<AssembledHandshake> {
    let prefix = handshake_prefix(data)?;
    Some(AssembledHandshake {
        message: message_bytes(data, prefix.len).into_owned(),
        complete: prefix.complete,
    })
}

/// `true` when the ClientHello at the start of `data` is fully
/// assembled: enough bytes have arrived, across however many TLS
/// records carried them, to satisfy the handshake header's declared
/// length. Callers are expected to have classified `data` as a
/// ClientHello already; a non-ClientHello message is never complete.
pub fn client_hello_is_complete(data: &[u8]) -> bool {
    handshake_prefix(data).is_some_and(|prefix| prefix.complete && prefix.kind == Some(0x01))
}

pub(super) fn client_hello_might_continue(data: &[u8]) -> bool {
    if data.first().is_some_and(|&kind| kind != HANDSHAKE)
        || data.get(1).is_some_and(|&major| major != 0x03)
    {
        return false;
    }
    match handshake_prefix(data) {
        Some(prefix) => {
            prefix.kind.is_none_or(|kind| kind == 0x01) && !prefix.complete && prefix.extendable
        }
        None => data.len() < 5,
    }
}

pub(super) fn handshake_message(data: &[u8]) -> Option<Cow<'_, [u8]>> {
    let prefix = handshake_prefix(data)?;
    Some(message_bytes(data, prefix.len))
}

struct HandshakePrefix {
    len: usize,
    kind: Option<u8>,
    complete: bool,
    extendable: bool,
}

fn handshake_prefix(data: &[u8]) -> Option<HandshakePrefix> {
    let mut records = walk_records(data);
    let first = records.next()?;
    if first.content_type != HANDSHAKE {
        return None;
    }
    let mut prefix = HandshakePrefix {
        len: 0,
        kind: None,
        complete: false,
        extendable: true,
    };
    let mut header = [0; 4];
    let mut header_len = 0;
    let mut next_header = first.payload.end;
    for record in std::iter::once(first).chain(records) {
        if record.content_type != HANDSHAKE {
            prefix.extendable = false;
            break;
        }
        next_header = record.payload.end;
        let payload = &data[record.payload];
        let n = payload.len().min(header.len() - header_len);
        header[header_len..header_len + n].copy_from_slice(&payload[..n]);
        header_len += n;
        prefix.len += payload.len();
        if header_len != 0 {
            prefix.kind = Some(header[0]);
        }
        if header_len == header.len() {
            let declared = 4 + be_u24(&header[1..]) as usize;
            if prefix.len >= declared {
                prefix.len = declared;
                prefix.complete = true;
                break;
            }
        }
    }
    if data.get(next_header).is_some_and(|&kind| kind != HANDSHAKE) {
        prefix.extendable = false;
    }
    Some(prefix)
}

fn message_bytes(data: &[u8], len: usize) -> Cow<'_, [u8]> {
    let mut records = walk_records(data);
    let first = records
        .next()
        .expect("handshake_prefix checked the first record");
    if len <= first.payload.len() {
        return Cow::Borrowed(&data[first.payload.start..first.payload.start + len]);
    }
    let mut message = Vec::with_capacity(len);
    for record in std::iter::once(first).chain(records) {
        let n = record.payload.len().min(len - message.len());
        message.extend_from_slice(&data[record.payload.start..record.payload.start + n]);
        if message.len() == len {
            break;
        }
    }
    Cow::Owned(message)
}

/// One record parsed from a TLS record-layer stream.
struct TlsRecord {
    content_type: u8,
    /// Byte range of the record's payload within the walked buffer. The
    /// final record's range is clipped to the bytes actually present
    /// when the buffer ends inside its declared payload.
    payload: Range<usize>,
}

/// Walk complete record headers lazily, clipping a truncated final payload.
fn walk_records(data: &[u8]) -> impl Iterator<Item = TlsRecord> + '_ {
    let mut pos = 0usize;
    std::iter::from_fn(move || {
        let payload_start = pos.checked_add(5)?;
        let header = data.get(pos..payload_start)?;
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let payload_end = payload_start.checked_add(len)?.min(data.len());
        pos = payload_end;
        Some(TlsRecord {
            content_type: header[0],
            payload: payload_start..payload_end,
        })
    })
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
        let records: Vec<_> = walk_records(&data).collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].content_type, 0x16);
        assert_eq!(&data[records[0].payload.clone()], &[0xAA, 0xBB]);
        assert_eq!(records[1].content_type, 0x17);
        assert_eq!(&data[records[1].payload.clone()], &[0xCC]);
    }

    #[test]
    fn truncated_payload_is_clipped() {
        let data = [0x16u8, 0x03, 0x01, 0x00, 0x05, 0xAA, 0xBB];
        let records: Vec<_> = walk_records(&data).collect();
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
    fn assembly_stops_at_the_first_message_boundary() {
        let message = [0x01, 0, 0, 3, 0xAA, 0xBB, 0xCC];
        for split in 1..=message.len() {
            let mut data = one_record(HANDSHAKE, &message[..split]);
            let mut tail = message[split..].to_vec();
            tail.extend_from_slice(&[0x02, 0, 0, 1, 0xDD]);
            data.extend_from_slice(&one_record(HANDSHAKE, &tail));
            let assembled = assemble_handshake_message(&data).unwrap();
            assert_eq!(assembled.message, message, "split at {split}");
            assert!(assembled.complete);
            assert!(client_hello_is_complete(&data));
        }
        let data = one_record(HANDSHAKE, &[0x01, 0, 0, 0, 0x02, 0, 0, 0]);
        assert_eq!(
            assemble_handshake_message(&data).unwrap().message,
            [1, 0, 0, 0]
        );
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
