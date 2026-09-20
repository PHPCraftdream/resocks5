//! Recover the original hostname a client intended to reach, from the
//! first bytes it sends *after* the CONNECT tunnel is established.
//!
//! ## Why this exists
//!
//! Some SOCKS5 front-ends (e.g. Proxifier with local DNS resolution)
//! resolve the destination hostname on the client machine and send the
//! resulting **IP literal** in the SOCKS5 CONNECT request. When the
//! upstream proxy refuses CONNECT to raw IPs in certain CDN ranges
//! (a real, observed behaviour) every such request times out, even
//! though the same host succeeds when addressed by name.
//!
//! The original name is not recoverable from the IP — a single CDN
//! address fronts thousands of domains. But the client *re-states the
//! name it wants* in its very first application bytes:
//!
//! - **TLS** puts it in the ClientHello `server_name` (SNI) extension.
//! - **HTTP/1.x** puts it in the `Host:` request header.
//!
//! Reading that first record lets us address the upstream by domain
//! again, transparently, without trusting the client-supplied IP.
//!
//! Both parsers are strictly bounds-checked and allocation-light: they
//! never panic on malformed input, returning `None` instead.

use crate::connect::tls_records::{client_hello_might_continue, handshake_message};

/// Extract the SNI host from the TLS ClientHello record stream `data`.
///
/// `data` must start at the TLS record header (content-type byte). The
/// ClientHello may be split across several consecutive Handshake
/// records (RFC 8446 §5.1), so the handshake message is reassembled
/// across record boundaries before its fields are walked; a truncated
/// stream is parsed as far as the bytes present, and the parser gives
/// up mid-field (`None`) rather than guessing. Only the first
/// `server_name` of type `host_name` (RFC 6066) is returned, lowercased.
///
/// Returns `None` for: non-handshake records, non-ClientHello
/// handshakes, absent SNI extension, or any malformed/truncated field.
pub fn parse_sni(data: &[u8]) -> Option<String> {
    // TLS record header: type(1) version(2) length(2). We require a
    // Handshake record (0x16) and a legacy major version of 0x03.
    if data.len() < 5 || data[0] != 0x16 || data[1] != 0x03 {
        return None;
    }
    // Reassemble the handshake byte stream across record boundaries: a
    // second record's 5-byte header is framing, not handshake content.
    let message = handshake_message(data)?;
    // Handshake header: msg_type(1) length(3)
    if message.len() < 4 || message[0] != 0x01 {
        return None;
    }
    let hs_len = be_u24(&message[1..4]) as usize;
    let hs = message.get(4..4 + hs_len).unwrap_or(&message[4..]);

    // ClientHello body:
    //   client_version(2) random(32) session_id(<vec8>)
    //   cipher_suites(<vec16>) compression_methods(<vec8>)
    //   extensions(<vec16>)
    let mut p = 0usize;
    p = skip(hs, p, 2)?; // client_version
    p = skip(hs, p, 32)?; // random
    p = skip_vec(hs, p, 1)?; // session_id
    p = skip_vec(hs, p, 2)?; // cipher_suites
    p = skip_vec(hs, p, 1)?; // compression_methods

    // extensions: 2-byte total length, then a sequence of
    //   ext_type(2) ext_len(2) ext_data(ext_len)
    let ext_total = be_u16(hs.get(p..p + 2)?) as usize;
    p += 2;
    let ext_end = p.checked_add(ext_total)?;
    let extensions = hs.get(p..ext_end.min(hs.len()))?;

    let mut e = 0usize;
    while e + 4 <= extensions.len() {
        let ext_type = be_u16(&extensions[e..e + 2]);
        let ext_len = be_u16(&extensions[e + 2..e + 4]) as usize;
        let ext_data = extensions.get(e + 4..e + 4 + ext_len)?;
        if ext_type == 0x0000 {
            return parse_server_name_ext(ext_data);
        }
        e += 4 + ext_len;
    }
    None
}

/// Parse the `server_name` extension body (RFC 6066):
///   server_name_list(<vec16>) of entries: name_type(1) host_name(<vec16>)
fn parse_server_name_ext(data: &[u8]) -> Option<String> {
    let list_len = be_u16(data.get(0..2)?) as usize;
    let list = data.get(2..2 + list_len)?;
    let mut p = 0usize;
    while p + 3 <= list.len() {
        let name_type = list[p];
        let name_len = be_u16(&list[p + 1..p + 3]) as usize;
        let name = list.get(p + 3..p + 3 + name_len)?;
        if name_type == 0x00 {
            // host_name
            let s = std::str::from_utf8(name).ok()?;
            if s.is_empty() {
                return None;
            }
            return Some(s.to_ascii_lowercase());
        }
        p += 3 + name_len;
    }
    None
}

/// Extract the `Host` header value (without port) from an HTTP/1.x
/// request prefix. Case-insensitive header match; tolerates the request
/// being only partially present as long as the `Host:` line is complete.
///
/// Returns `None` if no complete `Host:` line is found in `data`.
pub fn parse_http_host(data: &[u8]) -> Option<String> {
    let (request, mut headers) = crlf_line(data)?;
    if !is_http1_request_line(request) {
        return None;
    }
    while let Some((line, rest)) = crlf_line(headers) {
        if line.is_empty() {
            break;
        }
        headers = rest;
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        if line[..colon].trim_ascii().eq_ignore_ascii_case(b"host") {
            let val = std::str::from_utf8(&line[colon + 1..]).ok()?.trim();
            if val.is_empty() {
                return None;
            }
            // Strip an optional :port. IPv6 literals in Host are
            // bracketed ([::1]:443); we don't recover those (they're
            // already IPs anyway), so a simple rsplit on ':' is safe
            // for the hostname case we care about.
            let host = match val.rsplit_once(':') {
                Some((h, port)) if !h.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => h,
                _ => val,
            };
            return Some(host.to_ascii_lowercase());
        }
    }
    None
}

fn crlf_line(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let end = data.windows(2).position(|bytes| bytes == b"\r\n")?;
    Some((&data[..end], &data[end + 2..]))
}

fn is_http1_request_line(line: &[u8]) -> bool {
    line.ends_with(b" HTTP/1.0") || line.ends_with(b" HTTP/1.1")
}

/// `true` if appending more bytes could still let [`parse_sni`] find an
/// SNI host in `data` — i.e. the prefix is consistent with the start of
/// a TLS ClientHello record that has not fully arrived yet. `false`
/// means further bytes cannot change the outcome: bytes already present
/// rule out a ClientHello record, or the handshake message announced
/// across the record headers is complete, so a `parse_sni` result of `None`
/// on such input is final.
///
/// This is the "keep reading?" counterpart of `parse_sni`, whose `None`
/// collapses *malformed* and *merely truncated* input. A single TCP
/// read frequently delivers only part of a ClientHello (modern hellos
/// with many extensions are routinely split across segments), so
/// callers accumulate bytes while this returns `true`, re-running
/// `parse_sni` after each read.
pub fn sni_might_still_appear(data: &[u8]) -> bool {
    client_hello_might_continue(data)
}

/// `true` if appending more bytes could still let [`parse_http_host`]
/// find a `Host:` header in `data` — the header section has not been
/// terminated yet, so a `Host:` line could still arrive. `false` means
/// further bytes are irrelevant: `data` cannot be the start of an
/// HTTP/1.x request (request-line methods begin with an alphabetic
/// byte), the request line is already
/// terminated and carries no HTTP version, or the header section is
/// terminated in a form `parse_http_host` cannot parse (bare LF), in
/// which case waiting would only stall until the caller's deadline.
pub fn http_host_might_still_appear(data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }
    // Request-line methods start with an ALPHA token; a TLS record,
    // binary protocol payload, etc. can never grow a Host header.
    if !data[0].is_ascii_alphabetic() {
        return false;
    }
    if data.iter().position(|&b| b == b'\n').is_some_and(|end| {
        end == 0 || data[end - 1] != b'\r' || !is_http1_request_line(&data[..end - 1])
    }) {
        return false;
    }
    // Header section still open: a complete or partial `Host:` line
    // could still arrive. Once the section is terminated — CRLF CRLF,
    // or bare LF — no further header line can parse.
    !(data.windows(4).any(|bytes| bytes == b"\r\n\r\n")
        || data.windows(2).any(|bytes| bytes == b"\n\n"))
}

#[inline]
fn be_u16(b: &[u8]) -> u16 {
    ((b[0] as u16) << 8) | b[1] as u16
}

#[inline]
fn be_u24(b: &[u8]) -> u32 {
    ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32
}

/// Advance `p` by `n`, returning `None` if that would run past `buf`.
#[inline]
fn skip(buf: &[u8], p: usize, n: usize) -> Option<usize> {
    let q = p.checked_add(n)?;
    if q <= buf.len() {
        Some(q)
    } else {
        None
    }
}

/// Skip a length-prefixed vector whose length field is `len_bytes`
/// (1 or 2) bytes wide, returning the offset just past the vector.
#[inline]
fn skip_vec(buf: &[u8], p: usize, len_bytes: usize) -> Option<usize> {
    let len = match len_bytes {
        1 => *buf.get(p)? as usize,
        2 => be_u16(buf.get(p..p + 2)?) as usize,
        _ => return None,
    };
    skip(buf, p + len_bytes, len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupted_handshake_cannot_gain_an_sni_by_appending_bytes() {
        let interruption = [0x17, 0x03, 0x03, 0, 1, 0];
        for end in 1..=interruption.len() {
            let mut data = vec![0x16, 0x03, 0x01, 0, 4, 1, 0, 0, 100];
            data.extend_from_slice(&interruption[..end]);
            assert_eq!(parse_sni(&data), None);
            assert!(!sni_might_still_appear(&data), "interruption prefix {end}");
            data.extend_from_slice(&client_hello_with_sni("too-late.example"));
            assert_eq!(parse_sni(&data), None);
            assert!(!sni_might_still_appear(&data));
        }
    }

    #[test]
    fn incomplete_host_value_never_selects_a_partial_destination() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let start = b"GET / HTTP/1.1\r\nHost: ".len();
        for end in start + 1..request.len() - 2 {
            assert_eq!(parse_http_host(&request[..end]), None, "cut at {end}");
        }
        assert_eq!(parse_http_host(request).as_deref(), Some("example.com"));
    }

    #[test]
    fn binary_body_does_not_hide_a_complete_host_header() {
        assert_eq!(
            parse_http_host(b"POST / HTTP/1.1\r\nHost: example.com\r\n\r\n\xff\xfe").as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn opaque_header_bytes_do_not_rule_out_a_later_host() {
        let partial = b"GET / HTTP/1.1\r\nX-Opaque: \xff\r\nHo";
        assert!(http_host_might_still_appear(partial));
        let mut complete = partial.to_vec();
        complete.extend_from_slice(b"st: example.com\r\n\r\n");
        assert_eq!(parse_http_host(&complete).as_deref(), Some("example.com"));
    }

    /// Build a minimal but well-formed TLS ClientHello carrying a single
    /// SNI host_name extension.
    fn client_hello_with_sni(host: &str) -> Vec<u8> {
        // server_name extension body
        let host_bytes = host.as_bytes();
        let mut sni_ext = Vec::new();
        // server_name_list length (entry = 1 + 2 + host)
        let entry_len = 1 + 2 + host_bytes.len();
        sni_ext.extend_from_slice(&(entry_len as u16).to_be_bytes());
        sni_ext.push(0x00); // name_type = host_name
        sni_ext.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(host_bytes);

        // extension: type 0x0000, len, body
        let mut exts = Vec::new();
        exts.extend_from_slice(&0x0000u16.to_be_bytes());
        exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni_ext);

        // ClientHello body
        let mut ch = Vec::new();
        ch.extend_from_slice(&[0x03, 0x03]); // client_version TLS1.2
        ch.extend_from_slice(&[0xAB; 32]); // random
        ch.push(0x00); // session_id length 0
        ch.extend_from_slice(&0x0002u16.to_be_bytes()); // cipher_suites len
        ch.extend_from_slice(&[0x13, 0x01]); // one cipher suite
        ch.push(0x01); // compression_methods len
        ch.push(0x00); // null compression
        ch.extend_from_slice(&(exts.len() as u16).to_be_bytes()); // extensions len
        ch.extend_from_slice(&exts);

        // Handshake header: type 0x01, 3-byte length
        let mut hs = Vec::new();
        hs.push(0x01);
        let l = ch.len();
        hs.push((l >> 16) as u8);
        hs.push((l >> 8) as u8);
        hs.push(l as u8);
        hs.extend_from_slice(&ch);

        // TLS record header: type 0x16, version 0x0301, length
        let mut rec = Vec::new();
        rec.push(0x16);
        rec.extend_from_slice(&[0x03, 0x01]);
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    /// Build the same ClientHello as `client_hello_with_sni` but with an
    /// empty extensions list — no SNI.
    fn client_hello_without_sni() -> Vec<u8> {
        // ClientHello with empty extensions.
        let mut ch = Vec::new();
        ch.extend_from_slice(&[0x03, 0x03]);
        ch.extend_from_slice(&[0xAB; 32]);
        ch.push(0x00);
        ch.extend_from_slice(&0x0002u16.to_be_bytes());
        ch.extend_from_slice(&[0x13, 0x01]);
        ch.push(0x01);
        ch.push(0x00);
        ch.extend_from_slice(&0x0000u16.to_be_bytes()); // extensions len = 0
        let mut hs = Vec::new();
        hs.push(0x01);
        let l = ch.len();
        hs.push((l >> 16) as u8);
        hs.push((l >> 8) as u8);
        hs.push(l as u8);
        hs.extend_from_slice(&ch);
        let mut rec = Vec::new();
        rec.push(0x16);
        rec.extend_from_slice(&[0x03, 0x01]);
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn extracts_sni_from_well_formed_hello() {
        let rec = client_hello_with_sni("registry.npmjs.org");
        assert_eq!(parse_sni(&rec).as_deref(), Some("registry.npmjs.org"));
    }

    #[test]
    fn sni_is_lowercased() {
        let rec = client_hello_with_sni("Registry.NPMJS.org");
        assert_eq!(parse_sni(&rec).as_deref(), Some("registry.npmjs.org"));
    }

    #[test]
    fn returns_none_for_non_handshake_record() {
        // ApplicationData record
        let data = [0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5];
        assert_eq!(parse_sni(&data), None);
    }

    #[test]
    fn returns_none_for_truncated_hello() {
        let rec = client_hello_with_sni("example.com");
        // Cut the record off mid-extensions.
        assert_eq!(parse_sni(&rec[..rec.len() - 5]), None);
    }

    #[test]
    fn returns_none_when_no_sni_extension() {
        let rec = client_hello_without_sni();
        assert_eq!(parse_sni(&rec), None);
    }

    #[test]
    fn does_not_panic_on_random_bytes() {
        // Fuzz-ish: many short prefixes of a valid hello plus garbage.
        let rec = client_hello_with_sni("a.example");
        for i in 0..rec.len() {
            let _ = parse_sni(&rec[..i]);
        }
        let _ = parse_sni(&[0x16, 0x03, 0x01, 0xFF, 0xFF]);
        let _ = parse_sni(&[0x16, 0x03]);
    }

    #[test]
    fn extracts_http_host_simple() {
        let req = b"GET / HTTP/1.1\r\nHost: registry.npmjs.org\r\n\r\n";
        assert_eq!(parse_http_host(req).as_deref(), Some("registry.npmjs.org"));
    }

    #[test]
    fn http_host_strips_port() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        assert_eq!(parse_http_host(req).as_deref(), Some("example.com"));
    }

    #[test]
    fn http_host_case_insensitive_header() {
        let req = b"GET / HTTP/1.1\r\nhOsT:  Example.COM \r\n\r\n";
        assert_eq!(parse_http_host(req).as_deref(), Some("example.com"));
    }

    #[test]
    fn http_host_absent() {
        let req = b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n";
        assert_eq!(parse_http_host(req), None);
    }

    #[test]
    fn http_host_incomplete_line_returns_none() {
        // Host line not yet terminated — we only act on complete lines.
        let req = b"GET / HTTP/1.1\r\nHost: registry.npmjs.or";
        assert_eq!(parse_http_host(req), None);
    }

    #[test]
    fn sni_five_byte_prefix_is_incomplete_not_absent() {
        // R21: a 5-byte first read — record header only, handshake-type
        // byte not yet arrived — is the case the single-read flow got
        // wrong: parse_sni must give up on it, but the caller must be told
        // to keep reading rather than fall back.
        let rec = client_hello_with_sni("example.com");
        let prefix = &rec[..5];
        assert_eq!(parse_sni(prefix), None);
        assert!(sni_might_still_appear(prefix));
    }

    #[test]
    fn sni_truncated_hello_is_incomplete() {
        let rec = client_hello_with_sni("example.com");
        let cut = &rec[..rec.len() - 5];
        assert_eq!(parse_sni(cut), None);
        assert!(sni_might_still_appear(cut));
    }

    #[test]
    fn sni_empty_prefix_is_incomplete() {
        assert!(sni_might_still_appear(&[]));
    }

    #[test]
    fn sni_complete_hello_is_decided() {
        let rec = client_hello_with_sni("example.com");
        assert!(!sni_might_still_appear(&rec));
        // A complete hello WITHOUT an SNI extension must also read as
        // decided — otherwise recovery stalls on SNI-less clients.
        let no_sni = client_hello_without_sni();
        assert!(!sni_might_still_appear(&no_sni));
    }

    #[test]
    fn sni_non_hello_prefixes_are_never_incomplete() {
        // ApplicationData record.
        assert!(!sni_might_still_appear(&[
            0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5
        ]));
        // Wrong legacy record version.
        assert!(!sni_might_still_appear(&[
            0x16, 0x02, 0x01, 0x00, 0x10, 0x01
        ]));
        // Handshake present, but not a ClientHello type.
        assert!(!sni_might_still_appear(&[
            0x16, 0x03, 0x99, 0x99, 0x99, 0xFF
        ]));
        // Plain HTTP request.
        assert!(!sni_might_still_appear(
            b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"
        ));
    }

    #[test]
    fn sni_probe_accumulation_finds_sni_under_any_segmentation() {
        // Model of the production accumulate loop: parse after every chunk;
        // whenever the probe says "decided" the parse must have found the
        // SNI (no decided-but-missed state may exist for a valid hello).
        let rec = client_hello_with_sni("sni.example");
        let mut accumulated: Vec<u8> = Vec::new();
        let mut found = false;
        for chunk in rec.chunks(3) {
            accumulated.extend_from_slice(chunk);
            if let Some(host) = parse_sni(&accumulated) {
                assert_eq!(host, "sni.example");
                found = true;
                break;
            }
            assert!(
                sni_might_still_appear(&accumulated),
                "probe gave up at {} of {} bytes",
                accumulated.len(),
                rec.len()
            );
        }
        assert!(found);
    }

    #[test]
    fn http_host_partial_request_is_incomplete() {
        let req = b"GET / HTTP/1.1\r\nHost: registry.npmjs.or";
        assert!(http_host_might_still_appear(req));
    }

    #[test]
    fn http_host_request_line_split_is_incomplete() {
        // Version suffix not yet arrived: the request line is open, so the
        // probe must not decide from a missing " HTTP/".
        assert!(http_host_might_still_appear(b"GET / HT"));
    }

    #[test]
    fn http_host_complete_header_is_decided() {
        assert!(!http_host_might_still_appear(
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        ));
        // Complete header section with no Host line at all — decided, so
        // recovery falls back to the IP instead of waiting for the deadline.
        assert!(!http_host_might_still_appear(
            b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n"
        ));
    }

    #[test]
    fn http_host_non_http_prefixes_are_never_incomplete() {
        // TLS record prefix.
        assert!(!http_host_might_still_appear(&[
            0x16, 0x03, 0x01, 0x00, 0x10, 0x01
        ]));
        // A server-greeting-style line: request line terminated without an
        // HTTP version — waiting for it would stall to the deadline.
        assert!(!http_host_might_still_appear(b"SSH-2.0-OpenSSH_9\r\n"));
        // Bare-LF request: parse_http_host reads CRLF lines only.
        assert!(!http_host_might_still_appear(b"GET /\nHost: a.example\n\n"));
        // Empty value on a terminated Host line.
        assert!(!http_host_might_still_appear(
            b"GET / HTTP/1.1\r\nHost:\r\n\r\n"
        ));
    }

    #[test]
    fn http_host_probe_accumulation_finds_host_under_any_segmentation() {
        let req: &[u8] = b"POST / HTTP/1.1\r\nHost: split.example\r\n\r\n";
        // Every segmentation visits a sequence of these prefixes.
        for end in 0..=req.len() {
            let prefix = &req[..end];
            if let Some(host) = parse_http_host(prefix) {
                assert_eq!(host, "split.example", "cut at {end}");
            } else {
                assert!(
                    http_host_might_still_appear(prefix),
                    "probe gave up at {end}"
                );
            }
        }
        // Once the request is complete the parsed host must be exact.
        assert_eq!(parse_http_host(req).as_deref(), Some("split.example"));
    }

    /// ClientHello handshake stream (msg_type + length + body) with a
    /// 32-byte session_id and an SNI host, plus byte ranges — inside the
    /// stream — of the session_id, the extensions block content, and the
    /// server_name value, so tests can drop a TLS record boundary
    /// strictly INSIDE a field rather than between fields.
    #[allow(clippy::type_complexity)] // (stream, session_id, ext_block, name) ranges
    fn hello_field_map(host: &str) -> (Vec<u8>, (usize, usize), (usize, usize), (usize, usize)) {
        let host = host.as_bytes();
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version
        body.extend_from_slice(&[0xAB; 32]); // random
        body.push(32); // session_id length
        let sid = (body.len(), body.len() + 32);
        body.resize(body.len() + 32, 0xAA);
        body.extend_from_slice(&0x0002u16.to_be_bytes()); // cipher_suites length
        body.extend_from_slice(&[0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]); // compression_methods
                                               // extensions block content:
                                               //   [ext_type 2][ext_len 2][list_len 2][name_type 1][name_len 2][name]
        let ext_body_len: u16 = (5 + host.len()) as u16; // list_len..name
        let ext_total: u16 = (4 + ext_body_len as usize) as u16;
        body.extend_from_slice(&ext_total.to_be_bytes()); // extensions total length
        let ext_block = (body.len(), body.len() + ext_total as usize);
        body.extend_from_slice(&0x0000u16.to_be_bytes()); // server_name ext type
        body.extend_from_slice(&ext_body_len.to_be_bytes());
        body.extend_from_slice(&((3 + host.len()) as u16).to_be_bytes()); // list_len
        body.push(0x00); // name_type = host_name
        body.extend_from_slice(&(host.len() as u16).to_be_bytes());
        let name = (body.len(), body.len() + host.len());
        body.extend_from_slice(host);
        let mut stream = vec![0x01]; // msg_type = ClientHello
        let l = body.len();
        stream.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        stream.extend_from_slice(&body);
        (stream, sid, ext_block, name)
    }

    /// Wrap one handshake message into TWO consecutive Handshake TLS
    /// records whose boundary sits at `split` — a mid-field offset of
    /// the caller's choosing.
    fn two_record_hello(stream: &[u8], split: usize) -> Vec<u8> {
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(split as u16).to_be_bytes());
        rec.extend_from_slice(&stream[..split]);
        rec.extend_from_slice(&[0x16, 0x03, 0x01]);
        rec.extend_from_slice(&((stream.len() - split) as u16).to_be_bytes());
        rec.extend_from_slice(&stream[split..]);
        rec
    }

    #[test]
    fn parse_sni_reassembles_hello_split_inside_session_id() {
        let (stream, sid, _, _) = hello_field_map("split.example");
        let split = (sid.0 + sid.1) / 2;
        assert!(split > sid.0 && split < sid.1);
        assert_eq!(
            parse_sni(&two_record_hello(&stream, split)).as_deref(),
            Some("split.example")
        );
    }

    #[test]
    fn parse_sni_reassembles_hello_split_inside_extensions() {
        let (stream, _, exts, name) = hello_field_map("split.example");
        // Strictly inside the server_name_list length field: not on any
        // field boundary, not inside the host name itself.
        let split = exts.0 + 5;
        assert!(split > exts.0 && split < exts.1 && split < name.0);
        assert_eq!(
            parse_sni(&two_record_hello(&stream, split)).as_deref(),
            Some("split.example")
        );
    }

    #[test]
    fn parse_sni_reassembles_hello_split_inside_server_name_value() {
        let (stream, _, _, name) = hello_field_map("fragmented.example.net");
        let split = (name.0 + name.1) / 2;
        assert!(split > name.0 && split < name.1);
        assert_eq!(
            parse_sni(&two_record_hello(&stream, split)).as_deref(),
            Some("fragmented.example.net")
        );
    }

    #[test]
    fn sni_probe_accounts_for_record_boundaries() {
        // One byte short of the declared message length — but the
        // missing byte sits behind the second record's header. The
        // probe must still say "keep reading": the shortfall is
        // payload, not framing.
        let (stream, _, _, _) = hello_field_map("split.example");
        let split = stream.len() - 1;
        let full = two_record_hello(&stream, split);
        let header_plus = &full[..5 + split + 5];
        assert_eq!(parse_sni(header_plus), None);
        assert!(sni_might_still_appear(header_plus));
        assert!(!sni_might_still_appear(&full));
        assert_eq!(parse_sni(&full).as_deref(), Some("split.example"));
    }
}
