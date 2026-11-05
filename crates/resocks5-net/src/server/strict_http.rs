//! Opt-in strict RFC 9112 validation for the already-split HTTP CONNECT pieces.

/// A strict-mode violation found by [`validate`].
pub(crate) enum StrictViolation {
    /// Answer 400 with this fixed reason text.
    Bad(&'static str),
    /// Answer 505: well-formed HTTP-version that is not 1.0 or 1.1.
    Unsupported,
}

fn bad(reason: &'static str) -> StrictViolation {
    StrictViolation::Bad(reason)
}

fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// Authority-host bytes: RFC 3986 unreserved + sub-delims; `%XX` escapes are
/// checked separately. Dotted quads need no extra range check here.
fn is_authority_host_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=".contains(&byte)
}

/// True when every byte is an authority-host byte and every `%` opens a
/// two-hex-digit escape.
fn valid_authority_host(host: &str) -> bool {
    let bytes = host.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let Some(hex) = bytes.get(i + 1..i + 3) else {
                return false;
            };
            if !hex.iter().all(|b| b.is_ascii_hexdigit()) {
                return false;
            }
            i += 3;
        } else {
            if !is_authority_host_byte(bytes[i]) {
                return false;
            }
            i += 1;
        }
    }
    true
}

/// Validate the already-split HTTP CONNECT request against RFC 9112.
///
/// `request_line` is the request line text; `headers` are the raw header
/// lines without their CRLF terminators. The method is NOT checked here —
/// the caller keeps its existing 501 path. Each violation carries a fixed
/// reason (never echoing request data).
pub(crate) fn validate(request_line: &str, headers: &[&[u8]]) -> Result<(), StrictViolation> {
    let parts: Vec<&str> = request_line.split(' ').collect();
    if parts.len() != 3
        || parts
            .iter()
            .any(|part| part.is_empty() || part.bytes().any(|b| b == b'\t' || b.is_ascii_control()))
    {
        return Err(bad("strict HTTP: malformed request line"));
    }

    let version = parts[2];
    let v = version.as_bytes();
    if v.len() != 8
        || !version.starts_with("HTTP/")
        || !v[5].is_ascii_digit()
        || v[6] != b'.'
        || !v[7].is_ascii_digit()
    {
        return Err(bad("strict HTTP: malformed HTTP-version"));
    }
    if version != "HTTP/1.0" && version != "HTTP/1.1" {
        return Err(StrictViolation::Unsupported);
    }

    let target = parts[1];
    let port_text: &str;
    if let Some(rest) = target.strip_prefix('[') {
        let Some((inside, after)) = rest.split_once(']') else {
            return Err(bad("strict HTTP: bare IPv6 authority"));
        };
        if inside.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(bad(
                "strict HTTP: bracketed authority is not an IPv6 address",
            ));
        }
        let Some(port) = after.strip_prefix(':') else {
            return Err(bad("strict HTTP: authority is missing a port"));
        };
        port_text = port;
    } else {
        let Some((h, port)) = target.rsplit_once(':') else {
            return Err(bad("strict HTTP: authority is missing a port"));
        };
        if h.is_empty() {
            return Err(bad("strict HTTP: authority host is empty"));
        }
        if h.contains(':') {
            return Err(bad("strict HTTP: bare IPv6 authority"));
        }
        // CONNECT authorities carry no path, userinfo, query, or fragment.
        if !valid_authority_host(h) {
            return Err(bad("strict HTTP: invalid authority host"));
        }
        port_text = port;
    }
    if port_text.is_empty() || port_text.len() > 5 || !port_text.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(bad("strict HTTP: invalid authority port"));
    }
    let Ok(port) = port_text.parse::<u32>() else {
        return Err(bad("strict HTTP: invalid authority port"));
    };
    if !(1..=65535).contains(&port) {
        return Err(bad("strict HTTP: invalid authority port"));
    }

    let mut host_count = 0usize;
    let mut host_value_empty = false;
    let mut proxy_auth_count = 0usize;
    for line in headers {
        if line.first() == Some(&b' ') || line.first() == Some(&b'\t') {
            return Err(bad("strict HTTP: obsolete line folding"));
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            return Err(bad("strict HTTP: header line is missing a colon"));
        };
        let name = &line[..colon];
        let value = &line[colon + 1..];
        if name.is_empty() {
            return Err(bad("strict HTTP: empty header field name"));
        }
        // RFC 9112 section 5.1: only whitespace between the name and the colon
        // has its own rejection; whitespace inside a name is an invalid token.
        if matches!(name.last(), Some(b' ' | b'\t')) {
            return Err(bad("strict HTTP: whitespace before header colon"));
        }
        if !name.iter().all(|&b| is_tchar(b)) {
            return Err(bad("strict HTTP: invalid header field name"));
        }
        // RFC 9112 field values: CTL bytes are invalid; HTAB and SP are the
        // only bytes below 0x20 because CRLF never reaches this validator.
        if value.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7F) {
            return Err(bad("strict HTTP: invalid header field value"));
        }
        let lower = name.to_ascii_lowercase();
        match lower.as_slice() {
            b"host" => {
                host_count += 1;
                host_value_empty = value.trim_ascii().is_empty();
            }
            b"proxy-authorization" => proxy_auth_count += 1,
            _ => {}
        }
    }

    if version == "HTTP/1.1" && host_count == 0 {
        return Err(bad("strict HTTP: missing Host header"));
    }
    if host_count > 1 {
        return Err(bad("strict HTTP: duplicate Host header"));
    }
    if host_value_empty {
        return Err(bad("strict HTTP: empty Host header"));
    }
    if proxy_auth_count > 1 {
        return Err(bad("strict HTTP: duplicate Proxy-Authorization header"));
    }

    Ok(())
}
