//! Compilation and validation of `allowed_clients` rules.
//!
//! A rule string is comma-separated elements (OR):
//! - exact IP (`1.2.3.4`, `::1`, `2001:db8::1`; the mapped form
//!   `::ffff:a.b.c.d` is normalized to IPv4);
//! - the `loopback` keyword — `127.0.0.0/8` and `::1`;
//! - a mask with `*`: `*` replaces exactly one octet (IPv4, exactly 4
//!   octets) or exactly one hex group (IPv6). `::` is a single
//!   compression and means ONLY zero groups: `2001:db8::*` =
//!   `2001:db8:0:0:0:0:0:*`, not /64 and not /32. Without `::` —
//!   exactly 8 explicit groups; with `::` — strictly fewer than 8.
//!
//! Rejected (fail-closed): hostnames, CIDR, ports, partial stars
//! (`1*.2.3.4`, `1*x`), zones `%eth0`, brackets `[::1]`, extra `:`
//! (`:::`), groups longer than 4 hex digits, leading zeros of IPv4
//! octets (`01.2.3.4`), empty strings and empty elements (`a,,b`).
//! Any bad element rejects the whole string, even with `*` present.
//!
//! Comparison: the peer is normalized mapped→IPv4. IPv4 compared
//! against an IPv6 mask is treated as `::ffff:a.b.c.d`;
//! IPv4-compatible (`::a.b.c.d` without ffff) is not normalized.

use std::net::{IpAddr, Ipv6Addr};

use anyhow::{bail, Context, Result};

/// Compiled `allowed_clients` rule: `matches` answers whether an IP is
/// allowed. Empty rules are impossible — compilation rejects them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AllowedClients {
    allow_all: bool,
    rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Rule {
    Exact(IpAddr),
    Loopback,
    Mask(Mask),
}

/// Mask: `None` = wildcard group, `Some(v)` = fixed value.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Mask {
    V4([Option<u8>; 4]),
    V6([Option<u16>; 8]),
}

/// Compile a rule string. Fail-closed: any invalid element
/// rejects the whole string.
pub(crate) fn compile_allowed_clients(spec: &str) -> Result<AllowedClients> {
    let mut rules = Vec::new();
    let mut allow_all = false;
    for raw in spec.split(',') {
        let elem = raw.trim();
        if elem.is_empty() {
            bail!("allowed_clients: пустой элемент в правиле {:?}", spec);
        }
        if elem == "*" {
            allow_all = true;
            continue;
        }
        rules.push(parse_element(elem).with_context(|| {
            format!(
                "allowed_clients: некорректный элемент {:?} в правиле {:?}",
                elem, spec
            )
        })?);
    }
    if rules.is_empty() && !allow_all {
        bail!("allowed_clients: пустая строка правила");
    }
    Ok(AllowedClients { allow_all, rules })
}

impl AllowedClients {
    pub(crate) fn matches(&self, ip: IpAddr) -> bool {
        let ip = normalize_mapped(ip);
        if self.allow_all {
            return true;
        }
        self.rules.iter().any(|r| rule_matches(r, ip))
    }
}

/// IPv4-mapped IPv6 (::ffff:a.b.c.d) → IPv4; other addresses unchanged.
fn normalize_mapped(ip: IpAddr) -> IpAddr {
    if let IpAddr::V6(v6) = ip {
        if let Some(v4) = v6.to_ipv4_mapped() {
            return IpAddr::V4(v4);
        }
    }
    ip
}

fn rule_matches(rule: &Rule, ip: IpAddr) -> bool {
    match rule {
        Rule::Exact(exact) => *exact == ip,
        Rule::Loopback => match ip {
            IpAddr::V4(v4) => v4.is_loopback(),
            IpAddr::V6(v6) => v6.is_loopback(),
        },
        Rule::Mask(Mask::V4(segs)) => match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                segs.iter()
                    .zip(octets.iter())
                    .all(|(s, o)| s.is_none_or(|v| v == *o))
            }
            IpAddr::V6(_) => false,
        },
        Rule::Mask(Mask::V6(segs)) => {
            // IPv4 compared as ::ffff:a.b.c.d; IPv4-compatible untouched.
            let segs6: [u16; 8] = match ip {
                IpAddr::V6(v6) => v6.segments(),
                IpAddr::V4(v4) => v4.to_ipv6_mapped().segments(),
            };
            segs.iter()
                .zip(segs6.iter())
                .all(|(s, o)| s.is_none_or(|v| v == *o))
        }
    }
}

fn parse_element(elem: &str) -> Result<Rule> {
    if elem.eq_ignore_ascii_case("loopback") {
        return Ok(Rule::Loopback);
    }
    if elem.contains(':') {
        parse_v6(elem)
    } else if elem.contains('.') {
        parse_v4(elem)
    } else {
        bail!("не IP-адрес и не ключевое слово");
    }
}

fn parse_v4(elem: &str) -> Result<Rule> {
    // Exact address (no '*') — std's single canon, including the ban on
    // leading zeros ("01.2.3.4" → Err).
    if !elem.contains('*') {
        let ip: IpAddr = elem
            .parse()
            .map_err(|_| anyhow::anyhow!("некорректный IPv4-адрес"))?;
        return Ok(Rule::Exact(ip));
    }
    let parts: Vec<&str> = elem.split('.').collect();
    if parts.len() != 4 {
        bail!("IPv4-маска требует ровно 4 октета");
    }
    let mut out = [None; 4];
    for (i, p) in parts.iter().enumerate() {
        if *p == "*" {
            continue;
        }
        if p.contains('*') || p.is_empty() || !p.chars().all(|c| c.is_ascii_digit()) {
            bail!("некорректный октет {:?}", p);
        }
        if p.len() > 1 && p.starts_with('0') {
            bail!("ведущие нули в октете {:?} не допускаются", p);
        }
        let v: u8 = p
            .parse()
            .map_err(|_| anyhow::anyhow!("некорректный октет {:?}", p))?;
        out[i] = Some(v);
    }
    Ok(Rule::Mask(Mask::V4(out)))
}

fn parse_v6(elem: &str) -> Result<Rule> {
    if elem.contains('%') {
        bail!("IPv6-зоны не поддерживаются");
    }
    if elem.starts_with('[') || elem.ends_with(']') {
        bail!("скобки не поддерживаются");
    }
    // Exact address without '*' — parse via std (compression, hex case
    // are canonical).
    if !elem.contains('*') {
        let v6: Ipv6Addr = elem
            .parse()
            .map_err(|_| anyhow::anyhow!("некорректный IPv6-адрес"))?;
        let ip = normalize_mapped(IpAddr::V6(v6));
        return Ok(Rule::Exact(ip));
    }

    // Exactly one '::' — otherwise ambiguous.
    if elem.match_indices("::").count() > 1 {
        bail!("более одного '::'");
    }
    if elem.contains(":::") {
        bail!("лишние ':'");
    }

    let (head_str, tail_str) = match elem.split_once("::") {
        Some((h, t)) => (h, t),
        None => (elem, ""),
    };
    let head: Vec<&str> = if head_str.is_empty() {
        Vec::new()
    } else {
        head_str.split(':').collect()
    };
    let tail: Vec<&str> = if tail_str.is_empty() {
        Vec::new()
    } else {
        tail_str.split(':').collect()
    };
    if head.iter().any(|g| g.is_empty()) || tail.iter().any(|g| g.is_empty()) {
        bail!("лишние ':'");
    }

    let explicit = head.len() + tail.len();
    if explicit > 8 {
        // Rejected BEFORE subtraction — otherwise underflow/panic.
        bail!("слишком много групп");
    }
    match elem.split_once("::") {
        // With '::' there are strictly fewer than 8 explicit groups; the
        // compressed groups are zeros, '*' fills NOTHING (no "star fills
        // compression" semantics).
        Some(_) => {
            if explicit == 8 {
                bail!("'::' при 8 явных группах");
            }
            let mut full: Vec<&str> = Vec::with_capacity(8);
            full.extend(head);
            // Compressed '::' groups are zeros (see comment above).
            full.extend(std::iter::repeat_n("0", 8 - explicit));
            full.extend(tail);
            Ok(Rule::Mask(Mask::V6(finish_v6_groups(&full)?)))
        }
        // Without '::' — exactly 8 explicit groups, '*' allowed in each.
        None => {
            if explicit != 8 {
                bail!("IPv6-маска без '::' требует ровно 8 групп");
            }
            Ok(Rule::Mask(Mask::V6(finish_v6_groups(&head)?)))
        }
    }
}

fn finish_v6_groups(groups: &[&str]) -> Result<[Option<u16>; 8]> {
    let mut out = [None; 8];
    for (i, g) in groups.iter().enumerate() {
        if *g == "*" {
            continue;
        }
        if g.contains('*') || g.is_empty() {
            bail!("некорректная группа {:?}", g);
        }
        if !g.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("лишние символы в группе {:?}", g);
        }
        // hex group: 1..4 digits ("00000" — 5 digits — rejected explicitly).
        if g.len() > 4 {
            bail!("группа {:?} длиннее 4 hex-цифр", g);
        }
        let v = u16::from_str_radix(g, 16)
            .map_err(|_| anyhow::anyhow!("некорректная hex-группа {:?}", g))?;
        out[i] = Some(v);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(spec: &str) -> AllowedClients {
        compile_allowed_clients(spec).unwrap_or_else(|e| panic!("{spec}: {e}"))
    }
    fn err(spec: &str) {
        assert!(
            compile_allowed_clients(spec).is_err(),
            "ожидалась ошибка для {spec:?}"
        );
    }
    fn m(spec: &str, ip: &str) -> bool {
        ok(spec).matches(ip.parse().unwrap())
    }

    // ─── parser: supported forms ─────────────────────────────────

    #[test]
    fn exact_addresses_parse() {
        ok("1.2.3.4");
        ok("::1");
        ok("2001:db8::1");
        ok("2001:0db8:0000::1");
        ok("*");
        ok("loopback");
        ok("10.*.0.1");
        ok("2001:db8::*");
        ok("2001:db8:*::1");
        ok("2001:db8:1:*::5");
        ok("*,loopback");
    }

    #[test]
    fn rejected_forms() {
        err(""); // empty string
        err("a,,b"); // empty element
        err(" "); // whitespace only
        err("example.com"); // hostname
        err("10.0.0.0/8"); // CIDR
        err("1.2.3.4:80"); // port
        err("1*.2.3.4"); // partial star
        err("1*x"); // junk next to the star
        err("10.1.*"); // not 4 octets
        err("10.*.*"); // not 4 octets
        err("::1%eth0"); // zone
        err("[::1]"); // brackets
        err(":::"); // extra ':'
        err("1:2"); // too few groups without '::'
        err("1.2.3"); // too few octets
        err("1.2.3.4.5"); // too many octets
        err("256.1.1.1"); // octet out of range
        err("01.2.3.4"); // leading zeros
        err("2001:db8::*::*"); // two '::'
        err("2001:db8:00000::*"); // group longer than 4 hex digits
        err("2001:db8::1*x"); // junk next to '*' in IPv6
    }

    #[test]
    fn too_many_groups_rejected() {
        // 9 explicit groups without '::'
        err("1:2:3:4:5:6:7:8:9");
        // 9 explicit groups with '::'
        err("::1:2:3:4:5:6:7:8:9");
        err("1:2:3:4:5:6:7:8::9");
        // 8 explicit groups + '::'
        err("1:2:3:4:5:6:7:8::");
        err("::1:2:3:4:5:6:7:8");
        err("2001:db8::1:2:3:4:5:6:7:8");
    }

    #[test]
    fn wildcard_group_count_negatives() {
        // '*' does not bypass group count/ban rules: with '::' and without.
        err("1:2:3:4:5:6:7:8:*"); // 9 explicit groups without '::'
        err("1:2:3:4:5:6:7:*::"); // 8 explicit groups + '::'
        err("::1:2:3:4:5:6:7:8:*"); // 9 explicit groups + '::'
        err("2001:db8:*"); // 3 groups without '::' — '*' does not expand to 8
        err("01.*.2.3"); // leading zeros of an octet, also under '*'
        err("2001:::*"); // ':::' — extra ':'
    }

    #[test]
    fn star_does_not_hide_bad_element() {
        err("*,example.com");
        err("*,1*.2.3.4");
        err("1.2.3.4,,*");
    }

    #[test]
    fn equivalent_v6_spellings_parse_identically() {
        assert_eq!(
            ok("2001:db8::1"),
            ok("2001:0db8:0000:0000:0000:0000:0000:0001")
        );
    }

    #[test]
    fn mapped_exact_rules_are_normalized() {
        // '::ffff:127.0.0.1' and '127.0.0.1' are the same Exact.
        assert_eq!(ok("::ffff:127.0.0.1"), ok("127.0.0.1"));
        assert_eq!(ok("::ffff:10.0.0.1"), ok("10.0.0.1"));
    }

    // ─── matcher ────────────────────────────────────────────────────

    #[test]
    fn exact_match_is_numeric() {
        assert!(m("1.2.3.4", "1.2.3.4"));
        assert!(!m("1.2.3.4", "1.2.3.5"));
        assert!(m("2001:db8::1", "2001:0db8:0000::1"));
        assert!(!m("2001:db8::1", "2001:db8::2"));
        assert!(!m("1.2.3.4", "::ffff:5.6.7.8"));
    }

    #[test]
    fn exact_mapped_matches_both_spellings() {
        assert!(m("127.0.0.1", "::ffff:127.0.0.1"));
        assert!(m("::ffff:127.0.0.1", "127.0.0.1"));
        assert!(m("::ffff:127.0.0.1", "::ffff:127.0.0.1"));
        assert!(!m("::ffff:127.0.0.1", "127.0.0.2"));
    }

    #[test]
    fn loopback_matches_only_loopback() {
        assert!(m("loopback", "127.0.0.1"));
        assert!(m("loopback", "127.255.0.9"));
        assert!(m("loopback", "::1"));
        assert!(!m("loopback", "128.0.0.1"));
        assert!(!m("loopback", "::2"));
    }

    #[test]
    fn v4_wildcard_mask() {
        assert!(m("10.*.0.1", "10.1.0.1"));
        assert!(m("10.*.0.1", "10.200.0.1"));
        assert!(!m("10.*.0.1", "10.1.0.2"));
        assert!(!m("10.*.0.1", "11.1.0.1"));
        assert!(m("*.*.*.*", "8.8.8.8"));
    }

    #[test]
    fn v6_wildcard_mask() {
        // '::' is zero groups only; '*' is exactly one group.
        // "2001:db8::*" = 2001:db8:0:0:0:0:0:* (NOT /64).
        assert!(m("2001:db8::*", "2001:db8::1"));
        assert!(m("2001:db8::*", "2001:db8:0:0:0:0:0:5"));
        assert!(m("2001:db8::*", "2001:db8::ffff"));
        // groups 3..6 are fixed to zeros → does not cover /64-like addresses
        assert!(!m("2001:db8::*", "2001:db8:1::1"));
        assert!(!m("2001:db8::*", "2001:db8::dead:beef"));
        assert!(!m("2001:db8::*", "2001:db9::1"));
        // "2001:db8:*::1" — only group 3 is a wildcard
        assert!(m("2001:db8:*::1", "2001:db8:5::1"));
        assert!(m("2001:db8:*::1", "2001:db8:0::1"));
        assert!(m("2001:db8:*::1", "2001:db8::1"));
        assert!(!m("2001:db8:*::1", "2001:db8::2"));
        assert!(!m("2001:db8:*::1", "2001:db8:5::2"));
        // multiple '*' in different explicit groups with '::'
        assert!(m("2001:*:db8:*::1", "2001:0:db8:ffff:0:0:0:1"));
        assert!(!m("2001:*:db8:*::1", "2001:0:db8:ffff:0:0:0:2"));
        // without '::' — exactly 8 groups
        assert!(m("2001:db8:0:0:0:0:0:*", "2001:db8::7"));
        assert!(!m("2001:db8:0:0:0:0:*:0", "2001:db8::7"));
    }

    #[test]
    fn mapped_hextet_mask_matches_ipv4_as_mapped() {
        // "::ffff:7f00:*" pins group 7 = 0x7f00 (octets 127.0),
        // group 8 is any; IPv4 is treated as ::ffff:a.b.c.d.
        assert!(m("::ffff:7f00:*", "127.0.0.1"));
        assert!(m("::ffff:7f00:*", "::ffff:127.0.0.1"));
        assert!(m("::ffff:7f00:*", "127.0.255.255"));
        assert!(!m("::ffff:7f00:*", "127.1.0.1"));
        assert!(!m("::ffff:7f00:*", "128.0.0.1"));
        assert!(!m("::ffff:7f00:*", "2001:db8::1"));
    }

    #[test]
    fn v4_mask_rejects_native_v6_but_accepts_mapped() {
        assert!(m("10.*.2.3", "::ffff:10.1.2.3"));
        assert!(!m("10.*.2.3", "2001:db8::1"));
        // non-mapped IPv4-compatible is not expanded to IPv4
        assert!(!m("1.2.3.4", "::102:304"));
        assert!(!m("::1", "127.0.0.1"));
    }

    #[test]
    fn star_allows_everything() {
        assert!(m("*", "1.2.3.4"));
        assert!(m("*", "::1"));
        assert!(m("*", "::ffff:5.6.7.8"));
    }

    #[test]
    fn or_semantics() {
        let c = ok("127.0.0.1, 10.*.0.1 , ::1");
        assert!(c.matches("127.0.0.1".parse().unwrap()));
        assert!(c.matches("10.9.0.1".parse().unwrap()));
        assert!(c.matches("::1".parse().unwrap()));
        assert!(!c.matches("10.9.0.2".parse().unwrap()));
    }

    #[test]
    fn loopback_keyword_is_case_insensitive() {
        assert!(m("LoopBack", "::1"));
    }
}
