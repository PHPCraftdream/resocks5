//! Компиляция и проверка правил `allowed_clients`.
//!
//! Строка правила — элементы через запятую (OR):
//! - точный IP (`1.2.3.4`, `::1`, `2001:db8::1`; mapped-форма
//!   `::ffff:a.b.c.d` нормализуется к IPv4);
//! - ключевое слово `loopback` — `127.0.0.0/8` и `::1`;
//! - маска со `*`: `*` заменяет ровно один октет (IPv4, ровно 4 октета)
//!   или ровно одну hex-группу (IPv6). `::` — только одно сжатие и
//!   означает ТОЛЬКО нулевые группы: `2001:db8::*` =
//!   `2001:db8:0:0:0:0:0:*`, а не /64 и не /32. Без `::` — ровно
//!   8 явных групп; с `::` — строго меньше 8.
//!
//! Отвергается (fail-closed): hostname, CIDR, порт, частичные звёздочки
//! (`1*.2.3.4`, `1*x`), зоны `%eth0`, скобки `[::1]`, лишние `:` (`:::`),
//! группы длиннее 4 hex-цифр, ведущие нули октетов IPv4 (`01.2.3.4`),
//! пустая строка и пустые элементы (`a,,b`). Ошибка любого элемента
//! отвергает всю строку, даже при наличии `*`.
//!
//! Сравнение: peer нормализуется mapped→IPv4. IPv4 при сравнении с
//! IPv6-маской рассматривается как `::ffff:a.b.c.d`;
//! IPv4-compatible (`::a.b.c.d` без ffff) не нормализуется.

use std::net::{IpAddr, Ipv6Addr};

use anyhow::{bail, Context, Result};

/// Скомпилированное правило `allowed_clients`: `matches` отвечает,
/// допущен ли IP. Пустые правила невозможны — компиляция их отвергает.
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

/// Маска: `None` = wildcard-группа, `Some(v)` = фиксированное значение.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Mask {
    V4([Option<u8>; 4]),
    V6([Option<u16>; 8]),
}

/// Скомпилировать строку правила. Fail-closed: любой некорректный
/// элемент отвергает всю строку.
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

/// IPv4-mapped IPv6 (::ffff:a.b.c.d) → IPv4; остальные адреса без изменений.
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
            // IPv4 сравниваем как ::ffff:a.b.c.d; IPv4-compatible не трогаем.
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
    // Точный адрес (без '*') — единая каноника std, включая запрет
    // ведущих нулей ("01.2.3.4" → Err).
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
    // Точный адрес без '*' — парсим std (сжатие, регистр hex — канонично).
    if !elem.contains('*') {
        let v6: Ipv6Addr = elem
            .parse()
            .map_err(|_| anyhow::anyhow!("некорректный IPv6-адрес"))?;
        let ip = normalize_mapped(IpAddr::V6(v6));
        return Ok(Rule::Exact(ip));
    }

    // Ровно одно '::' — иначе неоднозначность.
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
        // Отвергаем ДО вычитания — иначе underflow/паника.
        bail!("слишком много групп");
    }
    match elem.split_once("::") {
        // С '::' явных групп строго меньше 8; сжатые группы — нули,
        // '*' НИЧЕГО не заполняет (никакой семантики "star fills compression").
        Some(_) => {
            if explicit == 8 {
                bail!("'::' при 8 явных группах");
            }
            let mut full: Vec<&str> = Vec::with_capacity(8);
            full.extend(head);
            // Сжатые '::' группы — нули (см. комментарий выше).
            full.extend(std::iter::repeat_n("0", 8 - explicit));
            full.extend(tail);
            Ok(Rule::Mask(Mask::V6(finish_v6_groups(&full)?)))
        }
        // Без '::' — ровно 8 явных групп, '*' в каждой допустима.
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
        // hex-группа: 1..4 цифры ("00000" — 5 цифр — отвергаем явно).
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

    // ─── парсер: поддержанные формы ─────────────────────────────────

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
        err(""); // пустая строка
        err("a,,b"); // пустой элемент
        err(" "); // только пробел
        err("example.com"); // hostname
        err("10.0.0.0/8"); // CIDR
        err("1.2.3.4:80"); // порт
        err("1*.2.3.4"); // частичная звёздочка
        err("1*x"); // мусор рядом со звёздочкой
        err("10.1.*"); // не 4 октета
        err("10.*.*"); // не 4 октета
        err("::1%eth0"); // зона
        err("[::1]"); // скобки
        err(":::"); // лишние ':'
        err("1:2"); // мало групп без '::'
        err("1.2.3"); // мало октетов
        err("1.2.3.4.5"); // много октетов
        err("256.1.1.1"); // октет вне диапазона
        err("01.2.3.4"); // ведущие нули
        err("2001:db8::*::*"); // два '::'
        err("2001:db8:00000::*"); // группа длиннее 4 hex-цифр
        err("2001:db8::1*x"); // мусор рядом со '*' в IPv6
    }

    #[test]
    fn too_many_groups_rejected() {
        // 9 явных групп без '::'
        err("1:2:3:4:5:6:7:8:9");
        // 9 явных групп с '::'
        err("::1:2:3:4:5:6:7:8:9");
        err("1:2:3:4:5:6:7:8::9");
        // 8 явных групп + '::'
        err("1:2:3:4:5:6:7:8::");
        err("::1:2:3:4:5:6:7:8");
        err("2001:db8::1:2:3:4:5:6:7:8");
    }

    #[test]
    fn wildcard_group_count_negatives() {
        // '*' не обходит подсчёт групп/запретов: и с '::', и без.
        err("1:2:3:4:5:6:7:8:*"); // 9 явных групп без '::'
        err("1:2:3:4:5:6:7:*::"); // 8 явных групп + '::'
        err("::1:2:3:4:5:6:7:8:*"); // 9 явных групп + '::'
        err("2001:db8:*"); // 3 группы без '::' — '*' не расширяет до 8
        err("01.*.2.3"); // ведущие нули октета и под '*'
        err("2001:::*"); // ':::' — лишние ':'
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
        // '::ffff:127.0.0.1' и '127.0.0.1' — один и тот же Exact.
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
        // '::' — только нулевые группы; '*' — ровно одна группа.
        // "2001:db8::*" = 2001:db8:0:0:0:0:0:* (НЕ /64).
        assert!(m("2001:db8::*", "2001:db8::1"));
        assert!(m("2001:db8::*", "2001:db8:0:0:0:0:0:5"));
        assert!(m("2001:db8::*", "2001:db8::ffff"));
        // группы 3..6 фиксированы нулями → /64-подобных адресов не покрывает
        assert!(!m("2001:db8::*", "2001:db8:1::1"));
        assert!(!m("2001:db8::*", "2001:db8::dead:beef"));
        assert!(!m("2001:db8::*", "2001:db9::1"));
        // "2001:db8:*::1" — wildcard только группа 3
        assert!(m("2001:db8:*::1", "2001:db8:5::1"));
        assert!(m("2001:db8:*::1", "2001:db8:0::1"));
        assert!(m("2001:db8:*::1", "2001:db8::1"));
        assert!(!m("2001:db8:*::1", "2001:db8::2"));
        assert!(!m("2001:db8:*::1", "2001:db8:5::2"));
        // несколько '*' в разных явных группах при '::'
        assert!(m("2001:*:db8:*::1", "2001:0:db8:ffff:0:0:0:1"));
        assert!(!m("2001:*:db8:*::1", "2001:0:db8:ffff:0:0:0:2"));
        // без '::' — ровно 8 групп
        assert!(m("2001:db8:0:0:0:0:0:*", "2001:db8::7"));
        assert!(!m("2001:db8:0:0:0:0:*:0", "2001:db8::7"));
    }

    #[test]
    fn mapped_hextet_mask_matches_ipv4_as_mapped() {
        // "::ffff:7f00:*" фиксирует группу 7 = 0x7f00 (октеты 127.0),
        // группа 8 — любая; IPv4 рассматривается как ::ffff:a.b.c.d.
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
        // non-mapped IPv4-compatible не расширяется в IPv4
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
