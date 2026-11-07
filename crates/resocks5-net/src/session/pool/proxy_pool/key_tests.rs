//! Прямые проверки консистентности owning и borrowed представлений
//! ключа пула: поток Hasher, eq и lookup в map.

use std::hash::{Hash, Hasher};

use dashmap::DashMap;

use super::{ProxyEndpoint, ProxyKey};

/// Копит сырой поток байтов Hasher: сравнение по потоку, а не по
/// digest, ловит рассогласование ручного dyn Hash с кортежным.
#[derive(Default)]
struct Recorder(Vec<u8>);

impl Hasher for Recorder {
    fn finish(&self) -> u64 {
        0
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }
}

fn owned(host: &str, port: u16) -> ProxyKey {
    (host.to_owned(), port)
}

#[test]
fn borrowed_hash_stream_matches_the_owned_tuple() {
    for (host, port) in [
        ("proxy.example.invalid", 1080),
        ("2001:db8::1", 9050),
        ("прокси-тест.invalid", 1),
        ("🌍.invalid", 65535),
        ("", 0),
        ("h", 65534),
    ] {
        let owned_key = owned(host, port);
        let mut from_owned = Recorder::default();
        owned_key.hash(&mut from_owned);
        let mut from_borrowed = Recorder::default();
        let key: &dyn ProxyEndpoint = &(host, port);
        key.hash(&mut from_borrowed);
        assert_eq!(from_owned.0, from_borrowed.0, "host={host:?} port={port}");
    }
}

#[test]
fn borrowed_equality_agrees_with_the_owned_tuple() {
    for (left, right) in [
        (("h", 1u16), ("h", 1u16)),
        (("h", 1), ("h", 2)),
        (("h", 1), ("g", 1)),
        (("h", 0), ("h", 65535)),
        (("", 1), ("", 1)),
        (("", 1), ("h", 1)),
        (("🌍", 1), ("🌍", 1)),
        (("🌍", 1), ("🌍", 2)),
        (("2001:db8::1", 9050), ("2001:db8::1", 9050)),
        (("2001:db8::1", 9050), ("2001:db8::2", 9050)),
    ] {
        let owned_eq = owned(left.0, left.1) == owned(right.0, right.1);
        let key: &dyn ProxyEndpoint = &(left.0, left.1);
        let other: &dyn ProxyEndpoint = &(right.0, right.1);
        let borrowed_eq = key == other;
        assert_eq!(owned_eq, borrowed_eq, "{left:?} vs {right:?}");
    }
}

#[test]
fn borrowed_lookup_resolves_owned_entries_distinctly() {
    let map: DashMap<ProxyKey, u32> = DashMap::new();
    map.insert(owned("proxy.example.invalid", 1080), 1);
    map.insert(owned("proxy.example.invalid", 1081), 2);
    map.insert(owned("2001:db8::1", 9050), 3);
    map.insert(owned("прокси-тест.invalid", 1), 4);
    map.insert(owned("", 0), 5);

    let hit = |host: &str, port: u16| -> Option<u32> {
        // Owning-ключ не строится, как в production-коде.
        let key: &dyn ProxyEndpoint = &(host, port);
        map.get(key).map(|entry| *entry)
    };

    assert_eq!(hit("proxy.example.invalid", 1080), Some(1));
    assert_eq!(hit("proxy.example.invalid", 1081), Some(2));
    assert_eq!(hit("2001:db8::1", 9050), Some(3));
    assert_eq!(hit("прокси-тест.invalid", 1), Some(4));
    assert_eq!(hit("", 0), Some(5));

    // Host и port различаются: перекрёстных попаданий нет.
    assert_eq!(hit("proxy.example.invalid", 1082), None);
    assert_eq!(hit("proxy.example.invalid2", 1080), None);
    assert_eq!(hit("2001:db8::1", 9051), None);
    assert_eq!(hit("прокси-тест.invalid", 2), None);
    assert_eq!(hit("", 1), None);
    assert_eq!(hit("h", 0), None);
}
