//! Wire-path сценарии #208: реальный `crate::server::accept()` на
//! предзаполненном in-memory duplex-потоке (чтение кадров, UTF-8-преобразования,
//! построение `Credentials`, retention duplicate, конструирование `IncomingRequest`).
//! Подготовка (runtime, duplex, запись байтов, опции) — вне scope; scope включает
//! `runtime.block_on` и возможный Box future. Executor overhead не исключён.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose;
use base64::Engine as _;
use tokio::io::{duplex, AsyncWriteExt};

use crate::perf::{measure, report, Counts};
use crate::server::{accept, Credentials, IncomingRequest, ServerError, ServerOptions};

/// Один wire-вход: байты клиента и флаги опций сервера.
struct WireCase {
    bytes: Vec<u8>,
    anonymous: bool,
    raw: bool,
    retain: bool,
}

/// RFC 1929 sub-negotiation: `VER, ULEN, UNAME, PLEN, PASSWD` (локальная
/// реплика из server/tests, недоступных из session::testing).
fn subneg(user: &[u8], pass: &[u8]) -> Vec<u8> {
    assert!(user.len() <= 255 && pass.len() <= 255);
    let mut frame = Vec::with_capacity(2 + user.len() + pass.len());
    frame.push(1);
    frame.push(user.len() as u8);
    frame.extend_from_slice(user);
    frame.push(pass.len() as u8);
    frame.extend_from_slice(pass);
    frame
}

/// SOCKS5: greeting + subneg + CONNECT-запрос на exit.invalid:443 (ATYP=3).
fn socks5_bytes(user: &[u8], pass: &[u8]) -> Vec<u8> {
    let mut bytes = vec![5, 1, 2];
    bytes.extend_from_slice(&subneg(user, pass));
    bytes.extend_from_slice(&[5, 1, 0, 3, 12]);
    bytes.extend_from_slice(b"exit.invalid");
    bytes.extend_from_slice(&[0x01, 0xBB]);
    bytes
}

/// SOCKS5 аноним: greeting с методом 0x00 (без subneg) + CONNECT.
fn socks5_anonymous_bytes() -> Vec<u8> {
    let mut bytes = vec![5, 1, 0];
    bytes.extend_from_slice(&[5, 1, 0, 3, 12]);
    bytes.extend_from_slice(b"exit.invalid");
    bytes.extend_from_slice(&[0x01, 0xBB]);
    bytes
}

/// HTTP CONNECT на exit.invalid:443; с Basic-заголовком или без (контроль).
fn http_bytes(basic_token: &str) -> Vec<u8> {
    format!(
        "CONNECT exit.invalid:443 HTTP/1.1\r\nHost: exit.invalid\r\nProxy-Authorization: Basic {basic_token}\r\n\r\n"
    )
    .into_bytes()
}

fn http_anonymous_bytes() -> Vec<u8> {
    "CONNECT exit.invalid:443 HTTP/1.1\r\nHost: exit.invalid\r\n\r\n"
        .as_bytes()
        .to_vec()
}

/// Ожидания сохранности контракта для одного wire-сценария.
struct Expectation<'a> {
    user: &'a [u8],
    password: &'a [u8],
    payload: Option<&'a [u8]>,
    utf8: bool,
    req_user: Option<&'a str>,
    retain: bool,
}

/// Один прогон: prep вне measure (свежие runtime+duplex — одинаковые one-time
/// стоимости tokio на каждый вызов), measure оборачивает только block_on(accept).
fn accept_measured(
    case: &WireCase,
    expected: &Expectation,
    authenticate_expected: bool,
) -> (Result<IncomingRequest, ServerError>, Counts) {
    // Запись фикстуры — в отдельном одноразовом runtime без драйверов: duplex —
    // чистый канал, reactor не нужен; измеряемый runtime остаётся нетронутым.
    let prep = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("prep runtime build");
    let (mut peer, mut server) = duplex(64 * 1024);
    let fixture = case.bytes.clone();
    prep.block_on(async {
        peer.write_all(&fixture).await.expect("peer write");
        peer.shutdown().await.expect("peer shutdown");
    });
    drop(prep);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime build");
    let options = ServerOptions::new(
        tokio::time::Instant::now() + Duration::from_secs(5),
        case.anonymous,
        !case.anonymous,
    )
    .raw_credentials(case.raw)
    .retain_credentials(case.retain);
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    // Замыкание не аллоцирует и не паникует; сигнатура повторяет accept.
    let authenticate = move |credentials: Credentials| {
        let ok = credentials.username_bytes() == expected.user
            && credentials.password_bytes() == expected.password
            && credentials.basic_payload().map(str::as_bytes) == expected.payload
            && credentials.is_utf8() == expected.utf8;
        counted.fetch_add(1, Ordering::SeqCst);
        async move { ok }
    };
    let (result, counts) = measure(|| {
        runtime.block_on(async { accept(&mut server, &options, authenticate).await })
    });
    // peer держим до конца accept: сервер пишет в него ответы; dealloc после measure — вне scope.
    drop(peer);
    let called = calls.load(Ordering::SeqCst);
    let expected_calls = usize::from(authenticate_expected);
    assert_eq!(called, expected_calls, "вызовов closure аутентификации");
    (result, counts)
}

/// Контракт IncomingRequest одинаков на обоих прогонах; retain/anonymous ветки.
fn assert_request(req: &mut IncomingRequest, expected: &Expectation, anonymous: bool) {
    assert_eq!(req.target(), "exit.invalid:443");
    assert_eq!(req.username(), expected.req_user);
    if anonymous {
        assert_eq!(req.username_bytes(), None);
    } else {
        assert_eq!(req.username_bytes(), Some(expected.user));
    }
    if expected.retain {
        let creds = req.take_credentials().expect("retained");
        assert_eq!(creds.username_bytes(), expected.user);
        assert_eq!(creds.password_bytes(), expected.password);
        assert_eq!(creds.basic_payload().map(str::as_bytes), expected.payload);
        assert_eq!(creds.is_utf8(), expected.utf8);
        assert!(req.take_credentials().is_none());
    } else {
        assert!(req.take_credentials().is_none());
    }
}

#[test]
fn perf208_basic_payload_copy_guard() {
    for retain in [false, true] {
        let mut measured = Vec::new();
        for password_len in [22usize, 118] {
            let password = "p".repeat(password_len);
            let payload = format!("user:{password}");
            let token = general_purpose::STANDARD.encode(payload.as_bytes());
            let bytes = format!(
                "CONNECT exit.invalid:443 HTTP/1.1\r\nHost: exit.invalid\r\nProxy-Authorization: Basic {token}\r\n\r\n"
            ).into_bytes();
            let case = WireCase { bytes, anonymous: false, raw: false, retain };
            let expected = Expectation {
                user: b"user", password: password.as_bytes(), payload: Some(payload.as_bytes()),
                utf8: true, req_user: Some("user"), retain,
            };
            // Одинаковая форма callback/runtime: меряем длину данных внутри полного wire-пути.
            let run = || accept_measured(&case, &expected, true);
            let (first, counts) = run();
            let (again, repeated) = run();
            assert_eq!(counts, repeated, "повторный прогон должен совпасть");
            for result in [first, again] {
                let mut request = result.expect("Basic accept");
                assert_request(&mut request, &expected, false);
            }
            measured.push(counts);
        }
        let [short, long]: [Counts; 2] = measured.try_into().expect("две длины");
        assert_eq!(short.alloc, long.alloc);
        assert_eq!(short.alloc_zeroed, long.alloc_zeroed);
        assert_eq!(short.realloc, long.realloc);
        // Оракул относительный: буфер decoded payload и password растут на 96 байт каждый;
        // retention копирует также payload и password. Так обнаруживается лишний to_owned,
        // без привязки к абсолютным счётчикам аллокатора Windows.
        assert_eq!(long.requested_bytes - short.requested_bytes, if retain { 384 } else { 192 });
    }
}

#[test]
fn perf208_credentials_wire_parse_retention() {
    let basic_token = general_purpose::STANDARD.encode("user:pa:ss");

    // (имя отчёта, case, ожидания) — 7 сценариев, по одной строке report.
    let scenarios: Vec<(&str, WireCase, Expectation)> = vec![
        (
            "wire/socks5/utf8/retain",
            WireCase {
                bytes: socks5_bytes(b"user", b"password"),
                anonymous: false,
                raw: false,
                retain: true,
            },
            Expectation {
                user: b"user",
                password: b"password",
                payload: None,
                utf8: true,
                req_user: Some("user"),
                retain: true,
            },
        ),
        (
            "wire/socks5/utf8/plain",
            WireCase {
                bytes: socks5_bytes(b"user", b"password"),
                anonymous: false,
                raw: false,
                retain: false,
            },
            Expectation {
                user: b"user",
                password: b"password",
                payload: None,
                utf8: true,
                req_user: Some("user"),
                retain: false,
            },
        ),
        (
            "wire/socks5/raw/retain",
            WireCase {
                bytes: socks5_bytes(&[b'u', 0xff], &[b'p', 0xfe]),
                anonymous: false,
                raw: true,
                retain: true,
            },
            Expectation {
                user: &[b'u', 0xff],
                password: &[b'p', 0xfe],
                payload: None,
                utf8: false,
                req_user: Some("u\u{fffd}"),
                retain: true,
            },
        ),
        (
            "wire/http/basic/retain",
            WireCase {
                bytes: http_bytes(&basic_token),
                anonymous: false,
                raw: false,
                retain: true,
            },
            Expectation {
                user: b"user",
                password: b"pa:ss",
                payload: Some(b"user:pa:ss"),
                utf8: true,
                req_user: Some("user"),
                retain: true,
            },
        ),
        (
            "wire/http/basic/plain",
            WireCase {
                bytes: http_bytes(&basic_token),
                anonymous: false,
                raw: false,
                retain: false,
            },
            Expectation {
                user: b"user",
                password: b"pa:ss",
                payload: Some(b"user:pa:ss"),
                utf8: true,
                req_user: Some("user"),
                retain: false,
            },
        ),
        (
            "wire/http/anonymous/control",
            WireCase {
                bytes: http_anonymous_bytes(),
                anonymous: true,
                raw: false,
                retain: false,
            },
            Expectation {
                user: b"",
                password: b"",
                payload: None,
                utf8: true,
                req_user: None,
                retain: false,
            },
        ),
        (
            "wire/socks5/anonymous/control",
            WireCase {
                bytes: socks5_anonymous_bytes(),
                anonymous: true,
                raw: false,
                retain: false,
            },
            Expectation {
                user: b"",
                password: b"",
                payload: None,
                utf8: true,
                req_user: None,
                retain: false,
            },
        ),
    ];

    for (name, case, expected) in scenarios {
        let authenticate_expected = !case.anonymous;
        let run = || accept_measured(&case, &expected, authenticate_expected);
        // Свежий runtime на каждый прогон, без warm-up.
        let (result, counts) = run();
        let (again, repeated) = run();
        assert_eq!(counts, repeated, "детерминизм счётчиков на одинаковом входе");
        report(name, counts);
        // Сохранность контракта на ОБОИХ запросах.
        let mut first = result.expect("accept ok");
        let mut second = again.expect("accept ok");
        for req in [&mut first, &mut second] {
            assert_request(req, &expected, case.anonymous);
        }
    }
}
