use super::*;
use std::cell::Cell;
use tokio::sync::oneshot;

thread_local! {
    static EVENTS: Cell<(usize, [bool; 4])> = const { Cell::new((0, [false; 4])) };
}

fn record(c: &Credentials) {
    let empty = c.username().is_empty()
        && c.password().is_empty()
        && c.basic_payload().is_none()
        && c.username_bytes().is_empty()
        && c.password_bytes().is_empty()
        && c.raw_parts() == (None, None);
    EVENTS.with(|events| {
        let (count, mut wiped) = events.get();
        if count < wiped.len() {
            wiped[count] = empty;
        }
        events.set((count + 1, wiped));
    });
}

struct Reset(Option<crate::server::credentials::drop_observer::Guard>);
impl Drop for Reset {
    fn drop(&mut self) {
        drop(self.0.take());
        EVENTS.with(|events| events.set((0, [false; 4])));
    }
}

fn observe() -> Reset {
    EVENTS.with(|events| events.set((0, [false; 4])));
    Reset(Some(crate::server::credentials::drop_observer::install(
        record,
    )))
}

#[tokio::test]
async fn cancelled_basic_auth_drops_both_wiped_credentials() {
    let _reset = observe();
    let (mut peer, mut server) = duplex(4096);
    let token = general_purpose::STANDARD.encode("user:pa:ss");
    peer.write_all(
        format!("CONNECT h:443 HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let (started_tx, started_rx) = oneshot::channel();
    let options = options(false, true).retain_credentials(true);
    let mut future = Box::pin(accept(&mut server, &options, move |c| async move {
        assert_eq!(c.username(), "user");
        assert_eq!(c.password(), "pa:ss");
        assert_eq!(c.basic_payload(), Some("user:pa:ss"));
        let _ = started_tx.send(());
        let _ = std::future::pending::<()>().await;
        drop(c);
        true
    }));
    tokio::select! {
        result = &mut future => panic!("authentication unexpectedly completed: {result:?}"),
        started = started_rx => started.expect("callback started"),
    }
    EVENTS.with(|events| assert_eq!(events.get().0, 0));
    drop(future);
    EVENTS.with(|events| {
        let (count, wiped) = events.get();
        assert_eq!(count, 2);
        assert_eq!(&wiped[..2], &[true, true]);
    });
}

#[tokio::test]
async fn retained_basic_credentials_are_wiped_on_each_owner_drop() {
    let _reset = observe();
    let calls = Arc::new(AtomicUsize::new(0));
    let (result, _) = http_basic_accept("user", "pa:ss", b"", true, true, &calls).await;
    let mut request = result.expect("HTTP accepted");
    let retained = request.take_credentials().expect("retained credentials");
    assert_eq!(retained.username(), "user");
    assert_eq!(retained.password(), "pa:ss");
    assert_eq!(retained.username_bytes(), b"user");
    assert_eq!(retained.password_bytes(), b"pa:ss");
    assert_eq!(retained.basic_payload(), Some("user:pa:ss"));
    assert!(request.take_credentials().is_none());
    assert_eq!(request.take_username(), Some("user".to_owned()));
    EVENTS.with(|events| assert_eq!(events.get().0, 1));
    drop(retained);
    EVENTS.with(|events| {
        let (count, wiped) = events.get();
        assert_eq!(count, 2);
        assert_eq!(&wiped[..2], &[true, true]);
    });
    drop(request);
    EVENTS.with(|events| assert_eq!(events.get().0, 2));
}
