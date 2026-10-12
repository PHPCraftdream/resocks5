use super::*;

#[test]
fn users_lock_held_externally_does_not_block_cache_miss_verify_for_other_user() {
    // R5-10: while one thread is parked inside the init-claim persist
    // (waiting on the cross-process users-file lock), a plain
    // cache-miss verify for an unrelated, fully-configured user must
    // NOT block on the `users` RwLock.
    //
    // The busy lock is held by an in-process helper thread instead of
    // a child process: byte-range locks (LockFileEx / flock) conflict
    // across OPEN FILE HANDLES even within one process, which
    // users_file.rs's `lock_is_exclusive_and_released_on_drop` proves
    // (l1 held, second acquire times out). So a second UsersFileLock
    // from a helper thread exercises the identical busy-lock path in
    // persist_claim that a foreign process would, with zero
    // subprocess overhead. Actual cross-process release-on-owner-death
    // is separately covered by users_file.rs's crash test
    // `lock_is_released_when_owner_process_dies_without_cleanup`.
    //
    // Phase synchronization is by real events, not sleeps (R6-07):
    // the holder releases the file lock only on an explicit signal,
    // and the parent only proceeds once T1's presence at the guarded
    // region is CONFIRMED (R7-04 probe): try_lock proving T1 HOLDS
    // claim_lock, then the probe event fired immediately before the
    // persist call proving T1 actually ENTERED the guarded
    // persistence region — the mutex alone does not distinguish
    // holding claim_lock from being parked inside persist_claim.
    use std::sync::mpsc;
    use std::sync::TryLockError;
    use std::time::{Duration, Instant};

    let (mut state, path) = build_state_with_disk_file(
        vec![
            make_user("alice", "alice-pw", true),
            make_init_user("bob", true),
        ],
        false,
    );
    let (claim_tx, mut claim_rx) = mpsc::channel::<&'static str>();
    state.install_claim_probe(claim_tx);

    // Holder thread: acquire the users-file lock, signal the parent
    // once it is ACTUALLY held, then keep it until the parent's
    // explicit release signal — no fixed hold timer — and ack the
    // release after dropping it.
    let (locked_tx, locked_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (released_tx, released_rx) = mpsc::channel::<()>();
    let holder_path = path.clone();
    let holder = std::thread::spawn(move || {
        let lock =
            UsersFileLock::acquire_with_timeout(Path::new(&holder_path), Duration::from_secs(5))
                .expect("holder must acquire the users-file lock");
        locked_tx.send(()).expect("signal lock held");
        release_rx
            .recv()
            .expect("holder must receive the release signal");
        drop(lock);
        released_tx.send(()).expect("signal lock released");
    });
    locked_rx.recv().expect("lock-holder signalled");

    // T1: init-claim for bob — parks inside persist_claim on the
    // file lock the holder thread holds.
    let state = Arc::new(state);
    let t1 = std::thread::spawn({
        let state = state.clone();
        move || state.verify("bob", "bob-pw")
    });

    // Confirm T1 reached its critical section by polling for real
    // claim_lock contention (R6-07), not by a fixed sleep: try_lock
    // succeeding means T1 has not taken the mutex yet — drop the
    // guard immediately so it cannot stall T1 — and WouldBlock means
    // T1 holds it. Panic if the deadline passes without ever seeing
    // contention; that means T1 never reached the critical section
    // and the test's premise was never established.
    let contention_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match state.claim_lock.try_lock() {
            Err(TryLockError::WouldBlock) => break,
            Ok(uncontended) => drop(uncontended),
            Err(TryLockError::Poisoned(_)) => panic!("claim mutex poisoned"),
        }
        assert!(
            Instant::now() < contention_deadline,
            "T1 never took claim_lock within 10 s — the claim \
             contention this test relies on was never observed"
        );
        std::thread::sleep(Duration::from_millis(1));
    }

    // R7-04: the try_lock loop above proves only that T1 HOLDS
    // claim_lock — the post-mutex re-check and the users-file stat
    // still sit between the mutex and the guarded persistence region
    // whose users-guard-holding I/O a regression would have to
    // (re)introduce. Anchor T2's measurement to the probe event
    // fired immediately BEFORE the call into the persist helper:
    // only then is T1 genuinely inside the region this test is
    // about. 15 s guard: T1 hashes one real Argon2id digest before
    // it can arrive, and that stretch reaches seconds under real
    // CPU load (see the machine-load note).
    wait_for_claim_event(
        &mut claim_rx,
        "persist_region_entered",
        Duration::from_secs(15),
        "T1 entering the guarded persistence region",
    );

    // T2: a fresh cache-miss verify for alice (Argon2 only, no
    // claim machinery) must complete in milliseconds, not wait
    // behind T1's parked persist. The 5 s bound is a generous
    // companion guard (Argon2id can degrade from ~15 ms to seconds
    // under concurrent CPU load on this machine — see the
    // recovery-plan note), not the discriminator: in the old
    // (write-guard-held-across-persist) implementation this read
    // blocks until the holder releases the file lock — which only
    // happens after these assertions — so the regression shows up
    // as this verify never returning; the bound only catches any
    // unexpected shorter stall.
    let started = Instant::now();
    let ok = state.verify("alice", "alice-pw");
    let elapsed = started.elapsed();
    assert!(ok);
    assert!(
        elapsed < Duration::from_secs(5),
        "cache-miss verify for an unrelated user blocked {:?} behind the claim persist",
        elapsed
    );

    // Deterministic: the release signal has not been sent, so the
    // file lock is still held and T1 must still be parked inside
    // persist_claim — bob must still be the sentinel here.
    {
        let users = state.users.read().unwrap();
        let bob = users.iter().find(|u| u.name == "bob").unwrap();
        assert_eq!(bob.hash, INIT_HASH, "T1 must still be parked in persist");
    }

    // Explicit release: only now may the holder drop the lock, so
    // T1's parked persist can complete.
    release_tx
        .send(())
        .expect("signal the holder to release the file lock");
    released_rx
        .recv()
        .expect("holder acked the release (lock dropped)");

    holder.join().expect("join lock-holder thread");
    assert!(t1.join().unwrap());

    {
        let users = state.users.read().unwrap();
        let bob = users.iter().find(|u| u.name == "bob").unwrap();
        assert!(bob.hash.starts_with("$argon2id$"));
    }
    let loaded: UsersConfig = ktav::from_file(&path).unwrap();
    let bob = loaded.users.iter().find(|u| u.name == "bob").unwrap();
    assert_ne!(bob.hash, INIT_HASH);
    assert!(bob.hash.starts_with("$argon2id$"));

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{}.lock", path));
}

#[tokio::test]
async fn async_verify_completes_while_claim_parked_without_hashing_slot() {
    // R7-03: the phase split must let an ordinary cache-miss
    // verify_async run its Argon2 work while an init-claim is parked
    // in claim_commit on the cross-process users-file lock — even
    // with only ONE verify_slots permit free. This drives the REAL
    // async server path; the sync sibling test
    // users_lock_held_externally_... calls state.verify, which
    // bypasses verify_slots entirely and so cannot catch a
    // regression that keeps the permit across persistence.
    //
    // Phase synchronization is by real events, not sleeps (R6-07):
    // the holder releases the file lock only on an explicit signal,
    // and the parent confirms T1's parking via claim_lock try_lock
    // contention — T1 is the only other party contending for that
    // mutex, so WouldBlock proves T1 is parked inside its claim
    // critical section.
    use std::sync::mpsc;
    use std::sync::TryLockError;
    use std::time::{Duration, Instant};

    let (state, path) = build_state_with_disk_file(
        vec![
            make_user("alice", "alice-pw", true),
            make_init_user("bob", true),
        ],
        false,
    );
    let state = Arc::new(state);

    // Holder thread: acquire the users-file lock, signal the parent
    // once it is ACTUALLY held, then keep it until the parent's
    // explicit release signal — no fixed hold timer — and ack the
    // release after dropping it. A second UsersFileLock from a
    // helper thread exercises the identical busy-lock path in
    // persist_claim that a foreign process would (byte-range locks
    // conflict across open file handles within one process).
    let (locked_tx, locked_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (released_tx, released_rx) = mpsc::channel::<()>();
    let holder_path = path.clone();
    let holder = std::thread::spawn(move || {
        let lock =
            UsersFileLock::acquire_with_timeout(Path::new(&holder_path), Duration::from_secs(5))
                .expect("holder must acquire the users-file lock");
        locked_tx.send(()).expect("signal lock held");
        release_rx
            .recv()
            .expect("holder must receive the release signal");
        drop(lock);
        released_tx.send(()).expect("signal lock released");
    });
    locked_rx.recv().expect("lock-holder signalled");

    // Leave exactly ONE hashing slot free: the parked claim must not
    // need it (phase 2 runs without a permit), so it stays available
    // for T2's hashing.
    let slots = u32::try_from(state.verify_slots.available_permits()).unwrap();
    let held = state
        .verify_slots
        .clone()
        .acquire_many_owned(slots - 1)
        .await
        .unwrap();

    // T1: init-claim for bob through the real async path — parks
    // inside claim_commit's persist, waiting on the held file lock.
    let t1_state = Arc::clone(&state);
    let t1 = tokio::spawn(async move { t1_state.verify_async("bob", "bob-pw").await });

    // Confirm T1 parked in claim_commit by polling for real
    // claim_lock contention (R6-07), not by a fixed sleep: try_lock
    // succeeding means T1 has not taken the mutex yet — drop the
    // guard immediately so it cannot stall T1 — and WouldBlock means
    // T1 holds it. Panic if the deadline passes without ever seeing
    // contention; that means T1 never reached the critical section
    // and the test's premise was never established.
    let contention_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match state.claim_lock.try_lock() {
            Err(TryLockError::WouldBlock) => break,
            Ok(uncontended) => drop(uncontended),
            Err(TryLockError::Poisoned(_)) => panic!("claim mutex poisoned"),
        }
        assert!(
            Instant::now() < contention_deadline,
            "T1 never took claim_lock within 10 s — the parked-claim \
             premise was never established"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    // The core R7-03 assertion: while T1 is parked on the users-file
    // lock, its hashing permit is long gone (dropped when the
    // phase-1 closure returned), so the free slot count is back
    // to 1.
    assert_eq!(
        state.verify_slots.available_permits(),
        1,
        "a claim parked on the users-file lock must not hold a hashing slot (R7-03)"
    );

    // T2: a fresh cache-miss verify_async for alice — the REAL
    // server path — must complete while T1 is still parked. The
    // 5 s timeout bound is a generous companion guard (Argon2id can
    // degrade from ~15 ms to seconds under concurrent CPU load on
    // this machine — see the machine-load note in this file), not
    // the discriminator: pre-fix, T1 holds the only free permit
    // until the file lock is released, so T2 cannot even start
    // hashing (the permit-count assert above already fails).
    let started = Instant::now();
    let ok = tokio::time::timeout(
        Duration::from_secs(5),
        state.verify_async("alice", "alice-pw"),
    )
    .await
    .expect("verify_async for an unrelated user timed out behind the parked claim");
    let elapsed = started.elapsed();
    assert!(ok);
    assert!(
        elapsed < Duration::from_secs(5),
        "unrelated verify_async blocked {:?} behind the parked claim",
        elapsed
    );

    // Deterministic: the release signal has not been sent, so the
    // file lock is still held and T1 must still be parked inside
    // persist_claim — bob must still be the sentinel here.
    assert!(!t1.is_finished(), "T1 must still be parked in claim_commit");
    {
        let users = state.users.read().unwrap();
        let bob = users.iter().find(|u| u.name == "bob").unwrap();
        assert_eq!(bob.hash, INIT_HASH, "T1 must still be parked in persist");
    }

    // Explicit release: only now may the holder drop the lock, so
    // T1's parked persist can complete.
    release_tx
        .send(())
        .expect("signal the holder to release the file lock");
    let t1_ok = t1.await.expect("T1 task must not panic");
    assert!(t1_ok, "T1's claim must succeed once the file lock frees");
    released_rx
        .recv()
        .expect("holder acked the release (lock dropped)");
    holder.join().expect("join lock-holder thread");

    // T1's claim landed in memory and on disk.
    {
        let users = state.users.read().unwrap();
        let bob = users.iter().find(|u| u.name == "bob").unwrap();
        assert!(bob.hash.starts_with("$argon2id$"));
    }
    let loaded: UsersConfig = ktav::from_file(&path).unwrap();
    let bob = loaded.users.iter().find(|u| u.name == "bob").unwrap();
    assert_ne!(bob.hash, INIT_HASH);
    assert!(bob.hash.starts_with("$argon2id$"));

    // Every hashing slot is back: T1 dropped its phase-3 permit and
    // T2 its phase-1 permit.
    drop(held);
    assert_eq!(
        state.verify_slots.available_permits(),
        usize::try_from(slots).unwrap()
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{}.lock", path));
}
// ─── P1-01: claim admission cannot exhaust the shared blocking pool ──

#[test]
fn claim_pileup_cannot_starve_ordinary_login_on_small_blocking_pool() {
    // P1-01 release gate. A runtime whose blocking pool holds TWO
    // threads; three concurrent init-claims on three different accounts
    // while an external holder pins the cross-process users-file lock;
    // and one ordinary cache-miss login (alice) that MUST complete
    // while the file lock is still held.
    //
    // Fixed (admission cap forced to 1 here): exactly one claim occupies
    // a blocking thread — parked inside claim_commit on the pinned file
    // lock — while the other two wait for their admission permit on the
    // async runtime without touching any thread, leaving the second pool
    // thread for alice.
    //
    // Unfixed (mechanism reverted): every claim goes straight into its
    // own spawn_blocking; the first parks on the file lock and each
    // follower parks on claim_lock behind it, so both pool threads end
    // up permanently parked and alice's spawn_blocking never runs — the
    // login times out and the test fails.
    //
    // Sequencing is event/state anchored, never sleep-sized (R6-07): the
    // admitted claim's arrival at claim_commit is taken from the R7-04
    // probe, and alice starts only after verify_slots has been observed
    // FULL for three consecutive 50 ms polls — every phase-1 Argon2 hash
    // has finished and stayed finished, so on the unfixed code every
    // phase-2 closure a follower submits (submission follows phase-1
    // completion immediately) was queued BEFORE alice in tokio's FIFO
    // blocking queue (pool.rs push_back/pop_front, tokio 1.43.1) and
    // parks its thread first. If a phase-1 is starved because the pool
    // is already fully parked, the 30 s anchor deadline simply expires
    // and the test proceeds — alice then starves behind the parked
    // threads and fails with the meaningful message below.
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .max_blocking_threads(2)
        .build()
        .expect("test runtime");

    runtime.block_on(async move {
        let (mut state, path) = build_state_with_disk_file(
            vec![
                make_user("alice", "alice-pw", true),
                make_init_user("bob", true),
                make_init_user("carl", true),
                make_init_user("dave", true),
            ],
            false,
        );
        // Deterministic admission arithmetic: exactly one claim may run
        // its persistence at a time (the production default is 2; the
        // explicit knob keeps the pool budget independent of the build
        // machine's CPU count).
        state.claim_slots = Arc::new(tokio::sync::Semaphore::new(1));
        let (claim_tx, mut claim_rx) = mpsc::channel::<&'static str>();
        state.install_claim_probe(claim_tx);
        let state = Arc::new(state);
        let slots_before = state.verify_slots.available_permits();
        assert_eq!(
            state.claim_slots.available_permits(),
            1,
            "test premise: admission cap forced to 1"
        );

        // External holder: pins the users-file lock until the explicit
        // release signal (R6-07: no fixed hold timer).
        let (locked_tx, locked_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let holder_path = path.clone();
        let holder = std::thread::spawn(move || {
            let lock = UsersFileLock::acquire_with_timeout(
                Path::new(&holder_path),
                Duration::from_secs(5),
            )
            .expect("holder must acquire the users-file lock");
            locked_tx.send(()).expect("signal lock held");
            release_rx
                .recv()
                .expect("holder must receive the release signal");
            drop(lock);
        });
        locked_rx.recv().expect("users-file lock pinned");

        // Three concurrent claims through the real async path.
        let mut claims = Vec::new();
        for (name, pw) in [("bob", "bob-pw"), ("carl", "carl-pw"), ("dave", "dave-pw")] {
            let state = Arc::clone(&state);
            claims.push(tokio::spawn(
                async move { state.verify_async(name, pw).await },
            ));
        }

        // Event anchor: the one ADMITTED claim is inside claim_commit.
        wait_for_claim_event(
            &mut claim_rx,
            "claim_commit_entered",
            Duration::from_secs(60),
            "the admitted claim reaching claim_commit",
        );
        // State anchor: phase-1 hashing fully drained for three
        // consecutive polls (see the FIFO rationale above).
        let anchor_deadline = Instant::now() + Duration::from_secs(30);
        let mut steady = 0;
        while steady < 3 && Instant::now() < anchor_deadline {
            if state.verify_slots.available_permits() == slots_before {
                steady += 1;
            } else {
                steady = 0;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // The ordinary cache-miss login must complete while the file
        // lock is still held.
        let ok = tokio::time::timeout(
            Duration::from_secs(10),
            state.verify_async("alice", "alice-pw"),
        )
        .await
        .expect("ordinary cache-miss login starved by the claim pile-up");
        assert!(ok);

        // The admitted claim kept its permit across the whole park.
        assert_eq!(
            state.claim_slots.available_permits(),
            0,
            "the parked claim must hold its admission permit until its work finishes"
        );

        // The file lock is still pinned: nobody has persisted, every
        // init account is still the sentinel.
        {
            let users = state.users.read().unwrap();
            for name in ["bob", "carl", "dave"] {
                let u = users.iter().find(|u| u.name == name).unwrap();
                assert_eq!(u.hash, INIT_HASH, "{name} must still be unclaimed");
            }
        }

        release_tx.send(()).expect("release the users-file lock");

        for claim in claims {
            assert!(
                claim.await.expect("claim task must not panic"),
                "every claim must eventually succeed"
            );
        }
        assert_eq!(
            state.claim_slots.available_permits(),
            1,
            "the admission permit must be back once every claim finished"
        );

        // All three claims landed in memory (with cache entries) and on
        // disk; alice's own hash is intact.
        {
            let users = state.users.read().unwrap();
            for (name, pw) in [("bob", "bob-pw"), ("carl", "carl-pw"), ("dave", "dave-pw")] {
                let u = users.iter().find(|u| u.name == name).unwrap();
                assert!(u.hash.starts_with("$argon2id$"), "{name} hash in memory");
                assert!(
                    state.cache_matches(name, &compute_cache_hmac(&state.server_secret, name, pw)),
                    "{name} cache entry"
                );
            }
        }
        let loaded: UsersConfig = ktav::from_file(&path).unwrap();
        for name in ["bob", "carl", "dave"] {
            let u = loaded.users.iter().find(|u| u.name == name).unwrap();
            assert!(u.hash.starts_with("$argon2id$"), "{name} hash on disk");
        }
        let alice = loaded.users.iter().find(|u| u.name == "alice").unwrap();
        assert!(alice.hash.starts_with("$argon2id$"), "alice hash on disk");

        holder.join().expect("join holder");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}.lock", path));
    });
}
