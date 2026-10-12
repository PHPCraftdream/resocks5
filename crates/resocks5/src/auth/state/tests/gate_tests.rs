use super::*;

#[test]
fn cancelled_claim_keeps_admission_permit_until_persistence_finishes() {
    // P1-01 cancellation semantics, checked separately from the queue
    // test. The client future is aborted while its claim is parked on
    // the pinned users-file lock. The abort must NOT release the
    // admission permit early — the blocking closure is not cancellable
    // and keeps it until the persistence work actually finishes — must
    // not poison the pool for an ordinary login, and the abandoned
    // claim must still land in memory and on disk once the lock frees.
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .max_blocking_threads(3)
        .build()
        .expect("test runtime");

    runtime.block_on(async move {
        let (mut state, path) = build_state_with_disk_file(
            vec![
                make_user("alice", "alice-pw", true),
                make_init_user("zed", true),
            ],
            false,
        );
        state.claim_slots = Arc::new(tokio::sync::Semaphore::new(1));
        let (claim_tx, mut claim_rx) = mpsc::channel::<&'static str>();
        state.install_claim_probe(claim_tx);
        let state = Arc::new(state);

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

        let zed = {
            let state = Arc::clone(&state);
            tokio::spawn(async move { state.verify_async("zed", "zed-pw").await })
        };

        // Event anchor: the probe fires as the FIRST statement of
        // claim_commit, INSIDE the spawn_blocking closure — so by the
        // time it arrives the persistence work exists on a blocking
        // thread and aborting the client future cannot cancel it.
        wait_for_claim_event(
            &mut claim_rx,
            "claim_commit_entered",
            Duration::from_secs(60),
            "zed's claim reaching claim_commit",
        );
        zed.abort();
        assert!(
            zed.await.is_err(),
            "the client future must be gone after abort"
        );

        // The permit travelled WITH the blocking work: still held while
        // the orphaned persistence is parked on the file lock.
        assert_eq!(
            state.claim_slots.available_permits(),
            0,
            "the orphaned claim must keep its admission permit until its work finishes"
        );

        // The pool stays healthy for an ordinary login while the
        // orphaned claim sits parked.
        let ok = tokio::time::timeout(
            Duration::from_secs(10),
            state.verify_async("alice", "alice-pw"),
        )
        .await
        .expect("ordinary login starved by the cancelled claim");
        assert!(ok);

        // Still parked: zed is not published yet.
        {
            let users = state.users.read().unwrap();
            let z = users.iter().find(|u| u.name == "zed").unwrap();
            assert_eq!(z.hash, INIT_HASH, "zed must still be parked in persist");
        }

        release_tx.send(()).expect("release the users-file lock");

        // The orphaned persistence completes and publishes zed.
        let published = Instant::now() + Duration::from_secs(10);
        loop {
            {
                let users = state.users.read().unwrap();
                let z = users.iter().find(|u| u.name == "zed").unwrap();
                if z.hash != INIT_HASH {
                    break;
                }
            }
            assert!(
                Instant::now() < published,
                "the orphaned claim never finished its persistence"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let loaded: UsersConfig = ktav::from_file(&path).unwrap();
        let z = loaded.users.iter().find(|u| u.name == "zed").unwrap();
        assert!(
            z.hash.starts_with("$argon2id$"),
            "a cancelled client's claim must still persist"
        );
        assert!(state.verify("zed", "zed-pw"), "zed's password must work");
        assert_eq!(
            state.claim_slots.available_permits(),
            1,
            "the admission permit must be back once the orphaned work finished"
        );

        holder.join().expect("join holder");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}.lock", path));
    });
}

#[test]
fn same_account_claim_follower_waits_on_gate_not_on_a_blocking_thread() {
    // P1-01 dedup: a second concurrent claim for the SAME init account
    // must wait on the per-account async gate instead of queueing its
    // own blocking closure behind claim_lock. While the leader is
    // parked on the pinned users-file lock, the ordinary alice login
    // completes on the second pool thread, and over the WHOLE scenario
    // exactly ONE claim_commit_entered / persist_region_entered may be
    // emitted — the follower resolves against the committed hash after
    // the gate frees and never enters the claim machinery at all.
    // Unfixed, the follower parks a second blocking thread on
    // claim_lock and emits a second claim_commit_entered: the alice
    // login starves and the event count is 2.
    // The release is held until the follower's decision is established:
    // unfixed, its second claim_commit_entered is awaited while the file
    // lock is still pinned (the leader cannot publish, so the follower
    // cannot escape through the pre-mutex fast path); fixed, the permit
    // count proves the gate is what the follower is parked on.
    use std::sync::mpsc;
    use std::time::Duration;

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
            ],
            false,
        );
        state.claim_slots = Arc::new(tokio::sync::Semaphore::new(2));
        // Fix-presence signal for the discriminator below: while the
        // leader is parked, the FIXED code holds one of these two
        // permits (the follower will queue on the async gate); the
        // UNFIXED code never acquires any, so the count stays at 2.
        let admission_cap = state.claim_slots.available_permits();
        let (claim_tx, mut claim_rx) = mpsc::channel::<&'static str>();
        state.install_claim_probe(claim_tx);
        let state = Arc::new(state);

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

        let leader = {
            let state = Arc::clone(&state);
            tokio::spawn(async move { state.verify_async("bob", "same-pw").await })
        };
        // Collected, not plainly waited: the discriminator below counts
        // persist_region_entered, which legitimately interleaves with the
        // awaited claim_commit_entered, and a plain wait would consume and
        // discard it (the leader parks INSIDE claim_commit on the pinned
        // file lock, so both events sit in the channel until release).
        let mut events = Vec::new();
        collect_claim_events_until(
            &mut claim_rx,
            &mut events,
            "claim_commit_entered",
            1,
            Duration::from_secs(60),
            "the leader reaching claim_commit",
        );
        let follower = {
            let state = Arc::clone(&state);
            tokio::spawn(async move { state.verify_async("bob", "same-pw").await })
        };

        // Establish the follower's decision BEFORE releasing the lock
        // (otherwise the leader may publish during the follower's hash
        // and the follower escapes through the pre-mutex fast path
        // without ever entering the claim machinery — the observed
        // pre-fix pass). Unfixed: the follower must eventually park its
        // second blocking closure on claim_lock — the leader cannot
        // publish while the file lock is pinned, so the second
        // claim_commit_entered is guaranteed to arrive and the final
        // count assertion below fails deterministically. Fixed: the
        // permit count proves the admission mechanism is active, the
        // follower is parked on the gate and NO second event can ever
        // arrive, so waiting for it would deadlock — skip the wait.
        if state.claim_slots.available_permits() == admission_cap {
            wait_for_claim_event(
                &mut claim_rx,
                "claim_commit_entered",
                Duration::from_secs(60),
                "the unfixed follower parking on claim_lock (second entry into \
                 the claim machinery)",
            );
        }

        // The follower must not occupy a blocking thread: alice's
        // ordinary cache-miss login completes before the file lock is
        // released.
        let ok = tokio::time::timeout(
            Duration::from_secs(10),
            state.verify_async("alice", "alice-pw"),
        )
        .await
        .expect("ordinary login starved behind the same-account follower");
        assert!(ok);

        release_tx.send(()).expect("release the users-file lock");

        assert!(
            leader.await.expect("leader task must not panic"),
            "the leader must claim the account"
        );
        assert!(
            follower.await.expect("follower task must not panic"),
            "the follower must verify against the leader's hash"
        );

        // The discriminator: exactly ONE entry into the claim machinery
        // over the whole scenario — the leader's, already recorded in
        // `events` by the anchor. Unfixed, the follower's second entry
        // (awaited above while the lock was still pinned) shows up in
        // the drain and this fails with entered == 2.
        while let Ok(event) = claim_rx.try_recv() {
            events.push(event);
        }
        let entered = events
            .iter()
            .filter(|event| **event == "claim_commit_entered")
            .count();
        let persisted = events
            .iter()
            .filter(|event| **event == "persist_region_entered")
            .count();
        assert_eq!(
            entered, 1,
            "the follower must not enter claim_commit; events: {events:?}"
        );
        assert_eq!(
            persisted, 1,
            "only the leader may persist; events: {events:?}"
        );

        // Memory, cache and disk agree on one winning hash.
        let winner_hash = {
            let users = state.users.read().unwrap();
            let bob = users.iter().find(|u| u.name == "bob").unwrap();
            assert!(bob.hash.starts_with("$argon2id$"));
            bob.hash.clone()
        };
        let loaded: UsersConfig = ktav::from_file(&path).unwrap();
        let bob = loaded.users.iter().find(|u| u.name == "bob").unwrap();
        assert_eq!(bob.hash, winner_hash, "disk and memory must agree");
        assert!(state.verify("bob", "same-pw"));
        assert!(state.cache_matches(
            "bob",
            &compute_cache_hmac(&state.server_secret, "bob", "same-pw")
        ));

        holder.join().expect("join holder");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}.lock", path));
    });
}

#[test]
fn cancelled_leader_holds_claim_gate_against_same_account_follower() {
    // R3-P3-02 release gate: the per-account claim gate must live as
    // long as the admitted persistence work it deduplicates — including
    // after the client future is cancelled while that work is running.
    // The leader is aborted while its blocking closure is parked inside
    // persist_claim on the pinned users-file lock; a same-account
    // follower started immediately afterwards must NOT be admitted into
    // a second blocking claim (second claim_commit / persist region):
    // it must park on the gate the orphaned closure still holds and
    // resolve against the committed hash once that closure finishes.
    //
    // Unfixed (the gate guard lives in the cancelled async frame
    // instead of the blocking closure): the gate frees at abort time,
    // the follower takes it, finds no committed hash (the leader cannot
    // publish while the file lock is pinned), acquires the second
    // claim_slots permit (cap 2) and enters the claim machinery again —
    // claim_slots drops to 0 and a second claim_commit_entered arrives
    // while the file lock is still pinned.
    //
    // Sequencing is event/state anchored, never sleep-sized (R6-07):
    // the leader's arrival inside the guarded region is taken from the
    // R7-04 probe (persist_region_entered fires inside the
    // spawn_blocking closure, so the abort cannot cancel the work),
    // and the follower's phase-2 decision is read from the two permit
    // counters once its phase-1 hashing has been observed started and
    // then finished.
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
            ],
            false,
        );
        // Deterministic admission arithmetic: the default cap, spelled
        // out so the follower's expected "no permit held" state is
        // exact.
        state.claim_slots = Arc::new(tokio::sync::Semaphore::new(2));
        let admission_cap = state.claim_slots.available_permits();
        let (claim_tx, mut claim_rx) = mpsc::channel::<&'static str>();
        state.install_claim_probe(claim_tx);
        let state = Arc::new(state);
        let slots_before = state.verify_slots.available_permits();

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

        let leader = {
            let state = Arc::clone(&state);
            tokio::spawn(async move { state.verify_async("bob", "same-pw").await })
        };
        // Collected, not plainly waited: both events are needed for the
        // final count below, and persist_region_entered sits in the
        // channel behind claim_commit_entered while the leader is
        // parked. Once persist_region_entered has fired, the leader's
        // persistence exists on a blocking thread — aborting the client
        // future cannot cancel it (P1-01 semantics).
        let mut events = Vec::new();
        collect_claim_events_until(
            &mut claim_rx,
            &mut events,
            "claim_commit_entered",
            1,
            Duration::from_secs(60),
            "the leader reaching claim_commit",
        );
        collect_claim_events_until(
            &mut claim_rx,
            &mut events,
            "persist_region_entered",
            1,
            Duration::from_secs(60),
            "the leader entering the guarded persistence region",
        );

        // Cancel the leader while its orphaned persistence is parked on
        // the pinned file lock.
        leader.abort();
        assert!(
            leader.await.is_err(),
            "the leader future must be gone after abort"
        );

        let follower = {
            let state = Arc::clone(&state);
            tokio::spawn(async move { state.verify_async("bob", "same-pw").await })
        };

        // Anchor the follower's phase-2 decision while the file lock —
        // and therefore the leader's inability to publish — stays
        // pinned. Phase 1 is observable through verify_slots: a
        // below-full reading is the follower's Argon2id hash in flight
        // (nothing else hashes in this scenario), and polling at 1 ms
        // against a hash that takes tens of milliseconds at best
        // reliably catches it. Once the hash is done and stays done,
        // the decision has been made:
        // fixed  — the follower parked on the gate the orphaned
        //          closure still holds, holding NO admission permit
        //          (claim_slots stays at cap - 1);
        // unfixed — the follower took the second permit and entered
        //          the claim machinery again (claim_slots at 0).
        let anchor_deadline = Instant::now() + Duration::from_secs(30);
        let mut hashing_started = false;
        let mut steady = 0;
        let mut follower_admitted = false;
        while Instant::now() < anchor_deadline {
            if state.verify_slots.available_permits() != slots_before {
                hashing_started = true;
                steady = 0;
            } else if hashing_started {
                if state.claim_slots.available_permits() == admission_cap - 1 {
                    steady += 1;
                    if steady == 3 {
                        break;
                    }
                } else {
                    follower_admitted = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert!(
            hashing_started && (steady == 3 || follower_admitted),
            "the follower never reached its phase-2 decision within 30 s"
        );
        if follower_admitted {
            // Unfixed: the second claim_commit_entered is guaranteed to
            // arrive while the file lock is pinned (the leader cannot
            // publish, so the follower cannot escape through any fast
            // path). Await it so the failure below is anchored to the
            // probe, not merely to the permit counters.
            wait_for_claim_event(
                &mut claim_rx,
                "claim_commit_entered",
                Duration::from_secs(60),
                "the unfixed follower being admitted into a second \
                 claim_commit after the leader's cancellation",
            );
        }
        // Release BEFORE the regression assert: on the failing
        // (unfixed) path the panicking test must not leave the parked
        // closures pinned forever — the runtime waits for running
        // blocking tasks on drop.
        release_tx.send(()).expect("release the users-file lock");
        assert!(
            !follower_admitted,
            "the cancelled leader's per-account gate must keep the \
             follower out of the claim machinery while its persistence \
             is still running (R3-P3-02)"
        );

        // The orphaned persistence completes, publishes bob, and only
        // then frees the gate — the follower resolves against the
        // committed hash without ever persisting.
        assert!(
            follower.await.expect("follower task must not panic"),
            "the follower must verify against the leader's committed hash"
        );
        assert_eq!(
            state.claim_slots.available_permits(),
            admission_cap,
            "every admission permit must be back once the orphaned work \
             and the follower finished"
        );

        // Exactly ONE entry into the claim machinery and the persist
        // region over the whole scenario — the leader's.
        while let Ok(event) = claim_rx.try_recv() {
            events.push(event);
        }
        let entered = events
            .iter()
            .filter(|event| **event == "claim_commit_entered")
            .count();
        let persisted = events
            .iter()
            .filter(|event| **event == "persist_region_entered")
            .count();
        assert_eq!(
            entered, 1,
            "the follower must not enter claim_commit; events: {events:?}"
        );
        assert_eq!(
            persisted, 1,
            "only the leader's orphaned closure may persist; events: {events:?}"
        );

        // Memory, cache and disk agree on one winning hash, and the
        // claimed password keeps working.
        let winner_hash = {
            let users = state.users.read().unwrap();
            let bob = users.iter().find(|u| u.name == "bob").unwrap();
            assert!(bob.hash.starts_with("$argon2id$"));
            bob.hash.clone()
        };
        let loaded: UsersConfig = ktav::from_file(&path).unwrap();
        let bob = loaded.users.iter().find(|u| u.name == "bob").unwrap();
        assert_eq!(bob.hash, winner_hash, "disk and memory must agree");
        assert!(state.verify("bob", "same-pw"));
        assert!(state.cache_matches(
            "bob",
            &compute_cache_hmac(&state.server_secret, "bob", "same-pw")
        ));

        holder.join().expect("join holder");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}.lock", path));
    });
}
