use super::*;

// ─── is_direct tests ─────────────────────────────────────────────

#[test]
fn is_direct_true_for_enabled_direct_user() {
    let user = User {
        name: "direct_alice".to_string(),
        hash: compute_hash("pw").unwrap(),
        is_enabled: true,
        direct: true,
        allowed_clients: None,
    };
    let state = build_state(vec![user], false);
    assert!(state.is_direct("direct_alice"));
}

#[test]
fn is_direct_false_for_pool_user() {
    let state = build_state(vec![make_user("alice", "pw", true)], false);
    assert!(!state.is_direct("alice"));
}

#[test]
fn is_direct_false_for_disabled_direct_user() {
    let user = User {
        name: "disabled_alice".to_string(),
        hash: compute_hash("pw").unwrap(),
        is_enabled: false,
        direct: true,
        allowed_clients: None,
    };
    let state = build_state(vec![user], false);
    assert!(!state.is_direct("disabled_alice"));
}

#[test]
fn is_direct_false_for_unknown_user() {
    let state = build_state(vec![make_user("alice", "pw", true)], false);
    assert!(!state.is_direct("unknown"));
}

#[test]
fn init_claim_concurrent_same_password_both_win() {
    // Two threads claim "bob" with the SAME password. Whichever
    // wins the write lock first records the hash; the loser falls
    // through to argon2_verify, which succeeds (same password) so
    // both return true.
    let (state, path) = build_state_persistent(vec![make_init_user("bob", true)], false);
    let state = Arc::new(state);
    let s1 = state.clone();
    let s2 = state.clone();
    let t1 = std::thread::spawn(move || s1.verify("bob", "samepw"));
    let t2 = std::thread::spawn(move || s2.verify("bob", "samepw"));
    let r1 = t1.join().unwrap();
    let r2 = t2.join().unwrap();
    assert!(r1 && r2);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn init_claim_racer_rechecks_after_claim_lock_and_does_not_clobber_winner() {
    // R6-01: two concurrent logins with the SAME correct password.
    // A helper thread pins the cross-process users-file lock in two
    // phases. Phase A parks the first claimer inside persist_claim,
    // so the second login queues on claim_lock behind it and both
    // pass the pre-mutex init check. Phase A ends on a SIGNAL from
    // this thread, not on a timer: it is released only once both
    // racers have been observed entering claim_commit. Phase B starts
    // 5 s after A is released — the winner only needs to notice the
    // file lock is free and grab it sometime in that window, which
    // costs real milliseconds once scheduled, but this machine can see
    // multi-second scheduling latency under heavy concurrent CPU
    // load from sibling cargo processes (same class as the Argon2id
    // degradation noted elsewhere in this file); a 200 ms gap was
    // observed to let the external holder win that race under load,
    // pushing the winner itself into a doomed persist attempt. Phase
    // B then holds for 11 s — one second past persist_claim's 10 s
    // UsersFileLock LOCK_TIMEOUT — so any persistence attempt by the
    // loser would time out exactly like the review's "another
    // process holds the lock past its timeout" scenario. The fixed
    // loser must re-check the init state AFTER acquiring claim_lock,
    // verify against the winner's hash, and return without ever
    // entering persistence.
    // The deterministic companion test below scripts the winner's commit directly.
    use std::sync::mpsc;
    use std::time::Duration;

    let (mut state, path) = build_state_persistent(vec![make_init_user("bob", true)], false);
    let (claim_tx, mut claim_rx) = mpsc::channel::<&'static str>();
    state.install_claim_probe(claim_tx);
    let state = Arc::new(state);

    let (locked_tx, locked_rx) = mpsc::channel::<()>();
    let (release_a_tx, release_a_rx) = mpsc::channel::<()>();
    let holder_path = path.clone();
    let holder = std::thread::spawn(move || {
        let phase_a =
            UsersFileLock::acquire_with_timeout(Path::new(&holder_path), Duration::from_secs(5))
                .expect("holder must acquire the users-file lock (phase A)");
        locked_tx.send(()).expect("signal phase-A lock held");
        // Phase A ends on a signal, never on a timer. The window it
        // holds open is the entire point of the test: the winner
        // cannot publish its hash while its persist is parked here,
        // and only an unpublished hash keeps the loser out of
        // prepare_claim's pre-mutex fast path. A fixed 3 s sleep
        // silently made the test require the loser's ABSOLUTE
        // Argon2id time to fit inside that sleep. Under concurrent
        // CPU load hashing degrades from ~15 ms to seconds, the loser
        // then found a published hash, resolved inline, never entered
        // claim_commit at all, and the wait below timed out on an
        // event that could no longer ever arrive — a hard failure, in
        // ~50% of loaded full-suite runs, that looked like flakiness
        // but was this ordering assumption. Releasing on the probe
        // instead reduces the requirement to the DIFFERENCE between
        // the two racers' hashes, which load barely affects since
        // both hash concurrently.
        let _ = release_a_rx.recv();
        drop(phase_a); // the winner's persist completes in the gap below
        std::thread::sleep(Duration::from_secs(5));
        let phase_b =
            UsersFileLock::acquire_with_timeout(Path::new(&holder_path), Duration::from_secs(5))
                .expect("holder must re-acquire the users-file lock (phase B)");
        let _ = &phase_b;
        // Held past persist_claim's 10 s LOCK_TIMEOUT: a persistence
        // attempt in this window cannot succeed. The fixed loser
        // never attempts one; this hold only makes the pre-fix
        // failure mode (persist Failed → sentinel reset → winner
        // clobbered) slow and loud if the re-check ever regresses.
        std::thread::sleep(Duration::from_secs(11));
    });
    locked_rx.recv().expect("phase-A lock held");

    // Detached on purpose: the 11 s phase-B hold only matters for
    // the counterfactual persistence attempt; the fixed path is done
    // in ~3.5 s and joining would pay that hold on every test run.
    // The unique per-test path keeps the pin invisible to other
    // tests; the OS releases the lock when the process exits.
    drop(holder);

    let s1 = Arc::clone(&state);
    let s2 = Arc::clone(&state);
    let t1 = std::thread::spawn(move || s1.verify("bob", "same-pw"));
    let t2 = std::thread::spawn(move || s2.verify("bob", "same-pw"));
    // R7-04: anchor to the probe, not to hope. BOTH racers must
    // reach claim_commit — each emits claim_commit_entered as the
    // first statement of claim_commit, so a racer that resolved via
    // the pre-mutex fast path never emits a second event and this
    // fails loudly instead of letting the test pass without ever
    // exercising the post-mutex re-check. Events are COLLECTED, not
    // merely awaited: the winner's persist_region_entered
    // legitimately interleaves with the two, and the persistence
    // check below counts it. The guard is generous because it now
    // bounds only "did the seam fire at all" — phase A stays held
    // until this returns, so no amount of Argon2id slowness can make
    // the awaited event unreachable the way a fixed sleep could.
    let mut events = Vec::new();
    collect_claim_events_until(
        &mut claim_rx,
        &mut events,
        "claim_commit_entered",
        2,
        Duration::from_secs(60),
        "both claimants reaching claim_commit (neither may resolve via \
         the pre-mutex fast path)",
    );
    // Both racers are now past the fast-path check — one holding
    // claim_lock, one queued on it — so releasing phase A can no
    // longer let the winner publish ahead of the loser's check.
    release_a_tx.send(()).expect("release phase A");

    let r1 = t1.join().unwrap();
    let r2 = t2.join().unwrap();
    assert!(r1, "the winning login must succeed");
    assert!(r2, "the loser must verify against the winner's hash");

    // Whatever the racers emitted after the collection above returned.
    while let Ok(event) = claim_rx.try_recv() {
        events.push(event);
    }
    // The authoritative "no persistence detour" check. It replaces an
    // earlier wall-clock bound (<12 s per racer) that only INFERRED
    // the same thing from elapsed time and therefore had to assume
    // how slow Argon2id may get. persist_region_entered fires
    // immediately before the call into persist_claim, so counting it
    // measures the property directly: exactly one racer — the winner
    // — may enter the persist region, while the fixed loser re-checks
    // after claim_lock and returns without ever reaching it.
    let persist_entries = events
        .iter()
        .filter(|event| **event == "persist_region_entered")
        .count();
    assert_eq!(
        persist_entries, 1,
        "exactly one racer (the winner) may enter the persist region, \
         saw {persist_entries}; probe events: {events:?}"
    );

    // Final state: the winner's commit is intact everywhere and
    // memory, disk and cache agree on one and the same hash.
    let winner_hash = {
        let users = state.users.read().unwrap();
        let bob = users.iter().find(|u| u.name == "bob").unwrap();
        assert!(
            bob.hash.starts_with("$argon2id$"),
            "winner's committed hash must not be reset to the sentinel, got {:?}",
            bob.hash
        );
        bob.hash.clone()
    };
    let loaded: UsersConfig = ktav::from_file(&path).unwrap();
    let bob = loaded.users.iter().find(|u| u.name == "bob").unwrap();
    assert_eq!(bob.hash, winner_hash, "disk and memory must agree");
    assert!(
        state.verify("bob", "same-pw"),
        "winner hash must still verify"
    );
    assert!(
        state.cache_matches(
            "bob",
            &compute_cache_hmac(&state.server_secret, "bob", "same-pw")
        ),
        "cache must hold the entry for the winning password"
    );

    // A fresh state on the persisted file accepts the same password:
    // both logins verified against one and the same winning hash.
    let fresh = AuthState::build(
        &AuthConfig {
            allow_anonymous: false,
        },
        &loaded,
        path.clone(),
    )
    .unwrap();
    assert!(fresh.verify("bob", "same-pw"));

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{}.lock", path));
}

#[test]
fn init_claim_persist_failure_after_winner_cannot_reset_winner_hash() {
    // R6-01, deterministic variant. A real two-thread race cannot
    // reliably expose the pre-fix bug: the loser's persist enters
    // only after the winner released the file lock, so on a fast
    // machine it slips in, sees the winner's hash on disk, and
    // returns via DiskHashChanged without any clobber. Here the
    // winner's committed state (memory + disk) is scripted directly
    // while the racer is parked on claim_lock, and the cross-process
    // users-file lock is pinned continuously for longer than
    // persist_claim's 10 s UsersFileLock LOCK_TIMEOUT from before
    // the racer can reach persistence — so a pre-fix racer (no
    // post-mutex re-check) deterministically blocks for the full
    // 10 s, fails, and returns false, while the fixed racer
    // re-checks after the mutex and never touches persistence.
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    let (mut state, path) = build_state_with_disk_file(vec![make_init_user("bob", true)], false);
    let (claim_tx, mut claim_rx) = mpsc::channel::<&'static str>();
    state.install_claim_probe(claim_tx);
    let state = Arc::new(state);
    let winner_hash = compute_hash("winner-pw").unwrap();

    // Pin the users-file lock continuously, well past the 10 s
    // persist LOCK_TIMEOUT, for the whole scenario.
    let (locked_tx, locked_rx) = mpsc::channel::<()>();
    let holder_path = path.clone();
    let holder = std::thread::spawn(move || {
        let lock =
            UsersFileLock::acquire_with_timeout(Path::new(&holder_path), Duration::from_secs(5))
                .expect("holder must acquire the users-file lock");
        locked_tx.send(()).expect("signal lock held");
        std::thread::sleep(Duration::from_secs(14));
        let _ = &lock;
    });
    locked_rx.recv().expect("users-file lock pinned");

    // Hold claim_lock from before the racer starts so the racer is
    // guaranteed to park on this mutex right after its pre-mutex
    // init check. R7-04: wait for the probe event proving the racer
    // actually REACHED claim_commit — its first statement emits
    // claim_commit_entered — instead of sleeping a fixed 2 s and
    // hoping its Argon2id hashing finished: under real CPU load that
    // stretch is seconds, not the ~15 ms nominal, so no fixed sleep
    // can prove arrival. The parent still holds claim_lock here, so
    // after the event the racer is necessarily parked on the mutex
    // and cannot pass the post-mutex re-check until the winner's
    // state is injected and this guard is dropped. 15 s guard: the
    // arrival needs one real Argon2id hash (see the machine-load
    // note).
    let claim_guard = state.claim_lock.lock().expect("claim mutex poisoned");
    let racer_state = Arc::clone(&state);
    let racer = std::thread::spawn(move || {
        let started = Instant::now();
        (racer_state.verify("bob", "winner-pw"), started.elapsed())
    });
    wait_for_claim_event(
        &mut claim_rx,
        "claim_commit_entered",
        Duration::from_secs(15),
        "the racer reaching claim_commit (past its pre-mutex check)",
    );

    // Script the winner's commit exactly as the Written branch would
    // leave it: real hash in memory and on disk. The cache is
    // deliberately left empty — populating it is part of what the
    // racer's claimed-hash path must do.
    {
        let mut users = state.users.write().unwrap();
        let bob = users.iter_mut().find(|u| u.name == "bob").unwrap();
        bob.hash = winner_hash.clone();
    }
    ktav::to_file(
        &UsersConfig {
            users: vec![User {
                name: "bob".into(),
                hash: winner_hash.clone(),
                is_enabled: true,
                direct: false,
                allowed_clients: None,
            }],
        },
        &path,
    )
    .unwrap();

    drop(claim_guard); // let the racer into the claim critical section

    let (racer_ok, racer_elapsed) = racer.join().unwrap();
    assert!(racer_ok, "racer must verify against the winner's hash");
    // R7-04 negative check: the racer's claim_commit_entered was
    // already consumed by the wait above, so after the winner-state
    // injection and the re-check resolution the probe channel must
    // hold NOTHING — in particular no persist_region_entered, which
    // would mean the racer entered persistence for a hash it never
    // published.
    assert!(
        matches!(claim_rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "racer emitted a further claim event after the winner-state \
         injection — it entered the guarded persist region"
    );
    // Any persistence attempt blocks ≥10 s against the pinned lock
    // (persist_claim → UsersFileLock::acquire → LOCK_TIMEOUT), so a
    // sub-9 s total proves the racer never entered persistence. The
    // bound sits in the ~8 s class on purpose (see the machine-load
    // note): the fixed path runs TWO real Argon2id operations (the
    // candidate hash and the verify against the winner's hash), and
    // each has been observed to stretch into multiple seconds under
    // concurrent CPU load — the bound is a generous safety margin,
    // while the probe assertions above are the discriminator. The
    // final-state asserts below are authoritative.
    assert!(
        racer_elapsed < Duration::from_secs(9),
        "racer elapsed {racer_elapsed:?} — it entered persistence and \
         waited out the pinned users-file lock"
    );

    // The winner's commit is intact everywhere: memory hash not
    // reset to the sentinel, disk untouched, and the cache now holds
    // the winning password's entry — populated by the racer's
    // claimed-hash verify path.
    {
        let users = state.users.read().unwrap();
        let bob = users.iter().find(|u| u.name == "bob").unwrap();
        assert_eq!(
            bob.hash, winner_hash,
            "winner's committed hash must not be reset to the sentinel"
        );
    }
    let loaded: UsersConfig = ktav::from_file(&path).unwrap();
    assert_eq!(loaded.users[0].hash, winner_hash, "disk must be untouched");
    assert!(
        state.cache_matches(
            "bob",
            &compute_cache_hmac(&state.server_secret, "bob", "winner-pw")
        ),
        "cache must hold the winning password's entry"
    );

    // Detached on purpose (same reasoning as the concurrent racer
    // test above): the remaining pin hold only matters for the
    // pre-fix counterfactual.
    drop(holder);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{}.lock", path));
}

#[test]
fn init_claim_into_missing_file_writes_full_fallback_list() {
    // R6-05: the fallback snapshot is now built only for the
    // missing-file branch, after claim_lock and the post-mutex
    // re-check — but the branch's content contract is unchanged:
    // creating the file writes the caller's FULL in-memory list
    // (with the claimed hash applied), not just the claimed user.
    let (state, path) = build_state_persistent(
        vec![
            make_user("alice", "alice-pw", true),
            make_init_user("bob", true),
        ],
        false,
    );
    assert!(!Path::new(&path).exists());
    assert!(state.verify("bob", "bob-pw"));

    let loaded: UsersConfig = ktav::from_file(&path).unwrap();
    assert_eq!(loaded.users.len(), 2, "fallback must carry every user");
    let alice = loaded.users.iter().find(|u| u.name == "alice").unwrap();
    assert!(
        alice.hash.starts_with("$argon2id$"),
        "alice's real hash must survive the first-claim file creation"
    );
    let bob = loaded.users.iter().find(|u| u.name == "bob").unwrap();
    assert_ne!(bob.hash, INIT_HASH);
    assert!(bob.hash.starts_with("$argon2id$"));
    // Both accounts work against the freshly created file.
    assert!(state.verify("alice", "alice-pw"));

    let _ = std::fs::remove_file(&path);
}

// ─── cross-process safety: CLI edits vs init-claim (R13) ────────

#[test]
fn init_claim_preserves_concurrent_cli_edit_to_other_users() {
    // Server snapshot is [alice enabled, bob init]; a CLI process
    // then disables alice and adds carol ON DISK; finally bob
    // claims. The claim must merge into the on-disk truth, not
    // overwrite it with the stale snapshot.
    let baseline = vec![
        make_user("alice", "alice-pw", true),
        make_init_user("bob", true),
    ];
    let (state, path) = build_state_with_disk_file(baseline.clone(), false);

    // Simulated CLI edit (separate process writing the file).
    let cli_edit = vec![
        User {
            is_enabled: false,
            ..baseline[0].clone()
        },
        make_init_user("bob", true),
        make_init_user("carol", true),
    ];
    ktav::to_file(&UsersConfig { users: cli_edit }, &path).unwrap();

    assert!(state.verify("bob", "bob-pw"));

    let loaded: UsersConfig = ktav::from_file(&path).unwrap();
    assert_eq!(loaded.users.len(), 3, "CLI-added user must survive");
    let alice = loaded.users.iter().find(|u| u.name == "alice").unwrap();
    assert!(!alice.is_enabled, "CLI disable must survive the claim");
    let carol = loaded.users.iter().find(|u| u.name == "carol").unwrap();
    assert_eq!(carol.hash, INIT_HASH);
    let bob = loaded.users.iter().find(|u| u.name == "bob").unwrap();
    assert_ne!(bob.hash, INIT_HASH);
    assert!(bob.hash.starts_with("$argon2id$"));

    // A server restarted on the merged file sees the CLI's edits too.
    let fresh = AuthState::build(
        &AuthConfig {
            allow_anonymous: false,
        },
        &loaded,
        path.clone(),
    )
    .unwrap();
    assert!(fresh.verify("bob", "bob-pw"));
    assert!(
        !fresh.verify("alice", "alice-pw"),
        "alice must still be disabled on disk"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn init_claim_yields_to_cli_password_change_for_same_user() {
    // R13, same-user variant: the CLI set a real password for bob
    // while the server still believed bob was unclaimed. The claim
    // must adopt the on-disk hash, not overwrite it.
    let (state, path) = build_state_with_disk_file(vec![make_init_user("bob", true)], false);
    let cli_hash = compute_hash("cli-pw").unwrap();
    ktav::to_file(
        &UsersConfig {
            users: vec![User {
                name: "bob".into(),
                hash: cli_hash.clone(),
                is_enabled: true,
                direct: false,
                allowed_clients: None,
            }],
        },
        &path,
    )
    .unwrap();

    // The client submits the password the CLI installed.
    assert!(state.verify("bob", "cli-pw"));

    // The CLI's hash is still on disk, byte-for-byte.
    let loaded: UsersConfig = ktav::from_file(&path).unwrap();
    assert_eq!(loaded.users[0].hash, cli_hash);

    // In-memory state adopted it too — wrong passwords now take the
    // normal rejection path and never rewrite the file.
    assert!(!state.verify("bob", "wrong"));
    let reloaded: UsersConfig = ktav::from_file(&path).unwrap();
    assert_eq!(reloaded.users[0].hash, cli_hash);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn init_claim_fails_when_user_removed_from_disk_by_cli() {
    // R13, removal variant: CLI deleted bob from the file while the
    // server's snapshot still had him. The claim must fail closed —
    // not resurrect bob by writing the stale snapshot back.
    let baseline = vec![
        make_user("alice", "alice-pw", true),
        make_init_user("bob", true),
    ];
    let (state, path) = build_state_with_disk_file(baseline.clone(), false);

    let cli_edit = vec![baseline[0].clone()]; // bob removed
    ktav::to_file(&UsersConfig { users: cli_edit }, &path).unwrap();

    assert!(!state.verify("bob", "anything"));

    // In-memory hash reverted to the sentinel so state stays
    // consistent with disk.
    {
        let users = state.users.read().unwrap();
        let bob = users.iter().find(|u| u.name == "bob").unwrap();
        assert_eq!(bob.hash, INIT_HASH);
    }

    // On-disk file untouched: still exactly the CLI's version.
    let loaded: UsersConfig = ktav::from_file(&path).unwrap();
    assert_eq!(loaded.users.len(), 1);
    assert_eq!(loaded.users[0].name, "alice");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn init_claim_write_failure_leaves_previous_disk_file_intact() {
    // R12 through the claim path: the persist starts but fails
    // mid-way (the temp-file slot is sabotaged with a directory).
    // The previous on-disk file must survive byte-for-byte and the
    // in-memory sentinel must be left in place for a retry.
    let baseline = vec![
        make_user("alice", "alice-pw", true),
        make_init_user("bob", true),
    ];
    let (state, path) = build_state_with_disk_file(baseline, false);
    let before = std::fs::read_to_string(&path).unwrap();

    let tmp = PathBuf::from(format!("{}.tmp", path));
    std::fs::create_dir(&tmp).unwrap();

    assert!(!state.verify("bob", "pw"));

    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        before,
        "failed persist must leave the previous file intact"
    );
    {
        let users = state.users.read().unwrap();
        let bob = users.iter().find(|u| u.name == "bob").unwrap();
        assert_eq!(
            bob.hash, INIT_HASH,
            "sentinel must still be in place — the failed attempt never published anything"
        );
    }

    std::fs::remove_dir(&tmp).unwrap();
    let _ = std::fs::remove_file(&path);
}
