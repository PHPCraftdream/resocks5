//! Private counters #208; linked only in unit tests with instrumentation.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Counts {
    pub alloc: u64,
    pub alloc_zeroed: u64,
    pub realloc: u64,
    pub dealloc: u64,
    /// Requested bytes, not RSS and not allocator block sizes.
    pub requested_bytes: u64,
    pub config_clones: u64,
    pub chain_builds: u64,
    pub gate_formats: u64,
    pub chain_nodes: u64,
    pub hash_nodes: u64,
    pub resolve_comparisons: u64,
    pub weighted_keys: u64,
    pub sort_comparisons: u64,
    pub mark_dead_calls: u64,
    pub mark_dead_layer_visits: u64,
    pub mark_dead_membership_checks: u64,
    pub singleton_dedup_comparisons: u64,
    pub singleton_candidates_inserted: u64,
    pub singleton_candidates_skipped: u64,
    pub singleton_emitted_inserts: u64,
    pub singleton_emitted_duplicates: u64,
    pub singleton_cursor_candidates: u64,
    pub singleton_cursor_comparisons: u64,
    pub mark_dead_cursor_visits: u64,
    pub mark_dead_index_lookups: u64,
    pub mark_dead_eligible_checks: u64,
    pub chain_plan_steps: u64,
}

thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static COUNTS: Cell<Counts> = const { Cell::new(Counts {
        alloc: 0,
        alloc_zeroed: 0,
        realloc: 0,
        dealloc: 0,
        requested_bytes: 0,
        config_clones: 0,
        chain_builds: 0,
        gate_formats: 0,
        chain_nodes: 0,
        hash_nodes: 0,
        resolve_comparisons: 0,
        weighted_keys: 0,
        sort_comparisons: 0,
        mark_dead_calls: 0,
        mark_dead_layer_visits: 0,
        mark_dead_membership_checks: 0,
        singleton_dedup_comparisons: 0,
        singleton_candidates_inserted: 0,
        singleton_candidates_skipped: 0,
        singleton_emitted_inserts: 0,
        singleton_emitted_duplicates: 0,
        singleton_cursor_candidates: 0,
        singleton_cursor_comparisons: 0,
        mark_dead_cursor_visits: 0,
        mark_dead_index_lookups: 0,
        mark_dead_eligible_checks: 0,
        chain_plan_steps: 0,
    }) };
}

pub(crate) fn operation(update: impl FnOnce(&mut Counts)) {
    let _ = ACTIVE.try_with(|active| {
        if active.get() {
            let _ = COUNTS.try_with(|cell| {
                let mut counts = cell.get();
                update(&mut counts);
                cell.set(counts);
            });
        }
    });
}

struct CountingSystem;

#[global_allocator]
static ALLOCATOR: CountingSystem = CountingSystem;

// SAFETY: all calls and layouts are passed to System unchanged; accounting does not allocate.
unsafe impl GlobalAlloc for CountingSystem {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        operation(|c| {
            c.alloc = c.alloc.saturating_add(1);
            c.requested_bytes = c.requested_bytes.saturating_add(layout.size() as u64);
        });
        // SAFETY: layout satisfies the GlobalAlloc::alloc contract.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        operation(|c| {
            c.alloc_zeroed = c.alloc_zeroed.saturating_add(1);
            c.requested_bytes = c.requested_bytes.saturating_add(layout.size() as u64);
        });
        // SAFETY: layout satisfies the GlobalAlloc::alloc_zeroed contract.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        operation(|c| c.dealloc = c.dealloc.saturating_add(1));
        // SAFETY: ptr and layout of the original block are passed by the caller.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        operation(|c| {
            c.realloc = c.realloc.saturating_add(1);
            c.requested_bytes = c.requested_bytes.saturating_add(new_size as u64);
        });
        // SAFETY: original block and new_size satisfy GlobalAlloc::realloc.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

struct Scope;

impl Drop for Scope {
    fn drop(&mut self) {
        ACTIVE.with(|active| active.set(false));
    }
}

/// Synchronous work only: the scope must not cross await or move to another thread.
pub(crate) fn measure<T>(work: impl FnOnce() -> T) -> (T, Counts) {
    ACTIVE.with(|active| assert!(!active.get(), "nested perf scope"));
    COUNTS.with(|cell| cell.set(Counts::default()));
    ACTIVE.with(|active| active.set(true));
    let scope = Scope;
    let result = std::hint::black_box(work());
    drop(scope);
    let counts = COUNTS.with(Cell::get);
    (result, counts)
}

pub(crate) fn report(name: &str, counts: Counts) {
    println!("\nPERF208 {name} {counts:?}");
}

#[test]
fn perf208_allocator_calibration_and_scope_cleanup() {
    let (_, empty) = measure(|| std::hint::black_box(()));
    assert_eq!(empty, Counts::default());
    let (block, counts) = measure(|| std::hint::black_box(Box::new([7u8; 128])));
    assert_eq!(counts.alloc, 1);
    assert_eq!(counts.requested_bytes, 128);
    let (_, freed) = measure(|| drop(block));
    assert_eq!(freed.dealloc, 1);
    let (mut bytes, zeroed) = measure(|| std::hint::black_box(vec![0u8; 32]));
    assert_eq!(zeroed.alloc + zeroed.alloc_zeroed, 1);
    assert_eq!(zeroed.requested_bytes, 32);
    let (_, grown) = measure(|| {
        bytes.reserve_exact(std::hint::black_box(32));
        std::hint::black_box(&bytes);
    });
    assert_eq!(grown.realloc, 1);
    assert_eq!(grown.requested_bytes, 64);
    assert!(std::panic::catch_unwind(|| measure(|| panic!("scope cleanup"))).is_err());
    let (_, after_panic) = measure(|| ());
    assert_eq!(after_panic, Counts::default());
    let (_, own_thread) = measure(|| operation(|c| c.chain_builds += 1));
    assert_eq!(own_thread.chain_builds, 1);
}

#[test]
fn perf208_scopes_are_thread_local() {
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            barrier.wait();
            let block = std::hint::black_box(Box::new([1u8; 128]));
            operation(|c| c.chain_builds += 99);
            drop(block);
            barrier.wait();
        });
        let (_, counts) = measure(|| {
            barrier.wait();
            barrier.wait();
        });
        worker.join().unwrap();
        // Barrier may initialize a platform wait; we check our own marker.
        assert_eq!(counts.chain_builds, 0);
    });
}
