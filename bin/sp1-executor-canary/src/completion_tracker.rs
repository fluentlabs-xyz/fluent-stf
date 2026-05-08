//! Strict-prefix completion tracker.
//!
//! SP1 workers complete blocks out of order (worker A may finish block
//! 100 while worker B is still on block 50). The SQLite resume cursor
//! and the driver's `consumer_tip` watermark must advance only by the
//! strict prefix of completed blocks — i.e. the highest `N` such that
//! every block in `[start..=N]` has been processed. Otherwise a crash
//! after writing a "max-based" cursor would skip the unfinished blocks
//! below it on restart.
//!
//! Implementation: `next_expected` tracks the next block we have not
//! yet seen complete; `out_of_order` holds completed blocks that sit
//! above the gap. When a completion fills the gap, the watermark
//! advances and may cascade through any `out_of_order` blocks that
//! were waiting on it.

use std::collections::BTreeSet;

pub(crate) struct CompletionTracker {
    next_expected: u64,
    out_of_order: BTreeSet<u64>,
}

impl CompletionTracker {
    /// `start_cursor` is the first block the canary will process — i.e.
    /// `last_canaried_block + 1` on restart.
    pub(crate) fn new(start_cursor: u64) -> Self {
        Self { next_expected: start_cursor, out_of_order: BTreeSet::new() }
    }

    /// Mark `block` as completed. Returns the new strict-prefix
    /// watermark (highest fully-canaried block) if it advanced, else
    /// `None`. Watermark = `next_expected - 1` after the update.
    pub(crate) fn mark_done(&mut self, block: u64) -> Option<u64> {
        if block < self.next_expected {
            return None;
        }
        if block != self.next_expected {
            self.out_of_order.insert(block);
            return None;
        }
        self.next_expected += 1;
        while let Some(&next) = self.out_of_order.iter().next() {
            if next == self.next_expected {
                self.out_of_order.remove(&next);
                self.next_expected += 1;
            } else {
                break;
            }
        }
        Some(self.next_expected - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_order_advances_watermark_on_each_block() {
        let mut t = CompletionTracker::new(100);
        assert_eq!(t.mark_done(100), Some(100));
        assert_eq!(t.mark_done(101), Some(101));
        assert_eq!(t.mark_done(102), Some(102));
    }

    #[test]
    fn out_of_order_holds_until_gap_fills() {
        let mut t = CompletionTracker::new(100);
        assert_eq!(t.mark_done(102), None);
        assert_eq!(t.mark_done(103), None);
        assert_eq!(t.mark_done(101), None);
        assert_eq!(t.mark_done(100), Some(103));
    }

    #[test]
    fn duplicate_completion_below_next_expected_is_ignored() {
        let mut t = CompletionTracker::new(100);
        assert_eq!(t.mark_done(100), Some(100));
        assert_eq!(t.mark_done(100), None);
    }

    #[test]
    fn watermark_cascades_through_dense_out_of_order() {
        let mut t = CompletionTracker::new(0);
        for n in [3, 1, 4, 2, 5] {
            t.mark_done(n);
        }
        assert_eq!(t.mark_done(0), Some(5));
    }
}
