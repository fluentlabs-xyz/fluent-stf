//! Host-side computation of `withdrawal_root` and `deposit_root` from
//! block log streams. The pure-inner functions operate on
//! `&alloy_primitives::Log` (the shape every receipt type ultimately
//! exposes), so they can be driven from either alloy RPC receipts or
//! reth's MDBX-shaped receipts.
//!
//! Used by the witness-orchestrator's challenge resolver to derive the
//! `withdrawalRoot` / `depositRoot` fields of `L2BlockHeader`. Mirror of
//! `crates/executor/client/src/events_hash.rs`, but operates over receipt
//! collections instead of `ExecutionOutcome`, so callers avoid full
//! block re-execution.

use alloy_primitives::{keccak256, Address, B256};
use alloy_rpc_types::TransactionReceipt;

/// keccak256 of empty input. Used as the convention "no events"
/// placeholder for the merkle-root output of an empty leaf set.
/// Matches `crates/executor/client/src/events_hash.rs::ZERO_BYTES_HASH`.
const ZERO_BYTES_HASH: B256 = B256::new([
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
]);

// Offsets into the (non-indexed) ABI-encoded log data, in bytes.
const RECEIVE_EVENT_MESSAGE_HASH_OFFSET: usize = 0;
const SEND_EVENT_MESSAGE_HASH_OFFSET: usize = 160;
const ROLLBACK_EVENT_MESSAGE_HASH_OFFSET: usize = 0;
// Legacy `BridgeWithdrawal` event uses a different layout.
const LEGACY_SEND_EVENT_MESSAGE_HASH_OFFSET: usize = 128;

/// `keccak256(messageHashes[0] ‖ … ‖ messageHashes[N-1])` over an
/// arbitrary stream of bare logs already filtered to "from successful
/// receipts". Returns `ZERO_BYTES_HASH` when no `ReceivedMessage`
/// events occurred.
pub fn calculate_deposit_hash_inner<'a>(
    logs: impl Iterator<Item = &'a alloy_primitives::Log>,
    bridge_address: Address,
    receive_topic: B256,
) -> B256 {
    let mut buf: Vec<u8> = Vec::new();
    for log in logs {
        if log.address != bridge_address {
            continue;
        }
        let Some(topic) = log.data.topics().first().copied() else { continue };
        if topic != receive_topic {
            continue;
        }
        let data = log.data.data.as_ref();
        if data.len() < RECEIVE_EVENT_MESSAGE_HASH_OFFSET + 32 {
            continue;
        }
        buf.extend_from_slice(&data[RECEIVE_EVENT_MESSAGE_HASH_OFFSET..][..32]);
    }
    keccak256(buf)
}

/// `keccak256(messageHashes[0] ‖ … ‖ messageHashes[N-1])`. Returns
/// `ZERO_BYTES_HASH` when no `ReceivedMessage` events occurred.
pub fn calculate_deposit_hash(
    receipts: &[TransactionReceipt],
    bridge_address: Address,
    receive_topic: B256,
) -> B256 {
    calculate_deposit_hash_inner(successful_receipt_logs(receipts), bridge_address, receive_topic)
}

/// Stream of bare logs from successful receipts — the shape every
/// `*_inner` helper takes.
fn successful_receipt_logs(
    receipts: &[TransactionReceipt],
) -> impl Iterator<Item = &alloy_primitives::Log> {
    receipts.iter().filter(|r| r.status()).flat_map(|r| r.inner.logs().iter().map(|l| &l.inner))
}

/// Merkle root over all `SentMessage` (and legacy / rollback) log
/// `messageHash` values from the bridge address, fed as a stream of bare
/// logs already filtered to "from successful receipts". Returns
/// `ZERO_BYTES_HASH` when no such events occurred.
pub fn calculate_withdrawal_root_inner<'a>(
    logs: impl Iterator<Item = &'a alloy_primitives::Log>,
    bridge_address: Address,
    send_topic: B256,
    legacy_withdrawal_topic: B256,
    rollback_topic: B256,
) -> B256 {
    let mut hashes: Vec<B256> = Vec::new();
    for log in logs {
        if log.address != bridge_address {
            continue;
        }
        let Some(topic) = log.data.topics().first().copied() else { continue };
        let data = log.data.data.as_ref();
        let off = if topic == send_topic {
            Some(SEND_EVENT_MESSAGE_HASH_OFFSET)
        } else if topic == legacy_withdrawal_topic {
            Some(LEGACY_SEND_EVENT_MESSAGE_HASH_OFFSET)
        } else if topic == rollback_topic {
            Some(ROLLBACK_EVENT_MESSAGE_HASH_OFFSET)
        } else {
            None
        };
        let Some(off) = off else { continue };
        if data.len() < off + 32 {
            continue;
        }
        hashes.push(B256::from_slice(&data[off..][..32]));
    }
    if hashes.is_empty() {
        return ZERO_BYTES_HASH;
    }
    batch_merkle::calculate_merkle_root(&hashes)
}

/// Merkle root over all `SentMessage` (and legacy / rollback) log
/// `messageHash` values from the bridge address. Returns
/// `ZERO_BYTES_HASH` when no such events occurred.
pub fn calculate_withdrawal_root(
    receipts: &[TransactionReceipt],
    bridge_address: Address,
    send_topic: B256,
    legacy_withdrawal_topic: B256,
    rollback_topic: B256,
) -> B256 {
    calculate_withdrawal_root_inner(
        successful_receipt_logs(receipts),
        bridge_address,
        send_topic,
        legacy_withdrawal_topic,
        rollback_topic,
    )
}

/// Count `ReceivedMessage` events from `bridge_address` in a stream of
/// bare logs already filtered to "from successful receipts". Used to
/// populate `L2BlockHeader.depositCount` for `resolveBlockChallenge`
/// calldata.
pub fn count_deposits_inner<'a>(
    logs: impl Iterator<Item = &'a alloy_primitives::Log>,
    bridge_address: Address,
    receive_topic: B256,
) -> u16 {
    let mut count: u16 = 0;
    for log in logs {
        if log.address != bridge_address {
            continue;
        }
        if log.data.topics().first().copied() == Some(receive_topic) {
            count = count.saturating_add(1);
        }
    }
    count
}

/// Count `ReceivedMessage` events from `bridge_address` in successful
/// receipts.
pub fn count_deposits(
    receipts: &[TransactionReceipt],
    bridge_address: Address,
    receive_topic: B256,
) -> u16 {
    count_deposits_inner(successful_receipt_logs(receipts), bridge_address, receive_topic)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_bytes_hash_matches_keccak_empty() {
        assert_eq!(ZERO_BYTES_HASH, keccak256([]));
    }

    #[test]
    fn deposit_hash_empty_returns_zero_bytes_hash() {
        let bridge = Address::ZERO;
        let topic = B256::ZERO;
        assert_eq!(calculate_deposit_hash(&[], bridge, topic), ZERO_BYTES_HASH);
    }

    #[test]
    fn withdrawal_root_empty_returns_zero_bytes_hash() {
        let bridge = Address::ZERO;
        let topic = B256::ZERO;
        assert_eq!(
            calculate_withdrawal_root(&[], bridge, topic, B256::ZERO, B256::ZERO),
            ZERO_BYTES_HASH
        );
    }
}
