//! Host-side computation of `withdrawal_root` and `deposit_root` from
//! L2 RPC transaction receipts. Mirror of
//! `crates/executor/client/src/events_hash.rs` but operates on
//! `alloy_rpc_types::TransactionReceipt` instead of `ExecutionOutcome`,
//! so callers can avoid full block re-execution.
//!
//! Used by the witness-orchestrator's challenge resolver to derive the
//! `withdrawalRoot` / `depositRoot` fields of `L2BlockHeader` directly
//! from `eth_getBlockReceipts(block)`.

use alloy_primitives::{keccak256, Address, B256};
use alloy_rpc_types::{Log, TransactionReceipt};

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

/// `keccak256(messageHashes[0] ‖ … ‖ messageHashes[N-1])`. Returns
/// `ZERO_BYTES_HASH` when no `ReceivedMessage` events occurred.
pub fn calculate_deposit_hash(
    receipts: &[TransactionReceipt],
    bridge_address: Address,
    receive_topic: B256,
) -> B256 {
    let mut buf: Vec<u8> = Vec::new();
    for receipt in receipts {
        if !receipt.status() {
            continue;
        }
        for log in receipt.inner.logs() {
            if log_address(log) != bridge_address {
                continue;
            }
            if log_topic0(log) != Some(receive_topic) {
                continue;
            }
            let data = log_data(log);
            if data.len() < RECEIVE_EVENT_MESSAGE_HASH_OFFSET + 32 {
                continue;
            }
            buf.extend_from_slice(&data[RECEIVE_EVENT_MESSAGE_HASH_OFFSET..][..32]);
        }
    }
    keccak256(buf)
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
    let mut hashes: Vec<B256> = Vec::new();
    for receipt in receipts {
        if !receipt.status() {
            continue;
        }
        for log in receipt.inner.logs() {
            if log_address(log) != bridge_address {
                continue;
            }
            let Some(topic) = log_topic0(log) else { continue };
            let data = log_data(log);
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
    }
    if hashes.is_empty() {
        return ZERO_BYTES_HASH;
    }
    batch_merkle::calculate_merkle_root(&hashes)
}

/// Count `ReceivedMessage` events from `bridge_address` in successful
/// receipts. Used to populate `L2BlockHeader.depositCount` for
/// `resolveBlockChallenge` calldata.
pub fn count_deposits(
    receipts: &[TransactionReceipt],
    bridge_address: Address,
    receive_topic: B256,
) -> u16 {
    let mut count: u16 = 0;
    for receipt in receipts {
        if !receipt.status() {
            continue;
        }
        for log in receipt.inner.logs() {
            if log_address(log) == bridge_address && log_topic0(log) == Some(receive_topic) {
                count = count.saturating_add(1);
            }
        }
    }
    count
}

fn log_address(log: &Log) -> Address {
    log.inner.address
}

fn log_topic0(log: &Log) -> Option<B256> {
    log.inner.topics().first().copied()
}

fn log_data(log: &Log) -> &[u8] {
    log.inner.data.data.as_ref()
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
