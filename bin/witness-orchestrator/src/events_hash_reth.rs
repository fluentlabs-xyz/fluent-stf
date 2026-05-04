//! Bridge-event hashing over MDBX-shaped receipts. Forwards into the
//! pure-inner functions in `rsp_host_executor::events_hash` so this
//! shell only deals with the per-receipt status check + log-extraction
//! shape.

use alloy_primitives::{Address, B256};
use rsp_host_executor::events_hash::{
    calculate_deposit_hash_inner, calculate_withdrawal_root_inner, count_deposits_inner,
};

pub(crate) fn calculate_withdrawal_root_from_reth_receipts(
    receipts: &[reth_ethereum_primitives::Receipt],
    bridge_address: Address,
    send_topic: B256,
    legacy_withdrawal_topic: B256,
    rollback_topic: B256,
) -> B256 {
    calculate_withdrawal_root_inner(
        successful_reth_receipt_logs(receipts),
        bridge_address,
        send_topic,
        legacy_withdrawal_topic,
        rollback_topic,
    )
}

pub(crate) fn calculate_deposit_hash_from_reth_receipts(
    receipts: &[reth_ethereum_primitives::Receipt],
    bridge_address: Address,
    receive_topic: B256,
) -> B256 {
    calculate_deposit_hash_inner(
        successful_reth_receipt_logs(receipts),
        bridge_address,
        receive_topic,
    )
}

pub(crate) fn count_deposits_from_reth_receipts(
    receipts: &[reth_ethereum_primitives::Receipt],
    bridge_address: Address,
    receive_topic: B256,
) -> u16 {
    count_deposits_inner(successful_reth_receipt_logs(receipts), bridge_address, receive_topic)
}

/// Stream of bare logs from successful reth receipts — the shape every
/// `*_inner` helper in `rsp_host_executor::events_hash` takes.
fn successful_reth_receipt_logs(
    receipts: &[reth_ethereum_primitives::Receipt],
) -> impl Iterator<Item = &alloy_primitives::Log> {
    receipts.iter().filter(|r| r.success).flat_map(|r| r.logs.iter())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{keccak256, Bytes, LogData};
    use reth_ethereum_primitives::Receipt;

    const ZERO_BYTES_HASH: B256 = B256::new([
        0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03,
        0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85,
        0xa4, 0x70,
    ]);

    fn mk_log(address: Address, topic: B256, data: Vec<u8>) -> alloy_primitives::Log {
        alloy_primitives::Log {
            address,
            data: LogData::new_unchecked(vec![topic], Bytes::from(data)),
        }
    }

    #[test]
    fn deposit_hash_empty_returns_zero_bytes_hash() {
        let bridge = Address::ZERO;
        let topic = B256::ZERO;
        assert_eq!(calculate_deposit_hash_from_reth_receipts(&[], bridge, topic), ZERO_BYTES_HASH);
    }

    #[test]
    fn withdrawal_root_empty_returns_zero_bytes_hash() {
        let bridge = Address::ZERO;
        let topic = B256::ZERO;
        assert_eq!(
            calculate_withdrawal_root_from_reth_receipts(
                &[],
                bridge,
                topic,
                B256::ZERO,
                B256::ZERO
            ),
            ZERO_BYTES_HASH
        );
    }

    #[test]
    fn deposit_hash_skips_failed_receipts() {
        let bridge = Address::repeat_byte(0xab);
        let topic = B256::repeat_byte(0xcd);
        let payload = [0x42u8; 32];
        let log = mk_log(bridge, topic, payload.to_vec());
        let success = Receipt {
            tx_type: alloy_consensus::TxType::Eip1559,
            success: true,
            cumulative_gas_used: 0,
            logs: vec![log.clone()],
        };
        let failure = Receipt {
            tx_type: alloy_consensus::TxType::Eip1559,
            success: false,
            cumulative_gas_used: 0,
            logs: vec![log],
        };
        let one = calculate_deposit_hash_from_reth_receipts(
            std::slice::from_ref(&success),
            bridge,
            topic,
        );
        let both = calculate_deposit_hash_from_reth_receipts(&[success, failure], bridge, topic);
        assert_eq!(one, both);
        assert_eq!(one, keccak256(payload));
    }

    #[test]
    fn count_deposits_counts_only_matching_topic() {
        let bridge = Address::repeat_byte(0x01);
        let receive_topic = B256::repeat_byte(0x02);
        let other_topic = B256::repeat_byte(0x03);
        let receipts = vec![Receipt {
            tx_type: alloy_consensus::TxType::Eip1559,
            success: true,
            cumulative_gas_used: 0,
            logs: vec![
                mk_log(bridge, receive_topic, vec![0u8; 32]),
                mk_log(bridge, other_topic, vec![0u8; 32]),
                mk_log(bridge, receive_topic, vec![0u8; 32]),
            ],
        }];
        assert_eq!(count_deposits_from_reth_receipts(&receipts, bridge, receive_topic), 2);
    }
}
