//! C5 registry ingress (#242, PROPOSED) keeps operations 8 and 9 off the wire.
//! Block sync decodes `SyncResponse::Blocks` with its own bincode call
//! (`SyncCodec::read_response`), not `Block::from_bytes`, so it is checked
//! here on its own: a synced block holding a governance transaction that
//! names operation 8 or 9 fails to decode, exactly as before the proposal,
//! and the same block naming operation 7 decodes.

use futures::io::Cursor;
use libp2p_request_response::Codec;
use libp2p_swarm::StreamProtocol;
use sumchain_p2p::sync::{SyncCodec, SyncResponse};
use sumchain_primitives::block::Block;
use sumchain_primitives::governance::{GovernanceOperation, GovernanceTxData};
use sumchain_primitives::{Address, Hash, SignedTransaction, TransactionV2, TxPayload};

const DATA: [u8; 5] = [0xC5; 5];

fn blocks_response() -> SyncResponse {
    let tx = SignedTransaction::new_v2(
        TransactionV2 {
            chain_id: 4242,
            from: Address::ZERO,
            fee: 1,
            nonce: 0,
            payload: TxPayload::Governance(GovernanceTxData {
                operation: GovernanceOperation::CastEquityVote,
                data: DATA.to_vec(),
            }),
        },
        [0x11; 64],
        [0x22; 32],
    );
    let mut block = Block::genesis(Hash::ZERO, [0x33; 32], 1);
    block.transactions.push(tx);
    SyncResponse::Blocks(vec![block])
}

/// The response bytes with the governance operation index set to `op`.
fn with_op(op: u32) -> Vec<u8> {
    let bytes = bincode::serialize(&blocks_response()).unwrap();
    let marker: Vec<u8> = [
        &23u32.to_le_bytes()[..],
        &7u32.to_le_bytes(),
        &(DATA.len() as u64).to_le_bytes(),
        &DATA,
    ]
    .concat();
    let found: Vec<usize> = bytes
        .windows(marker.len())
        .enumerate()
        .filter(|(_, w)| *w == marker.as_slice())
        .map(|(i, _)| i)
        .collect();
    assert_eq!(found.len(), 1, "the governance payload is in the response once");
    let mut out = bytes;
    out[found[0] + 4..found[0] + 8].copy_from_slice(&op.to_le_bytes());
    out
}

/// What `read_response` reads: a 4-byte big-endian length, then the message.
fn framed(message: &[u8]) -> Cursor<Vec<u8>> {
    Cursor::new([&(message.len() as u32).to_be_bytes()[..], message].concat())
}

async fn read(message: &[u8]) -> std::io::Result<SyncResponse> {
    SyncCodec
        .read_response(&StreamProtocol::new("/sumchain/sync/test"), &mut framed(message))
        .await
}

#[tokio::test]
async fn a_synced_block_naming_operation_8_or_9_does_not_decode() {
    // Control: operation 7 decodes through the codec and through bincode.
    let control = with_op(7);
    assert!(bincode::deserialize::<SyncResponse>(&control).is_ok());
    match read(&control).await.unwrap() {
        SyncResponse::Blocks(blocks) => assert_eq!(blocks[0].transactions.len(), 1),
        other => panic!("decoded as {other:?}"),
    }

    for op in [8u32, 9] {
        let expected = format!("invalid value: integer `{op}`, expected variant index 0 <= i < 8");
        let bytes = with_op(op);
        let err = bincode::deserialize::<SyncResponse>(&bytes).unwrap_err();
        assert_eq!(err.to_string(), expected, "bincode, op {op}");
        let err = read(&bytes).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "codec, op {op}");
        assert_eq!(err.to_string(), expected, "codec, op {op}");
    }
}
