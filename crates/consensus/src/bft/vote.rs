//! BFT voting mechanism.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sumchain_crypto::{sign, verify_signature, KeyPair};
use sumchain_primitives::{Block, BlockHeight, Hash, PublicKey, Signature};

use super::types::{Round, View, VoteType};
use crate::{ConsensusError, Result};

/// A proposal in BFT consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    /// View (height + round)
    pub view: View,
    /// Proposed block
    pub block: Block,
    /// Valid round (for proof-of-lock)
    pub valid_round: Option<Round>,
    /// Proposer signature
    pub signature: Signature,
}

impl Proposal {
    /// Create and sign a new proposal
    pub fn new(view: View, block: Block, valid_round: Option<Round>, keypair: &KeyPair) -> Self {
        let signing_data = Self::signing_data(&view, block.hash(), valid_round);
        let signature = sign(&signing_data, keypair.private_key());

        Self {
            view,
            block,
            valid_round,
            signature: *signature.as_bytes(),
        }
    }

    /// Verify proposal signature
    pub fn verify(&self, proposer: &PublicKey) -> bool {
        let signing_data = Self::signing_data(&self.view, self.block.hash(), self.valid_round);
        verify_signature(proposer, &signing_data, &self.signature)
    }

    /// Generate signing data
    fn signing_data(view: &View, block_hash: Hash, valid_round: Option<Round>) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&view.height.to_le_bytes());
        data.extend_from_slice(&view.round.to_le_bytes());
        data.extend_from_slice(block_hash.as_bytes());
        if let Some(round) = valid_round {
            data.extend_from_slice(&round.to_le_bytes());
        }
        data
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Proposal serialization failed")
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| {
            ConsensusError::InvalidVote(format!("Proposal deserialization failed: {}", e))
        })
    }
}

/// A vote in BFT consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    /// View (height + round)
    pub view: View,
    /// Vote type (prevote or precommit)
    pub vote_type: VoteType,
    /// Block hash being voted for (None = nil vote)
    pub block_hash: Option<Hash>,
    /// Validator public key
    pub validator: PublicKey,
    /// Signature
    pub signature: Signature,
}

impl Vote {
    /// Create and sign a new vote
    pub fn new(
        view: View,
        vote_type: VoteType,
        block_hash: Option<Hash>,
        keypair: &KeyPair,
    ) -> Self {
        let signing_data = Self::signing_data(&view, &vote_type, &block_hash);
        let signature = sign(&signing_data, keypair.private_key());

        Self {
            view,
            vote_type,
            block_hash,
            validator: *keypair.public_key(),
            signature: *signature.as_bytes(),
        }
    }

    /// Verify vote signature
    pub fn verify(&self) -> bool {
        let signing_data = Self::signing_data(&self.view, &self.vote_type, &self.block_hash);
        verify_signature(&self.validator, &signing_data, &self.signature)
    }

    /// Generate signing data
    fn signing_data(view: &View, vote_type: &VoteType, block_hash: &Option<Hash>) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&view.height.to_le_bytes());
        data.extend_from_slice(&view.round.to_le_bytes());
        data.push(match vote_type {
            VoteType::Prevote => 0,
            VoteType::Precommit => 1,
        });
        if let Some(hash) = block_hash {
            data.extend_from_slice(hash.as_bytes());
        }
        data
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Vote serialization failed")
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data)
            .map_err(|e| ConsensusError::InvalidVote(format!("Vote deserialization failed: {}", e)))
    }
}

/// Collection of votes for a specific view and type
#[derive(Debug, Clone)]
pub struct VoteSet {
    /// View this vote set is for
    view: View,
    /// Vote type
    vote_type: VoteType,
    /// Validator set size
    validator_count: usize,
    /// Votes by validator public key
    votes: HashMap<PublicKey, Vote>,
    /// Votes grouped by block hash
    votes_by_block: HashMap<Option<Hash>, usize>,
}

impl VoteSet {
    /// Create a new vote set
    pub fn new(view: View, vote_type: VoteType, validator_count: usize) -> Self {
        Self {
            view,
            vote_type,
            validator_count,
            votes: HashMap::new(),
            votes_by_block: HashMap::new(),
        }
    }

    /// Add a vote to the set
    pub fn add_vote(&mut self, vote: Vote) -> Result<bool> {
        // Verify vote is for correct view and type
        if vote.view != self.view || vote.vote_type != self.vote_type {
            return Err(ConsensusError::InvalidVote(
                "Vote view/type mismatch".to_string(),
            ));
        }

        // Verify signature
        if !vote.verify() {
            return Err(ConsensusError::InvalidVote(
                "Invalid vote signature".to_string(),
            ));
        }

        // Check for duplicate vote from this validator
        if self.votes.contains_key(&vote.validator) {
            return Ok(false); // Already have this vote
        }

        // Add vote
        let block_hash = vote.block_hash;
        self.votes.insert(vote.validator, vote);

        // Update block vote count
        *self.votes_by_block.entry(block_hash).or_insert(0) += 1;

        Ok(true)
    }

    /// Get total number of votes
    pub fn total_votes(&self) -> usize {
        self.votes.len()
    }

    /// Get votes for a specific block (None = nil votes)
    pub fn votes_for_block(&self, block_hash: &Option<Hash>) -> usize {
        *self.votes_by_block.get(block_hash).unwrap_or(&0)
    }

    /// Check if we have >2/3 votes for any block
    pub fn has_two_thirds_majority(&self) -> Option<Hash> {
        let threshold = self.two_thirds_threshold();

        for (block_hash, count) in &self.votes_by_block {
            if *count >= threshold {
                if let Some(hash) = block_hash {
                    return Some(*hash);
                }
            }
        }

        None
    }

    /// Check if we have >2/3 votes for a specific block
    pub fn has_two_thirds_for(&self, block_hash: &Option<Hash>) -> bool {
        self.votes_for_block(block_hash) >= self.two_thirds_threshold()
    }

    /// Check if we have >1/3 votes (any block) - triggers round increment
    pub fn has_one_third_any(&self) -> bool {
        self.total_votes() >= self.one_third_threshold()
    }

    /// Calculate 2/3 threshold (Byzantine quorum)
    fn two_thirds_threshold(&self) -> usize {
        (self.validator_count * 2) / 3 + 1
    }

    /// Calculate 1/3 threshold
    fn one_third_threshold(&self) -> usize {
        self.validator_count / 3 + 1
    }

    /// Get block with most votes (for valid block tracking)
    pub fn block_with_most_votes(&self) -> Option<Hash> {
        self.votes_by_block
            .iter()
            .filter_map(|(hash, count)| hash.map(|h| (h, count)))
            .max_by_key(|(_, count)| *count)
            .map(|(hash, _)| hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_crypto::KeyPair;

    #[test]
    fn test_vote_creation_and_verification() {
        let keypair = KeyPair::generate();
        let view = View::new(1, 0);
        let block_hash = Some(Hash::from_bytes(&[1; 32]));

        let vote = Vote::new(view, VoteType::Prevote, block_hash, &keypair);

        assert_eq!(vote.view, view);
        assert_eq!(vote.vote_type, VoteType::Prevote);
        assert_eq!(vote.block_hash, block_hash);
        assert!(vote.verify());
    }

    #[test]
    fn test_vote_set_quorum() {
        let view = View::new(1, 0);
        let mut vote_set = VoteSet::new(view, VoteType::Prevote, 4); // 4 validators

        let block_hash = Some(Hash::from_bytes(&[1; 32]));

        // Add 3 votes (3/4 = 75% > 66.6%)
        for _ in 0..3 {
            let keypair = KeyPair::generate();
            let vote = Vote::new(view, VoteType::Prevote, block_hash, &keypair);
            vote_set.add_vote(vote).unwrap();
        }

        assert!(vote_set.has_two_thirds_for(&block_hash));
        assert_eq!(vote_set.has_two_thirds_majority(), block_hash);
    }

    #[test]
    fn test_vote_set_no_quorum() {
        let view = View::new(1, 0);
        let mut vote_set = VoteSet::new(view, VoteType::Prevote, 4);

        let block_hash = Some(Hash::from_bytes(&[1; 32]));

        // Add 2 votes (2/4 = 50% < 66.6%)
        for _ in 0..2 {
            let keypair = KeyPair::generate();
            let vote = Vote::new(view, VoteType::Prevote, block_hash, &keypair);
            vote_set.add_vote(vote).unwrap();
        }

        assert!(!vote_set.has_two_thirds_for(&block_hash));
        assert_eq!(vote_set.has_two_thirds_majority(), None);
    }
}
