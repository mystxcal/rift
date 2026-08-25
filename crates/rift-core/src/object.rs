//! Monotonic reconstruction state for one authenticated object.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A 256-bit content digest.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Digest(pub [u8; 32]);

/// Stable identifier for one manifest entry.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct EntryId(pub u64);

/// Stable identifier for one source block.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct BlockId(pub u64);

/// Immutable declaration for a source block.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockSpec {
    /// Block identifier, unique within the object.
    pub id: BlockId,
    /// Manifest entry containing the block.
    pub entry: EntryId,
    /// Logical byte offset within the entry.
    pub offset: u64,
    /// Number of logical bytes represented by this block.
    pub length: u32,
    /// Decoder rank required to reconstruct the block.
    pub source_symbols: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlockState {
    spec: BlockSpec,
    rank: u16,
    declared_seal: Option<Digest>,
    phase: BlockPhase,
}

/// Monotonic ownership state for one independently reconstructible block.
///
/// Network paths may own only [`BlockPhase::InFlight`] work.  Once bytes are
/// authenticated they belong to the object-global ledger, not to the path
/// that delivered them.  This distinction is what makes cancellation and
/// path replacement safe.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum BlockPhase {
    /// No path currently owns delivery of this block.
    #[default]
    Missing,
    /// One admitted path owns an unverified delivery attempt.
    InFlight,
    /// Enough authenticated information is resident to reconstruct the block.
    Received,
    /// Reconstructed bytes match the immutable block commitment.
    Verified,
    /// Verified bytes have crossed the receiver's durability boundary.
    Durable,
}

/// One inclusive-start, exclusive-end run of durable block identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DurableRange {
    /// First durable block identifier in the run.
    pub start: BlockId,
    /// Number of consecutive durable block identifiers.
    pub count: u32,
}

/// Pure, monotonic state of an object being reconstructed.
#[derive(Clone, Debug, Default)]
pub struct ReconstructionGraph {
    blocks: BTreeMap<BlockId, BlockState>,
    declared_final_seal: Option<Digest>,
    final_verified: bool,
}

/// A rejected graph transition.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GraphError {
    /// A block declaration has no content or symbols.
    #[error("block {0:?} has invalid zero geometry")]
    InvalidBlock(BlockId),
    /// Final seal has closed the declaration set.
    #[error("the object declaration graph is already sealed")]
    GraphSealed,
    /// The same stable identifier was declared with different content.
    #[error("conflicting declaration for block {0:?}")]
    ConflictingBlock(BlockId),
    /// Two blocks claim overlapping bytes in one entry.
    #[error("block {new:?} overlaps declared block {existing:?}")]
    OverlappingBlocks {
        /// Newly proposed block.
        new: BlockId,
        /// Previously admitted overlapping block.
        existing: BlockId,
    },
    /// A transition references an undeclared block.
    #[error("unknown block {0:?}")]
    UnknownBlock(BlockId),
    /// Decoder rank attempted to move backward or beyond the source rank.
    #[error("invalid rank transition for block {block:?}: {current} -> {next} (limit {limit})")]
    InvalidRank {
        /// Block whose decoder rank was updated.
        block: BlockId,
        /// Previously accepted decoder rank.
        current: u16,
        /// Proposed new decoder rank.
        next: u16,
        /// Source rank declared for the block.
        limit: u16,
    },
    /// A path-ownership or durability transition would move backward or skip
    /// an authenticated boundary.
    #[error("invalid phase transition for block {block:?}: {current:?} -> {requested:?}")]
    InvalidPhase {
        /// Block whose phase was addressed.
        block: BlockId,
        /// Current canonical phase.
        current: BlockPhase,
        /// Rejected requested phase.
        requested: BlockPhase,
    },
    /// A block seal was replayed with different content.
    #[error("conflicting seal for block {0:?}")]
    ConflictingBlockSeal(BlockId),
    /// Verification was attempted before the block was reconstructable.
    #[error("block {0:?} is not reconstructable yet")]
    IncompleteBlock(BlockId),
    /// The reconstructed bytes did not match the declared block seal.
    #[error("seal mismatch for block {0:?}")]
    BlockSealMismatch(BlockId),
    /// The final seal was replayed with different content.
    #[error("conflicting final object seal")]
    ConflictingFinalSeal,
    /// Final verification was attempted while blocks were incomplete.
    #[error("the object still has incomplete blocks")]
    IncompleteObject,
    /// The reconstructed object did not match the declared final seal.
    #[error("final object seal mismatch")]
    FinalSealMismatch,
}

impl ReconstructionGraph {
    /// Create an empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare a block. Exact replay is idempotent; conflicting replay fails.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError`] for invalid geometry, overlap, conflicting replay,
    /// or a declaration made after the graph was sealed.
    pub fn declare_block(&mut self, spec: BlockSpec) -> Result<(), GraphError> {
        if self.declared_final_seal.is_some() {
            return Err(GraphError::GraphSealed);
        }
        if spec.length == 0
            || spec.source_symbols == 0
            || spec.offset.checked_add(u64::from(spec.length)).is_none()
        {
            return Err(GraphError::InvalidBlock(spec.id));
        }
        if let Some(existing) = self.blocks.get(&spec.id) {
            return if existing.spec == spec {
                Ok(())
            } else {
                Err(GraphError::ConflictingBlock(spec.id))
            };
        }

        let end = spec.offset + u64::from(spec.length);
        for existing in self
            .blocks
            .values()
            .filter(|block| block.spec.entry == spec.entry)
        {
            let existing_end = existing.spec.offset + u64::from(existing.spec.length);
            if spec.offset < existing_end && existing.spec.offset < end {
                return Err(GraphError::OverlappingBlocks {
                    new: spec.id,
                    existing: existing.spec.id,
                });
            }
        }

        self.blocks.insert(
            spec.id,
            BlockState {
                spec,
                rank: 0,
                declared_seal: None,
                phase: BlockPhase::Missing,
            },
        );
        Ok(())
    }

    /// Assign one missing block to a path owner.
    ///
    /// Exact replay is idempotent. Verified or durable blocks cannot be
    /// assigned again; duplicate tail work is represented by the scheduler,
    /// not by corrupting the canonical ledger.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError::UnknownBlock`] for an unknown identifier or
    /// [`GraphError::InvalidPhase`] for a non-missing completed block.
    pub fn assign(&mut self, id: BlockId) -> Result<(), GraphError> {
        let block = self
            .blocks
            .get_mut(&id)
            .ok_or(GraphError::UnknownBlock(id))?;
        match block.phase {
            BlockPhase::Missing => block.phase = BlockPhase::InFlight,
            BlockPhase::InFlight => {}
            phase => {
                return Err(GraphError::InvalidPhase {
                    block: id,
                    current: phase,
                    requested: BlockPhase::InFlight,
                });
            }
        }
        Ok(())
    }

    /// Release path-owned work that never became authenticated object state.
    ///
    /// # Errors
    ///
    /// Returns for an unknown block or an attempted regression after bytes
    /// entered the object-global ledger.
    pub fn abandon(&mut self, id: BlockId) -> Result<(), GraphError> {
        let block = self
            .blocks
            .get_mut(&id)
            .ok_or(GraphError::UnknownBlock(id))?;
        match block.phase {
            BlockPhase::Missing => {}
            BlockPhase::InFlight => block.phase = BlockPhase::Missing,
            phase => {
                return Err(GraphError::InvalidPhase {
                    block: id,
                    current: phase,
                    requested: BlockPhase::Missing,
                });
            }
        }
        Ok(())
    }

    /// Record decoder rank after authenticated innovative evidence is admitted.
    /// Equal rank is an idempotent replay.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError`] when the block is unknown or rank regresses or
    /// exceeds the block's declared source rank.
    pub fn advance_rank(&mut self, id: BlockId, next: u16) -> Result<(), GraphError> {
        let block = self
            .blocks
            .get_mut(&id)
            .ok_or(GraphError::UnknownBlock(id))?;
        if next < block.rank || next > block.spec.source_symbols {
            return Err(GraphError::InvalidRank {
                block: id,
                current: block.rank,
                next,
                limit: block.spec.source_symbols,
            });
        }
        block.rank = next;
        if next == block.spec.source_symbols && block.phase < BlockPhase::Received {
            block.phase = BlockPhase::Received;
        }
        Ok(())
    }

    /// Declare the expected digest for a block.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError`] for an unknown block or conflicting replay.
    pub fn declare_block_seal(&mut self, id: BlockId, seal: Digest) -> Result<(), GraphError> {
        let block = self
            .blocks
            .get_mut(&id)
            .ok_or(GraphError::UnknownBlock(id))?;
        match block.declared_seal {
            None => block.declared_seal = Some(seal),
            Some(existing) if existing == seal => {}
            Some(_) => return Err(GraphError::ConflictingBlockSeal(id)),
        }
        Ok(())
    }

    /// Verify reconstructed block bytes against their declaration.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError`] when the block is unknown, incomplete, lacks its
    /// declared seal, or has a different observed digest.
    pub fn verify_block(&mut self, id: BlockId, observed: Digest) -> Result<(), GraphError> {
        let block = self
            .blocks
            .get_mut(&id)
            .ok_or(GraphError::UnknownBlock(id))?;
        if block.rank != block.spec.source_symbols || block.declared_seal.is_none() {
            return Err(GraphError::IncompleteBlock(id));
        }
        if block.declared_seal != Some(observed) {
            return Err(GraphError::BlockSealMismatch(id));
        }
        block.phase = BlockPhase::Verified;
        Ok(())
    }

    /// Mark a verified block durable after its staging write has completed.
    /// Exact replay is idempotent.
    ///
    /// # Errors
    ///
    /// Returns for an unknown or not-yet-verified block.
    pub fn mark_durable(&mut self, id: BlockId) -> Result<(), GraphError> {
        let block = self
            .blocks
            .get_mut(&id)
            .ok_or(GraphError::UnknownBlock(id))?;
        match block.phase {
            BlockPhase::Verified => block.phase = BlockPhase::Durable,
            BlockPhase::Durable => {}
            phase => {
                return Err(GraphError::InvalidPhase {
                    block: id,
                    current: phase,
                    requested: BlockPhase::Durable,
                });
            }
        }
        Ok(())
    }

    /// Declare the canonical final object digest.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError`] when a different final seal was already declared.
    pub fn declare_final_seal(&mut self, seal: Digest) -> Result<(), GraphError> {
        match self.declared_final_seal {
            None => self.declared_final_seal = Some(seal),
            Some(existing) if existing == seal => {}
            Some(_) => return Err(GraphError::ConflictingFinalSeal),
        }
        Ok(())
    }

    /// Verify the canonical object graph after all blocks have verified.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError`] when any block is incomplete, the final seal is
    /// absent, or the observed object digest differs.
    pub fn verify_final(&mut self, observed: Digest) -> Result<(), GraphError> {
        if !self
            .blocks
            .values()
            .all(|block| block.phase >= BlockPhase::Verified)
            || self.declared_final_seal.is_none()
        {
            return Err(GraphError::IncompleteObject);
        }
        if self.declared_final_seal != Some(observed) {
            return Err(GraphError::FinalSealMismatch);
        }
        self.final_verified = true;
        Ok(())
    }

    /// Whether the staging layer may attempt its atomic destination commit.
    #[must_use]
    pub fn ready_to_commit(&self) -> bool {
        self.final_verified
    }

    /// Number of declared blocks.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Current and required decoder rank for a block.
    #[must_use]
    pub fn rank(&self, id: BlockId) -> Option<(u16, u16)> {
        self.blocks
            .get(&id)
            .map(|block| (block.rank, block.spec.source_symbols))
    }

    /// Current ownership/durability phase for one declared block.
    #[must_use]
    pub fn phase(&self, id: BlockId) -> Option<BlockPhase> {
        self.blocks.get(&id).map(|block| block.phase)
    }

    /// Whether every declared block has crossed the durability boundary.
    #[must_use]
    pub fn all_durable(&self) -> bool {
        self.blocks
            .values()
            .all(|block| block.phase == BlockPhase::Durable)
    }

    /// Compact canonical runs of durable block identifiers.
    ///
    /// Runs are sorted, non-overlapping, and never adjacent. Identifiers above
    /// `u32::MAX` run length naturally split into multiple ranges.
    #[must_use]
    pub fn durable_ranges(&self) -> Vec<DurableRange> {
        let mut ranges = Vec::new();
        let mut start = None;
        let mut previous = BlockId(0);
        let mut count = 0_u32;
        for id in self
            .blocks
            .iter()
            .filter_map(|(id, block)| (block.phase == BlockPhase::Durable).then_some(*id))
        {
            let contiguous =
                start.is_some() && previous.0.checked_add(1) == Some(id.0) && count < u32::MAX;
            if !contiguous {
                if let Some(first) = start {
                    ranges.push(DurableRange {
                        start: first,
                        count,
                    });
                }
                start = Some(id);
                count = 0;
            }
            previous = id;
            count += 1;
        }
        if let Some(first) = start {
            ranges.push(DurableRange {
                start: first,
                count,
            });
        }
        ranges
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(id: u64, offset: u64) -> BlockSpec {
        BlockSpec {
            id: BlockId(id),
            entry: EntryId(7),
            offset,
            length: 1024,
            source_symbols: 4,
        }
    }

    #[test]
    fn exact_declarations_are_idempotent_and_conflicts_fail() {
        let mut graph = ReconstructionGraph::new();
        graph.declare_block(spec(1, 0)).unwrap();
        graph.declare_block(spec(1, 0)).unwrap();
        let mut conflict = spec(1, 0);
        conflict.length = 512;
        assert_eq!(
            graph.declare_block(conflict),
            Err(GraphError::ConflictingBlock(BlockId(1)))
        );
    }

    #[test]
    fn overlapping_ranges_are_rejected() {
        let mut graph = ReconstructionGraph::new();
        graph.declare_block(spec(1, 0)).unwrap();
        assert!(matches!(
            graph.declare_block(spec(2, 1000)),
            Err(GraphError::OverlappingBlocks { .. })
        ));
        graph.declare_block(spec(3, 1024)).unwrap();
    }

    #[test]
    fn object_commits_only_after_monotonic_verified_completion() {
        let block_seal = Digest([3; 32]);
        let final_seal = Digest([9; 32]);
        let mut graph = ReconstructionGraph::new();
        graph.declare_block(spec(1, 0)).unwrap();
        graph.declare_block_seal(BlockId(1), block_seal).unwrap();
        graph.advance_rank(BlockId(1), 3).unwrap();
        assert_eq!(
            graph.verify_block(BlockId(1), block_seal),
            Err(GraphError::IncompleteBlock(BlockId(1)))
        );
        graph.advance_rank(BlockId(1), 4).unwrap();
        graph.verify_block(BlockId(1), block_seal).unwrap();
        graph.declare_final_seal(final_seal).unwrap();
        graph.verify_final(final_seal).unwrap();
        assert!(graph.ready_to_commit());
    }

    #[test]
    fn rank_cannot_regress_or_exceed_geometry() {
        let mut graph = ReconstructionGraph::new();
        graph.declare_block(spec(1, 0)).unwrap();
        graph.advance_rank(BlockId(1), 2).unwrap();
        assert!(matches!(
            graph.advance_rank(BlockId(1), 1),
            Err(GraphError::InvalidRank { .. })
        ));
        assert!(matches!(
            graph.advance_rank(BlockId(1), 5),
            Err(GraphError::InvalidRank { .. })
        ));
    }

    #[test]
    fn final_seal_closes_declarations_but_allows_empty_objects() {
        let final_seal = Digest([8; 32]);
        let mut graph = ReconstructionGraph::new();
        graph.declare_final_seal(final_seal).unwrap();
        assert_eq!(
            graph.declare_block(spec(1, 0)),
            Err(GraphError::GraphSealed)
        );
        graph.verify_final(final_seal).unwrap();
        assert!(graph.ready_to_commit());
    }

    #[test]
    fn path_ownership_can_be_released_only_before_authentication() {
        let mut graph = ReconstructionGraph::new();
        graph.declare_block(spec(1, 0)).unwrap();
        graph.assign(BlockId(1)).unwrap();
        assert_eq!(graph.phase(BlockId(1)), Some(BlockPhase::InFlight));
        graph.abandon(BlockId(1)).unwrap();
        assert_eq!(graph.phase(BlockId(1)), Some(BlockPhase::Missing));

        graph.advance_rank(BlockId(1), 4).unwrap();
        assert!(matches!(
            graph.abandon(BlockId(1)),
            Err(GraphError::InvalidPhase { .. })
        ));
    }

    #[test]
    fn durability_ranges_are_sparse_canonical_and_monotonic() {
        let mut graph = ReconstructionGraph::new();
        for id in 0..6 {
            graph.declare_block(spec(id, id * 1024)).unwrap();
        }
        for id in [0, 1, 3, 4, 5] {
            let block = BlockId(id);
            let byte = u8::try_from(id).unwrap();
            graph.advance_rank(block, 4).unwrap();
            graph.declare_block_seal(block, Digest([byte; 32])).unwrap();
            graph.verify_block(block, Digest([byte; 32])).unwrap();
            graph.mark_durable(block).unwrap();
        }
        assert_eq!(
            graph.durable_ranges(),
            vec![
                DurableRange {
                    start: BlockId(0),
                    count: 2,
                },
                DurableRange {
                    start: BlockId(3),
                    count: 3,
                },
            ]
        );
        assert!(!graph.all_durable());
    }
}
