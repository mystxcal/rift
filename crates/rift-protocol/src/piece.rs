//! Bounded lane records for independently reconstructible object pieces.

use rift_core::{BlockId, Digest, EntryId};
use thiserror::Error;

use crate::MAX_STREAM_COMPONENT_BYTES;

const MAGIC: [u8; 4] = *b"RFP2";
const VERSION: u8 = 1;
const START: u8 = 1;
const ENTRY: u8 = 2;
const PIECE: u8 = 3;
const OBJECT_SEAL: u8 = 4;
const RESUME_OFFER: u8 = 5;
const RESUME_DECISION: u8 = 6;
const COMMIT_RECEIPT: u8 = 7;
const CANCEL: u8 = 8;
const LEASE_LIVENESS: u8 = 9;
const COMMIT_ACK: u8 = 10;
const PREFIX_BYTES: usize = 6;
const PIECE_HEADER_BYTES: usize = PREFIX_BYTES + 8 + 8 + 8 + 32 + 4;

/// Maximum sparse runs exchanged by one retry negotiation.
pub const MAX_DURABLE_RANGES: usize = 4_096;

/// A canonical run of receiver-reverified pieces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResumeRange {
    /// First block identifier in the run.
    pub start: BlockId,
    /// Number of consecutive blocks.
    pub count: u32,
    /// Digest over the ordered piece commitments in this run.
    pub commitment: Digest,
}

/// One authenticated message carried by an independent QUIC lane.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PieceRecord<'a> {
    /// Immutable transfer geometry.
    Start {
        /// Stable live-retry identity.
        object_id: [u8; 16],
        /// Number of filesystem entries.
        entries: u64,
        /// Total logical regular-file bytes.
        total_length: u64,
        /// Maximum logical bytes in one piece.
        piece_bytes: u32,
        /// Exact number of source pieces.
        pieces: u64,
    },
    /// Canonical parent-before-child filesystem entry.
    Entry {
        /// Entry identifier.
        entry: EntryId,
        /// Parent identifier, absent only for the root.
        parent: Option<EntryId>,
        /// Whether this entry is a directory.
        directory: bool,
        /// Logical file length, zero for directories.
        length: u64,
        /// Portable metadata flags.
        metadata: u16,
        /// One canonical UTF-8 path component.
        name: &'a str,
    },
    /// One self-verifying source piece.
    Piece {
        /// Object-global piece identifier.
        block: BlockId,
        /// File containing the logical bytes.
        entry: EntryId,
        /// Logical byte offset within the file.
        offset: u64,
        /// Digest of `data`.
        digest: Digest,
        /// Borrowed logical bytes.
        data: &'a [u8],
    },
    /// Canonical commitment over metadata and ordered piece commitments.
    ObjectSeal {
        /// Complete object commitment.
        digest: Digest,
    },
    /// Receiver-reverified sparse durable state.
    ResumeOffer {
        /// Stable object identity.
        object_id: [u8; 16],
        /// Sorted non-overlapping, non-adjacent runs.
        ranges: Vec<ResumeRange>,
    },
    /// Sender-accepted subset of the offered sparse state.
    ResumeDecision {
        /// Stable object identity.
        object_id: [u8; 16],
        /// Sorted accepted runs. Commitments are repeated to bind the exact
        /// decision and make replay comparison mechanical.
        ranges: Vec<ResumeRange>,
    },
    /// Receiver's durable atomic-commit receipt.
    CommitReceipt {
        /// Complete object commitment.
        digest: Digest,
        /// Committed logical bytes.
        length: u64,
    },
    /// Sender's explicit acceptance of the durable receipt.
    CommitAck {
        /// Object commitment copied from the accepted receipt.
        digest: Digest,
    },
    /// Authenticated cancellation.
    Cancel,
    /// Low-rate authenticated evidence that the transfer lease is still live.
    LeaseLiveness {
        /// Monotonic useful-work counter.
        progress: u64,
    },
}

/// Malformed or non-canonical piece-lane message.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PieceRecordError {
    /// Record framing, version, or exact length was invalid.
    #[error("invalid piece record")]
    Invalid,
    /// Record or declared payload exceeded its caller-supplied bound.
    #[error("piece record exceeds negotiated limits")]
    TooLarge,
    /// Sparse ranges were empty, overlapping, adjacent, unordered, or wrapped.
    #[error("sparse durable ranges are not canonical")]
    NonCanonicalRanges,
}

impl PieceRecord<'_> {
    /// Encode one exact canonical lane message.
    ///
    /// # Errors
    ///
    /// Returns for oversized components, impossible geometry, or
    /// non-canonical sparse ranges.
    pub fn encode(&self) -> Result<Vec<u8>, PieceRecordError> {
        let mut output = Vec::new();
        output.extend_from_slice(&MAGIC);
        output.push(VERSION);
        match self {
            Self::Start {
                object_id,
                entries,
                total_length,
                piece_bytes,
                pieces,
            } => {
                if *entries == 0 || *piece_bytes == 0 {
                    return Err(PieceRecordError::Invalid);
                }
                output.push(START);
                output.extend_from_slice(object_id);
                output.extend_from_slice(&entries.to_be_bytes());
                output.extend_from_slice(&total_length.to_be_bytes());
                output.extend_from_slice(&piece_bytes.to_be_bytes());
                output.extend_from_slice(&pieces.to_be_bytes());
            }
            Self::Entry {
                entry,
                parent,
                directory,
                length,
                metadata,
                name,
            } => {
                if name.is_empty() || name.len() > MAX_STREAM_COMPONENT_BYTES {
                    return Err(PieceRecordError::TooLarge);
                }
                let name_length =
                    u16::try_from(name.len()).map_err(|_| PieceRecordError::TooLarge)?;
                output.push(ENTRY);
                output.extend_from_slice(&entry.0.to_be_bytes());
                output.extend_from_slice(&parent.map_or(u64::MAX, |id| id.0).to_be_bytes());
                output.push(u8::from(*directory));
                output.extend_from_slice(&length.to_be_bytes());
                output.extend_from_slice(&metadata.to_be_bytes());
                output.extend_from_slice(&name_length.to_be_bytes());
                output.extend_from_slice(name.as_bytes());
            }
            Self::Piece {
                block,
                entry,
                offset,
                digest,
                data,
            } => {
                let length = u32::try_from(data.len()).map_err(|_| PieceRecordError::TooLarge)?;
                if length == 0 {
                    return Err(PieceRecordError::Invalid);
                }
                output.push(PIECE);
                output.extend_from_slice(&block.0.to_be_bytes());
                output.extend_from_slice(&entry.0.to_be_bytes());
                output.extend_from_slice(&offset.to_be_bytes());
                output.extend_from_slice(&digest.0);
                output.extend_from_slice(&length.to_be_bytes());
                output.extend_from_slice(data);
            }
            Self::ObjectSeal { digest } => {
                output.push(OBJECT_SEAL);
                output.extend_from_slice(&digest.0);
            }
            Self::ResumeOffer { object_id, ranges } => {
                output.push(RESUME_OFFER);
                encode_ranges(&mut output, object_id, ranges)?;
            }
            Self::ResumeDecision { object_id, ranges } => {
                output.push(RESUME_DECISION);
                encode_ranges(&mut output, object_id, ranges)?;
            }
            Self::CommitReceipt { digest, length } => {
                output.push(COMMIT_RECEIPT);
                output.extend_from_slice(&digest.0);
                output.extend_from_slice(&length.to_be_bytes());
            }
            Self::CommitAck { digest } => {
                output.push(COMMIT_ACK);
                output.extend_from_slice(&digest.0);
            }
            Self::Cancel => output.push(CANCEL),
            Self::LeaseLiveness { progress } => {
                output.push(LEASE_LIVENESS);
                output.extend_from_slice(&progress.to_be_bytes());
            }
        }
        Ok(output)
    }
}

/// Decode one complete bounded lane message.
///
/// # Errors
///
/// Returns before borrowing payload bytes when framing, exact length, payload
/// bounds, UTF-8, or sparse-range canonicality is invalid.
pub fn decode_piece_record(
    input: &[u8],
    maximum_piece_bytes: usize,
) -> Result<PieceRecord<'_>, PieceRecordError> {
    if input.len() < PREFIX_BYTES || input[..4] != MAGIC || input[4] != VERSION {
        return Err(PieceRecordError::Invalid);
    }
    match input[5] {
        START => {
            exact(input, PREFIX_BYTES + 16 + 8 + 8 + 4 + 8)?;
            let entries = u64_at(input, 22)?;
            let piece_bytes = u32_at(input, 38)?;
            if entries == 0 || piece_bytes == 0 {
                return Err(PieceRecordError::Invalid);
            }
            Ok(PieceRecord::Start {
                object_id: array(input, 6)?,
                entries,
                total_length: u64_at(input, 30)?,
                piece_bytes,
                pieces: u64_at(input, 42)?,
            })
        }
        ENTRY => decode_entry(input),
        PIECE => {
            if input.len() < PIECE_HEADER_BYTES {
                return Err(PieceRecordError::Invalid);
            }
            let length = usize::try_from(u32_at(input, PIECE_HEADER_BYTES - 4)?)
                .map_err(|_| PieceRecordError::TooLarge)?;
            if length == 0 || length > maximum_piece_bytes {
                return Err(PieceRecordError::TooLarge);
            }
            exact(input, PIECE_HEADER_BYTES.saturating_add(length))?;
            Ok(PieceRecord::Piece {
                block: BlockId(u64_at(input, 6)?),
                entry: EntryId(u64_at(input, 14)?),
                offset: u64_at(input, 22)?,
                digest: Digest(array(input, 30)?),
                data: &input[PIECE_HEADER_BYTES..],
            })
        }
        OBJECT_SEAL => {
            exact(input, PREFIX_BYTES + 32)?;
            Ok(PieceRecord::ObjectSeal {
                digest: Digest(array(input, 6)?),
            })
        }
        RESUME_OFFER | RESUME_DECISION => {
            let (object_id, ranges) = decode_ranges(input)?;
            if input[5] == RESUME_OFFER {
                Ok(PieceRecord::ResumeOffer { object_id, ranges })
            } else {
                Ok(PieceRecord::ResumeDecision { object_id, ranges })
            }
        }
        COMMIT_RECEIPT => {
            exact(input, PREFIX_BYTES + 32 + 8)?;
            Ok(PieceRecord::CommitReceipt {
                digest: Digest(array(input, 6)?),
                length: u64_at(input, 38)?,
            })
        }
        COMMIT_ACK => {
            exact(input, PREFIX_BYTES + 32)?;
            Ok(PieceRecord::CommitAck {
                digest: Digest(array(input, 6)?),
            })
        }
        CANCEL => {
            exact(input, PREFIX_BYTES)?;
            Ok(PieceRecord::Cancel)
        }
        LEASE_LIVENESS => {
            exact(input, PREFIX_BYTES + 8)?;
            Ok(PieceRecord::LeaseLiveness {
                progress: u64_at(input, 6)?,
            })
        }
        _ => Err(PieceRecordError::Invalid),
    }
}

fn decode_entry(input: &[u8]) -> Result<PieceRecord<'_>, PieceRecordError> {
    const HEADER: usize = PREFIX_BYTES + 8 + 8 + 1 + 8 + 2 + 2;
    if input.len() < HEADER {
        return Err(PieceRecordError::Invalid);
    }
    let parent = u64_at(input, 14)?;
    let directory = match input[22] {
        0 => false,
        1 => true,
        _ => return Err(PieceRecordError::Invalid),
    };
    let length = usize::from(u16_at(input, 33)?);
    if length == 0 || length > MAX_STREAM_COMPONENT_BYTES {
        return Err(PieceRecordError::TooLarge);
    }
    exact(input, HEADER.saturating_add(length))?;
    let name = std::str::from_utf8(&input[HEADER..]).map_err(|_| PieceRecordError::Invalid)?;
    Ok(PieceRecord::Entry {
        entry: EntryId(u64_at(input, 6)?),
        parent: (parent != u64::MAX).then_some(EntryId(parent)),
        directory,
        length: u64_at(input, 23)?,
        metadata: u16_at(input, 31)?,
        name,
    })
}

fn encode_ranges(
    output: &mut Vec<u8>,
    object_id: &[u8; 16],
    ranges: &[ResumeRange],
) -> Result<(), PieceRecordError> {
    validate_ranges(ranges)?;
    let count = u16::try_from(ranges.len()).map_err(|_| PieceRecordError::TooLarge)?;
    output.extend_from_slice(object_id);
    output.extend_from_slice(&count.to_be_bytes());
    for range in ranges {
        output.extend_from_slice(&range.start.0.to_be_bytes());
        output.extend_from_slice(&range.count.to_be_bytes());
        output.extend_from_slice(&range.commitment.0);
    }
    Ok(())
}

fn decode_ranges(input: &[u8]) -> Result<([u8; 16], Vec<ResumeRange>), PieceRecordError> {
    const HEADER: usize = PREFIX_BYTES + 16 + 2;
    const RANGE_BYTES: usize = 8 + 4 + 32;
    if input.len() < HEADER {
        return Err(PieceRecordError::Invalid);
    }
    let count = usize::from(u16_at(input, PREFIX_BYTES + 16)?);
    if count > MAX_DURABLE_RANGES {
        return Err(PieceRecordError::TooLarge);
    }
    exact(
        input,
        HEADER.saturating_add(count.saturating_mul(RANGE_BYTES)),
    )?;
    let mut ranges = Vec::with_capacity(count);
    for index in 0..count {
        let offset = HEADER + index * RANGE_BYTES;
        ranges.push(ResumeRange {
            start: BlockId(u64_at(input, offset)?),
            count: u32_at(input, offset + 8)?,
            commitment: Digest(array(input, offset + 12)?),
        });
    }
    validate_ranges(&ranges)?;
    Ok((array(input, PREFIX_BYTES)?, ranges))
}

fn validate_ranges(ranges: &[ResumeRange]) -> Result<(), PieceRecordError> {
    if ranges.len() > MAX_DURABLE_RANGES {
        return Err(PieceRecordError::TooLarge);
    }
    let mut previous_end = None;
    for range in ranges {
        if range.count == 0 {
            return Err(PieceRecordError::NonCanonicalRanges);
        }
        let end = range
            .start
            .0
            .checked_add(u64::from(range.count))
            .ok_or(PieceRecordError::NonCanonicalRanges)?;
        if previous_end.is_some_and(|previous| range.start.0 <= previous) {
            return Err(PieceRecordError::NonCanonicalRanges);
        }
        previous_end = Some(end);
    }
    Ok(())
}

fn exact(input: &[u8], expected: usize) -> Result<(), PieceRecordError> {
    if input.len() == expected {
        Ok(())
    } else {
        Err(PieceRecordError::Invalid)
    }
}

fn array<const N: usize>(input: &[u8], offset: usize) -> Result<[u8; N], PieceRecordError> {
    input
        .get(offset..offset.saturating_add(N))
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(PieceRecordError::Invalid)
}

fn u16_at(input: &[u8], offset: usize) -> Result<u16, PieceRecordError> {
    Ok(u16::from_be_bytes(array(input, offset)?))
}

fn u32_at(input: &[u8], offset: usize) -> Result<u32, PieceRecordError> {
    Ok(u32::from_be_bytes(array(input, offset)?))
}

fn u64_at(input: &[u8], offset: usize) -> Result<u64, PieceRecordError> {
    Ok(u64::from_be_bytes(array(input, offset)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(record: PieceRecord<'_>) {
        let encoded = record.encode().unwrap();
        assert_eq!(decode_piece_record(&encoded, 1024).unwrap(), record);
        drop(record);
    }

    #[test]
    fn every_lane_shape_round_trips_exactly() {
        round_trip(PieceRecord::Start {
            object_id: [1; 16],
            entries: 2,
            total_length: 3,
            piece_bytes: 1024,
            pieces: 1,
        });
        round_trip(PieceRecord::Entry {
            entry: EntryId(1),
            parent: Some(EntryId(0)),
            directory: false,
            length: 3,
            metadata: 7,
            name: "ink.bin",
        });
        round_trip(PieceRecord::Piece {
            block: BlockId(2),
            entry: EntryId(1),
            offset: 4,
            digest: Digest([9; 32]),
            data: b"abc",
        });
        round_trip(PieceRecord::ObjectSeal {
            digest: Digest([2; 32]),
        });
        round_trip(PieceRecord::CommitReceipt {
            digest: Digest([3; 32]),
            length: 99,
        });
        round_trip(PieceRecord::CommitAck {
            digest: Digest([3; 32]),
        });
        round_trip(PieceRecord::Cancel);
        round_trip(PieceRecord::LeaseLiveness { progress: 88 });
    }

    #[test]
    fn sparse_ranges_round_trip_and_reject_ambiguous_forms() {
        let ranges = [
            ResumeRange {
                start: BlockId(0),
                count: 2,
                commitment: Digest([1; 32]),
            },
            ResumeRange {
                start: BlockId(4),
                count: 1,
                commitment: Digest([2; 32]),
            },
        ];
        for record in [
            PieceRecord::ResumeOffer {
                object_id: [4; 16],
                ranges: ranges.to_vec(),
            },
            PieceRecord::ResumeDecision {
                object_id: [4; 16],
                ranges: ranges.to_vec(),
            },
        ] {
            let encoded = record.encode().unwrap();
            assert_eq!(decode_piece_record(&encoded, 1024).unwrap(), record);
        }

        let adjacent = [
            ranges[0],
            ResumeRange {
                start: BlockId(2),
                ..ranges[1]
            },
        ];
        assert_eq!(
            PieceRecord::ResumeOffer {
                object_id: [0; 16],
                ranges: adjacent.to_vec(),
            }
            .encode(),
            Err(PieceRecordError::NonCanonicalRanges)
        );
    }

    #[test]
    fn piece_bound_is_checked_before_payload_borrow() {
        let encoded = PieceRecord::Piece {
            block: BlockId(0),
            entry: EntryId(0),
            offset: 0,
            digest: Digest([0; 32]),
            data: &[7; 32],
        }
        .encode()
        .unwrap();
        assert_eq!(
            decode_piece_record(&encoded, 16),
            Err(PieceRecordError::TooLarge)
        );
        assert_eq!(
            decode_piece_record(&encoded[..encoded.len() - 1], 64),
            Err(PieceRecordError::Invalid)
        );
    }
}
