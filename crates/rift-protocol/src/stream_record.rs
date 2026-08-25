//! Canonical records for the single-path correctness oracle.

use rift_core::{BlockId, Digest, EntryId};
use thiserror::Error;

/// Default systematic block bytes in the stream oracle.
pub const STREAM_BLOCK_BYTES: u32 = 48 * 1024;
/// Hard protocol ceiling independent of peer-negotiated lower limits.
pub const MAX_STREAM_BLOCK_BYTES: usize = 56 * 1024;

const FILE_START: u8 = 1;
const BLOCK_DATA: u8 = 2;
const BLOCK_SEAL: u8 = 3;
const OBJECT_SEAL: u8 = 4;
const COMMIT_RECEIPT: u8 = 5;
const CANCEL: u8 = 6;
const MIGRATION_OFFER: u8 = 7;
const MIGRATION_ACCEPT: u8 = 8;
const MIGRATION_REJECT: u8 = 9;
const FALLBACK: u8 = 10;
const RELAY_SAMPLE: u8 = 11;
const RELAY_SAMPLE_ACK: u8 = 12;
const PATH_KEEPALIVE: u8 = 13;
const TREE_START: u8 = 14;
const TREE_ENTRY: u8 = 15;
const ENTRY_SEAL: u8 = 16;
const RESUME_OFFER: u8 = 17;
const RESUME_DECISION: u8 = 18;
/// Hard protocol ceiling for one portable UTF-8 path component.
pub const MAX_STREAM_COMPONENT_BYTES: usize = 4_096;
// A sampled record is a sequenced wrapper around the largest stream record:
// BlockData's 21-byte envelope plus its bounded payload, then the 12-byte
// SequencedRecord envelope. The outer RelaySample envelope remains below the
// secure stream's independent 60 KiB plaintext ceiling.
const MAX_RELAY_SAMPLE_RECORD_BYTES: usize = MAX_STREAM_BLOCK_BYTES + 21 + 12;

/// Borrowed application record inside an authenticated stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamRecord<'a> {
    /// Immutable single-file geometry.
    FileStart {
        /// Transfer-local object identifier.
        object_id: [u8; 16],
        /// Logical byte length.
        length: u64,
        /// Nominal source block bytes.
        block_bytes: u32,
    },
    /// Immutable geometry for one file-or-directory object graph.
    TreeStart {
        /// Transfer-local object identifier.
        object_id: [u8; 16],
        /// Number of parent-before-child entries that follow.
        entries: u64,
        /// Total logical bytes across all regular files.
        total_length: u64,
        /// Nominal source block bytes.
        block_bytes: u32,
    },
    /// One authenticated, parent-before-child filesystem entry declaration.
    TreeEntry {
        /// Stable entry identifier. The root is always zero.
        entry: EntryId,
        /// Parent identifier, absent only for the root.
        parent: Option<EntryId>,
        /// Whether this entry is a directory.
        directory: bool,
        /// Logical regular-file length; zero for a directory.
        length: u64,
        /// Portable metadata flags.
        metadata: u16,
        /// One UTF-8 path component, never a path.
        name: &'a str,
    },
    /// One complete systematic block in canonical file order.
    BlockData {
        /// Stable source block identifier.
        block: BlockId,
        /// Logical byte offset.
        offset: u64,
        /// Borrowed source bytes.
        data: &'a [u8],
    },
    /// Commitment to the preceding block bytes.
    BlockSeal {
        /// Stable source block identifier.
        block: BlockId,
        /// BLAKE3 commitment.
        digest: Digest,
    },
    /// Commitment to one complete regular file's bytes.
    EntrySeal {
        /// File entry being sealed.
        entry: EntryId,
        /// BLAKE3 commitment to the file bytes.
        digest: Digest,
    },
    /// Receiver's verified contiguous prefix for one staged file.
    ResumeOffer {
        /// File entry whose invisible staging bytes were re-verified locally.
        entry: EntryId,
        /// Contiguous verified bytes available from offset zero.
        prefix: u64,
        /// BLAKE3 commitment to exactly `prefix` bytes.
        digest: Digest,
    },
    /// Sender's source-verified choice of reusable prefix.
    ResumeDecision {
        /// File entry to which the decision applies.
        entry: EntryId,
        /// Accepted prefix, either the complete offer or zero.
        prefix: u64,
    },
    /// Commitment to the complete logical file bytes.
    ObjectSeal {
        /// BLAKE3 commitment.
        digest: Digest,
    },
    /// Receiver proof that the verified object crossed the visibility boundary.
    CommitReceipt {
        /// Committed file digest.
        digest: Digest,
        /// Committed file length.
        length: u64,
    },
    /// Best-effort authenticated cancellation reason.
    Cancel {
        /// Stable protocol reason code.
        reason: u16,
    },
    /// Sender offers a validated direct path at a global record boundary.
    MigrationOffer {
        /// Candidate-pair identity.
        path_id: u32,
        /// First record that would use the direct path.
        sequence: u64,
    },
    /// Receiver accepts the offered path and exact boundary.
    MigrationAccept {
        /// Candidate-pair identity.
        path_id: u32,
        /// First record that will use the direct path.
        sequence: u64,
    },
    /// Receiver cannot accept the offered path at this boundary.
    MigrationReject {
        /// Candidate-pair identity.
        path_id: u32,
        /// Rejected direct boundary.
        sequence: u64,
    },
    /// Sender is replaying this sequence over relay after direct failure.
    Fallback {
        /// First replayed global record.
        sequence: u64,
    },
    /// One normal sequenced record sampled end to end on the incumbent relay.
    RelaySample {
        /// Global sequence carried by `record`.
        sequence: u64,
        /// Canonical encoded [`crate::SequencedRecord`].
        record: &'a [u8],
    },
    /// Immediate receiver acknowledgement of a relay sample.
    RelaySampleAck {
        /// Sampled global sequence.
        sequence: u64,
    },
    /// Keeps the incumbent relay recoverable while object records use direct UDP.
    PathKeepalive {
        /// Next global sequence at the sender when the keepalive was emitted.
        sequence: u64,
    },
}

/// Invalid authenticated stream record.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum StreamRecordError {
    /// Record is shorter or longer than its type requires.
    #[error("invalid stream record length")]
    InvalidLength,
    /// Record tag is unknown and mandatory.
    #[error("unknown stream record type {0}")]
    UnknownType(u8),
    /// Block payload exceeds the protocol or caller bound.
    #[error("stream block exceeds its negotiated bound")]
    BlockTooLarge,
    /// File geometry cannot be represented by this protocol generation.
    #[error("invalid stream file geometry")]
    InvalidGeometry,
}

impl StreamRecord<'_> {
    /// Encode one canonical record.
    ///
    /// # Errors
    ///
    /// Returns [`StreamRecordError`] when block data or geometry exceeds the
    /// fixed stream-oracle contract.
    pub fn encode(self) -> Result<Vec<u8>, StreamRecordError> {
        let mut output = Vec::new();
        match self {
            Self::FileStart {
                object_id,
                length,
                block_bytes,
            } => return encode_file_start(object_id, length, block_bytes),
            Self::TreeStart {
                object_id,
                entries,
                total_length,
                block_bytes,
            } => return encode_tree_start(object_id, entries, total_length, block_bytes),
            Self::TreeEntry {
                entry,
                parent,
                directory,
                length,
                metadata,
                name,
            } => return encode_tree_entry(entry, parent, directory, length, metadata, name),
            Self::BlockData {
                block,
                offset,
                data,
            } => return encode_block_data(block, offset, data),
            Self::BlockSeal { block, digest } => {
                output.reserve_exact(41);
                output.push(BLOCK_SEAL);
                output.extend_from_slice(&block.0.to_be_bytes());
                output.extend_from_slice(&digest.0);
            }
            Self::EntrySeal { entry, digest } => {
                return Ok(encode_entry_seal(entry, digest));
            }
            Self::ResumeOffer {
                entry,
                prefix,
                digest,
            } => return Ok(encode_resume_offer(entry, prefix, digest)),
            Self::ResumeDecision { entry, prefix } => {
                return Ok(encode_resume_decision(entry, prefix));
            }
            Self::ObjectSeal { digest } => {
                output.reserve_exact(33);
                output.push(OBJECT_SEAL);
                output.extend_from_slice(&digest.0);
            }
            Self::CommitReceipt { digest, length } => {
                output.reserve_exact(41);
                output.push(COMMIT_RECEIPT);
                output.extend_from_slice(&digest.0);
                output.extend_from_slice(&length.to_be_bytes());
            }
            Self::Cancel { reason } => {
                output.reserve_exact(3);
                output.push(CANCEL);
                output.extend_from_slice(&reason.to_be_bytes());
            }
            Self::MigrationOffer { path_id, sequence }
            | Self::MigrationAccept { path_id, sequence }
            | Self::MigrationReject { path_id, sequence } => {
                output.reserve_exact(13);
                output.push(match self {
                    Self::MigrationOffer { .. } => MIGRATION_OFFER,
                    Self::MigrationAccept { .. } => MIGRATION_ACCEPT,
                    Self::MigrationReject { .. } => MIGRATION_REJECT,
                    _ => unreachable!(),
                });
                output.extend_from_slice(&path_id.to_be_bytes());
                output.extend_from_slice(&sequence.to_be_bytes());
            }
            Self::Fallback { sequence } => {
                output.reserve_exact(9);
                output.push(FALLBACK);
                output.extend_from_slice(&sequence.to_be_bytes());
            }
            Self::RelaySample { sequence, record } => {
                if record.is_empty() || record.len() > MAX_RELAY_SAMPLE_RECORD_BYTES {
                    return Err(StreamRecordError::BlockTooLarge);
                }
                let length =
                    u32::try_from(record.len()).map_err(|_| StreamRecordError::BlockTooLarge)?;
                output.reserve_exact(13 + record.len());
                output.push(RELAY_SAMPLE);
                output.extend_from_slice(&sequence.to_be_bytes());
                output.extend_from_slice(&length.to_be_bytes());
                output.extend_from_slice(record);
            }
            Self::RelaySampleAck { sequence } | Self::PathKeepalive { sequence } => {
                output.reserve_exact(9);
                output.push(match self {
                    Self::RelaySampleAck { .. } => RELAY_SAMPLE_ACK,
                    Self::PathKeepalive { .. } => PATH_KEEPALIVE,
                    _ => unreachable!(),
                });
                output.extend_from_slice(&sequence.to_be_bytes());
            }
        }
        Ok(output)
    }
}

fn encode_block_data(
    block: BlockId,
    offset: u64,
    data: &[u8],
) -> Result<Vec<u8>, StreamRecordError> {
    let length = u32::try_from(data.len()).map_err(|_| StreamRecordError::BlockTooLarge)?;
    if data.is_empty() || data.len() > MAX_STREAM_BLOCK_BYTES {
        return Err(StreamRecordError::BlockTooLarge);
    }
    let mut output = Vec::with_capacity(21 + data.len());
    output.push(BLOCK_DATA);
    output.extend_from_slice(&block.0.to_be_bytes());
    output.extend_from_slice(&offset.to_be_bytes());
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(data);
    Ok(output)
}

fn encode_resume_offer(entry: EntryId, prefix: u64, digest: Digest) -> Vec<u8> {
    let mut output = Vec::with_capacity(49);
    output.push(RESUME_OFFER);
    output.extend_from_slice(&entry.0.to_be_bytes());
    output.extend_from_slice(&prefix.to_be_bytes());
    output.extend_from_slice(&digest.0);
    output
}

fn encode_entry_seal(entry: EntryId, digest: Digest) -> Vec<u8> {
    let mut output = Vec::with_capacity(41);
    output.push(ENTRY_SEAL);
    output.extend_from_slice(&entry.0.to_be_bytes());
    output.extend_from_slice(&digest.0);
    output
}

fn encode_resume_decision(entry: EntryId, prefix: u64) -> Vec<u8> {
    let mut output = Vec::with_capacity(17);
    output.push(RESUME_DECISION);
    output.extend_from_slice(&entry.0.to_be_bytes());
    output.extend_from_slice(&prefix.to_be_bytes());
    output
}

fn encode_file_start(
    object_id: [u8; 16],
    length: u64,
    block_bytes: u32,
) -> Result<Vec<u8>, StreamRecordError> {
    let block_bytes_usize =
        usize::try_from(block_bytes).map_err(|_| StreamRecordError::InvalidGeometry)?;
    if block_bytes == 0 || block_bytes_usize > MAX_STREAM_BLOCK_BYTES {
        return Err(StreamRecordError::InvalidGeometry);
    }
    let mut output = Vec::with_capacity(29);
    output.push(FILE_START);
    output.extend_from_slice(&object_id);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(&block_bytes.to_be_bytes());
    Ok(output)
}

fn encode_tree_start(
    object_id: [u8; 16],
    entries: u64,
    total_length: u64,
    block_bytes: u32,
) -> Result<Vec<u8>, StreamRecordError> {
    let block_bytes_usize =
        usize::try_from(block_bytes).map_err(|_| StreamRecordError::InvalidGeometry)?;
    if entries == 0 || block_bytes == 0 || block_bytes_usize > MAX_STREAM_BLOCK_BYTES {
        return Err(StreamRecordError::InvalidGeometry);
    }
    let mut output = Vec::with_capacity(37);
    output.push(TREE_START);
    output.extend_from_slice(&object_id);
    output.extend_from_slice(&entries.to_be_bytes());
    output.extend_from_slice(&total_length.to_be_bytes());
    output.extend_from_slice(&block_bytes.to_be_bytes());
    Ok(output)
}

fn encode_tree_entry(
    entry: EntryId,
    parent: Option<EntryId>,
    directory: bool,
    length: u64,
    metadata: u16,
    name: &str,
) -> Result<Vec<u8>, StreamRecordError> {
    let name = name.as_bytes();
    let name_length = u16::try_from(name.len()).map_err(|_| StreamRecordError::InvalidGeometry)?;
    if name.is_empty() || name.len() > MAX_STREAM_COMPONENT_BYTES || (directory && length != 0) {
        return Err(StreamRecordError::InvalidGeometry);
    }
    let mut output = Vec::with_capacity(30 + name.len());
    output.push(TREE_ENTRY);
    output.extend_from_slice(&entry.0.to_be_bytes());
    output.extend_from_slice(&parent.map_or(u64::MAX, |parent| parent.0).to_be_bytes());
    output.push(u8::from(directory));
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(&metadata.to_be_bytes());
    output.extend_from_slice(&name_length.to_be_bytes());
    output.extend_from_slice(name);
    Ok(output)
}

/// Decode one exact authenticated application record without copying block data.
///
/// # Errors
///
/// Returns [`StreamRecordError`] for unknown types, non-exact lengths, invalid
/// geometry, or block data above `max_block_bytes`.
pub fn decode_stream_record(
    input: &[u8],
    max_block_bytes: usize,
) -> Result<StreamRecord<'_>, StreamRecordError> {
    let tag = *input.first().ok_or(StreamRecordError::InvalidLength)?;
    match tag {
        FILE_START => decode_file_start(input, max_block_bytes),
        TREE_START => decode_tree_start(input, max_block_bytes),
        TREE_ENTRY => decode_tree_entry(input),
        BLOCK_DATA => {
            if input.len() < 21 {
                return Err(StreamRecordError::InvalidLength);
            }
            let length = usize::try_from(u32::from_be_bytes(array(input, 17)?))
                .map_err(|_| StreamRecordError::BlockTooLarge)?;
            if length == 0 || length > MAX_STREAM_BLOCK_BYTES || length > max_block_bytes {
                return Err(StreamRecordError::BlockTooLarge);
            }
            if input.len() != 21 + length {
                return Err(StreamRecordError::InvalidLength);
            }
            Ok(StreamRecord::BlockData {
                block: BlockId(u64::from_be_bytes(array(input, 1)?)),
                offset: u64::from_be_bytes(array(input, 9)?),
                data: input.get(21..).ok_or(StreamRecordError::InvalidLength)?,
            })
        }
        BLOCK_SEAL => {
            exact(input, 41)?;
            Ok(StreamRecord::BlockSeal {
                block: BlockId(u64::from_be_bytes(array(input, 1)?)),
                digest: Digest(array(input, 9)?),
            })
        }
        ENTRY_SEAL => {
            exact(input, 41)?;
            Ok(StreamRecord::EntrySeal {
                entry: EntryId(u64::from_be_bytes(array(input, 1)?)),
                digest: Digest(array(input, 9)?),
            })
        }
        RESUME_OFFER | RESUME_DECISION => decode_resume_record(input, tag),
        OBJECT_SEAL => {
            exact(input, 33)?;
            Ok(StreamRecord::ObjectSeal {
                digest: Digest(array(input, 1)?),
            })
        }
        COMMIT_RECEIPT => {
            exact(input, 41)?;
            Ok(StreamRecord::CommitReceipt {
                digest: Digest(array(input, 1)?),
                length: u64::from_be_bytes(array(input, 33)?),
            })
        }
        CANCEL => {
            exact(input, 3)?;
            Ok(StreamRecord::Cancel {
                reason: u16::from_be_bytes(array(input, 1)?),
            })
        }
        MIGRATION_OFFER | MIGRATION_ACCEPT | MIGRATION_REJECT => {
            exact(input, 13)?;
            let path_id = u32::from_be_bytes(array(input, 1)?);
            let sequence = u64::from_be_bytes(array(input, 5)?);
            Ok(match tag {
                MIGRATION_OFFER => StreamRecord::MigrationOffer { path_id, sequence },
                MIGRATION_ACCEPT => StreamRecord::MigrationAccept { path_id, sequence },
                MIGRATION_REJECT => StreamRecord::MigrationReject { path_id, sequence },
                _ => unreachable!(),
            })
        }
        FALLBACK => {
            exact(input, 9)?;
            Ok(StreamRecord::Fallback {
                sequence: u64::from_be_bytes(array(input, 1)?),
            })
        }
        RELAY_SAMPLE => decode_relay_sample(input),
        RELAY_SAMPLE_ACK => {
            exact(input, 9)?;
            Ok(StreamRecord::RelaySampleAck {
                sequence: u64::from_be_bytes(array(input, 1)?),
            })
        }
        PATH_KEEPALIVE => {
            exact(input, 9)?;
            Ok(StreamRecord::PathKeepalive {
                sequence: u64::from_be_bytes(array(input, 1)?),
            })
        }
        other => Err(StreamRecordError::UnknownType(other)),
    }
}

fn decode_file_start(
    input: &[u8],
    max_block_bytes: usize,
) -> Result<StreamRecord<'_>, StreamRecordError> {
    exact(input, 29)?;
    let block_bytes = u32::from_be_bytes(array(input, 25)?);
    let block_bytes_usize =
        usize::try_from(block_bytes).map_err(|_| StreamRecordError::InvalidGeometry)?;
    if block_bytes == 0
        || block_bytes_usize > MAX_STREAM_BLOCK_BYTES
        || block_bytes_usize > max_block_bytes
    {
        return Err(StreamRecordError::InvalidGeometry);
    }
    Ok(StreamRecord::FileStart {
        object_id: array(input, 1)?,
        length: u64::from_be_bytes(array(input, 17)?),
        block_bytes,
    })
}

fn decode_tree_start(
    input: &[u8],
    max_block_bytes: usize,
) -> Result<StreamRecord<'_>, StreamRecordError> {
    exact(input, 37)?;
    let entries = u64::from_be_bytes(array(input, 17)?);
    let block_bytes = u32::from_be_bytes(array(input, 33)?);
    let block_bytes_usize =
        usize::try_from(block_bytes).map_err(|_| StreamRecordError::InvalidGeometry)?;
    if entries == 0
        || block_bytes == 0
        || block_bytes_usize > MAX_STREAM_BLOCK_BYTES
        || block_bytes_usize > max_block_bytes
    {
        return Err(StreamRecordError::InvalidGeometry);
    }
    Ok(StreamRecord::TreeStart {
        object_id: array(input, 1)?,
        entries,
        total_length: u64::from_be_bytes(array(input, 25)?),
        block_bytes,
    })
}

fn decode_tree_entry(input: &[u8]) -> Result<StreamRecord<'_>, StreamRecordError> {
    if input.len() < 30 {
        return Err(StreamRecordError::InvalidLength);
    }
    let directory = match input[17] {
        0 => false,
        1 => true,
        _ => return Err(StreamRecordError::InvalidGeometry),
    };
    let length = u64::from_be_bytes(array(input, 18)?);
    if directory && length != 0 {
        return Err(StreamRecordError::InvalidGeometry);
    }
    let name_length = usize::from(u16::from_be_bytes(array(input, 28)?));
    if name_length == 0 || name_length > MAX_STREAM_COMPONENT_BYTES {
        return Err(StreamRecordError::InvalidGeometry);
    }
    exact(input, 30 + name_length)?;
    let name = std::str::from_utf8(input.get(30..).ok_or(StreamRecordError::InvalidLength)?)
        .map_err(|_| StreamRecordError::InvalidGeometry)?;
    let parent = u64::from_be_bytes(array(input, 9)?);
    Ok(StreamRecord::TreeEntry {
        entry: EntryId(u64::from_be_bytes(array(input, 1)?)),
        parent: (parent != u64::MAX).then_some(EntryId(parent)),
        directory,
        length,
        metadata: u16::from_be_bytes(array(input, 26)?),
        name,
    })
}

fn decode_relay_sample(input: &[u8]) -> Result<StreamRecord<'_>, StreamRecordError> {
    if input.len() < 13 {
        return Err(StreamRecordError::InvalidLength);
    }
    let length = usize::try_from(u32::from_be_bytes(array(input, 9)?))
        .map_err(|_| StreamRecordError::BlockTooLarge)?;
    if length == 0 || length > MAX_RELAY_SAMPLE_RECORD_BYTES {
        return Err(StreamRecordError::BlockTooLarge);
    }
    exact(input, 13 + length)?;
    Ok(StreamRecord::RelaySample {
        sequence: u64::from_be_bytes(array(input, 1)?),
        record: input.get(13..).ok_or(StreamRecordError::InvalidLength)?,
    })
}

fn decode_resume_record(input: &[u8], tag: u8) -> Result<StreamRecord<'_>, StreamRecordError> {
    match tag {
        RESUME_OFFER => {
            exact(input, 49)?;
            Ok(StreamRecord::ResumeOffer {
                entry: EntryId(u64::from_be_bytes(array(input, 1)?)),
                prefix: u64::from_be_bytes(array(input, 9)?),
                digest: Digest(array(input, 17)?),
            })
        }
        RESUME_DECISION => {
            exact(input, 17)?;
            Ok(StreamRecord::ResumeDecision {
                entry: EntryId(u64::from_be_bytes(array(input, 1)?)),
                prefix: u64::from_be_bytes(array(input, 9)?),
            })
        }
        _ => Err(StreamRecordError::UnknownType(tag)),
    }
}

fn exact(input: &[u8], expected: usize) -> Result<(), StreamRecordError> {
    if input.len() == expected {
        Ok(())
    } else {
        Err(StreamRecordError::InvalidLength)
    }
}

fn array<const N: usize>(input: &[u8], offset: usize) -> Result<[u8; N], StreamRecordError> {
    input
        .get(offset..offset + N)
        .ok_or(StreamRecordError::InvalidLength)?
        .try_into()
        .map_err(|_| StreamRecordError::InvalidLength)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_record_shapes_round_trip_exactly() {
        let data = b"systematic";
        let records = [
            StreamRecord::FileStart {
                object_id: [1; 16],
                length: 10,
                block_bytes: STREAM_BLOCK_BYTES,
            },
            StreamRecord::TreeStart {
                object_id: [7; 16],
                entries: 3,
                total_length: 10,
                block_bytes: STREAM_BLOCK_BYTES,
            },
            StreamRecord::TreeEntry {
                entry: EntryId(2),
                parent: Some(EntryId(1)),
                directory: false,
                length: 10,
                metadata: 3,
                name: "notes.txt",
            },
            StreamRecord::BlockData {
                block: BlockId(3),
                offset: 8,
                data,
            },
            StreamRecord::BlockSeal {
                block: BlockId(3),
                digest: Digest([2; 32]),
            },
            StreamRecord::EntrySeal {
                entry: EntryId(2),
                digest: Digest([8; 32]),
            },
            StreamRecord::ResumeOffer {
                entry: EntryId(2),
                prefix: 96 * 1024,
                digest: Digest([9; 32]),
            },
            StreamRecord::ResumeDecision {
                entry: EntryId(2),
                prefix: 96 * 1024,
            },
            StreamRecord::ObjectSeal {
                digest: Digest([3; 32]),
            },
            StreamRecord::CommitReceipt {
                digest: Digest([4; 32]),
                length: 10,
            },
            StreamRecord::Cancel { reason: 9 },
            StreamRecord::MigrationOffer {
                path_id: 17,
                sequence: 23,
            },
            StreamRecord::MigrationAccept {
                path_id: 17,
                sequence: 23,
            },
            StreamRecord::MigrationReject {
                path_id: 17,
                sequence: 23,
            },
            StreamRecord::Fallback { sequence: 23 },
            StreamRecord::RelaySample {
                sequence: 23,
                record: b"sample",
            },
            StreamRecord::RelaySampleAck { sequence: 23 },
            StreamRecord::PathKeepalive { sequence: 24 },
        ];

        for record in records {
            let encoded = record.encode().unwrap();
            assert_eq!(
                decode_stream_record(&encoded, MAX_STREAM_BLOCK_BYTES).unwrap(),
                record
            );
        }
    }

    #[test]
    fn block_length_is_exact_and_bounded_before_borrow() {
        let record = StreamRecord::BlockData {
            block: BlockId(1),
            offset: 0,
            data: b"abc",
        }
        .encode()
        .unwrap();
        assert_eq!(
            decode_stream_record(&record, 2),
            Err(StreamRecordError::BlockTooLarge)
        );
        let mut trailing = record;
        trailing.push(0);
        assert_eq!(
            decode_stream_record(&trailing, 100),
            Err(StreamRecordError::InvalidLength)
        );
    }
}
