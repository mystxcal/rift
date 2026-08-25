//! Negotiated limits and immutable manifest declarations.

use rift_core::{Digest, EntryId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Hard admission limits negotiated before object records are accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HardLimits {
    /// Maximum manifest records.
    pub max_entries: u64,
    /// Maximum UTF-8 path bytes.
    pub max_path_bytes: u32,
    /// Maximum path component depth.
    pub max_depth: u16,
    /// Maximum simultaneously active source blocks.
    pub max_active_blocks: u16,
    /// Maximum logical bytes in the authenticated object.
    pub max_object_bytes: u64,
    /// Maximum authenticated payload per native packet.
    pub max_packet_payload: u32,
    /// Maximum bytes resident in receiver reconstruction buffers.
    pub max_reconstruction_bytes: u64,
}

impl HardLimits {
    /// Conservative baseline for interoperable implementations.
    pub const CONSERVATIVE: Self = Self {
        max_entries: 1_000_000,
        max_path_bytes: 4_096,
        max_depth: 256,
        max_active_blocks: 64,
        max_object_bytes: 16 * 1024 * 1024 * 1024 * 1024,
        max_packet_payload: 1_200,
        max_reconstruction_bytes: 256 * 1024 * 1024,
    };

    /// Reject nonsensical limits before committing memory or network work.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::InvalidLimits`] for zero, unsafe, or internally
    /// inconsistent bounds.
    pub fn validate(self) -> Result<Self, ManifestError> {
        if self.max_entries == 0
            || self.max_path_bytes == 0
            || self.max_depth == 0
            || self.max_active_blocks == 0
            || self.max_object_bytes == 0
            || !(512..=65_507).contains(&self.max_packet_payload)
            || self.max_reconstruction_bytes < u64::from(self.max_packet_payload)
        {
            return Err(ManifestError::InvalidLimits);
        }
        Ok(self)
    }

    /// Negotiate the strict component-wise intersection of two resource caps.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::InvalidLimits`] when the intersection cannot
    /// support a valid protocol envelope.
    pub fn intersect(self, peer: Self) -> Result<Self, ManifestError> {
        Self {
            max_entries: self.max_entries.min(peer.max_entries),
            max_path_bytes: self.max_path_bytes.min(peer.max_path_bytes),
            max_depth: self.max_depth.min(peer.max_depth),
            max_active_blocks: self.max_active_blocks.min(peer.max_active_blocks),
            max_object_bytes: self.max_object_bytes.min(peer.max_object_bytes),
            max_packet_payload: self.max_packet_payload.min(peer.max_packet_payload),
            max_reconstruction_bytes: self
                .max_reconstruction_bytes
                .min(peer.max_reconstruction_bytes),
        }
        .validate()
    }
}

/// First immutable declaration for an object stream.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObjectStart {
    /// Random transfer-local object identifier.
    pub object_id: [u8; 16],
    /// Sender's declared limits, intersected with receiver limits before use.
    pub limits: HardLimits,
}

/// Supported manifest entry semantics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EntryKind {
    /// Directory node.
    Directory,
    /// Regular file and its logical byte length.
    File {
        /// Logical file length in bytes.
        length: u64,
    },
    /// Symbolic link. Receivers may reject this capability during negotiation.
    SymbolicLink {
        /// Link target as declared by the sender.
        target: String,
    },
}

/// Immutable manifest entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EntryRecord {
    /// Stable entry identifier.
    pub id: EntryId,
    /// Parent entry, absent only for the root.
    pub parent: Option<EntryId>,
    /// One path component, never an absolute or multi-component path.
    pub name: String,
    /// Entry payload semantics.
    pub kind: EntryKind,
    /// Canonical metadata digest, allowing platform-specific negotiation.
    pub metadata_digest: Digest,
}

/// Manifest contract violation.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ManifestError {
    /// One or more negotiated limits are zero, unsafe, or inconsistent.
    #[error("invalid negotiated hard limits")]
    InvalidLimits,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conservative_limits_are_valid() {
        assert_eq!(
            HardLimits::CONSERVATIVE.validate().unwrap(),
            HardLimits::CONSERVATIVE
        );
    }

    #[test]
    fn payload_cannot_exceed_udp_envelope_bound() {
        let limits = HardLimits {
            max_packet_payload: 70_000,
            ..HardLimits::CONSERVATIVE
        };
        assert_eq!(limits.validate(), Err(ManifestError::InvalidLimits));
    }
}
