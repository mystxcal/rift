//! Canonical handshake context and deterministic negotiation.

use thiserror::Error;

use crate::manifest::HardLimits;

const PROTOCOL_VERSION: u16 = 1;
const PROLOGUE_MAGIC: [u8; 8] = *b"RIFTHS01";

/// Stable endpoint role bound into the authenticated transcript.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Role {
    /// Endpoint declaring and transmitting the object.
    Sender = 1,
    /// Endpoint reconstructing and committing the object.
    Receiver = 2,
}

/// Bitsets of algorithms an endpoint can execute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlgorithmOffer {
    /// Supported AEAD identifiers.
    pub aead: u32,
    /// Supported block coding identifiers.
    pub coding: u32,
    /// Supported compression identifiers.
    pub compression: u32,
    /// Supported object representation identifiers.
    pub representation: u32,
}

/// One selected algorithm from each negotiated family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectedAlgorithms {
    /// Selected AEAD identifier in `0..32`.
    pub aead: u8,
    /// Selected coding identifier in `0..32`.
    pub coding: u8,
    /// Selected compression identifier in `0..32`.
    pub compression: u8,
    /// Selected representation identifier in `0..32`.
    pub representation: u8,
}

/// Everything security-relevant that precedes the ephemeral handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandshakePrologue {
    /// Public lookup component of the transfer capability.
    pub lookup_id: [u8; 16],
    /// Initiating endpoint role.
    pub initiator_role: Role,
    /// Negotiated hard resource bounds.
    pub limits: HardLimits,
    /// Negotiated algorithms.
    pub algorithms: SelectedAlgorithms,
    /// Identity of the path on which this handshake began.
    pub initial_path_id: u32,
}

/// Failed deterministic negotiation or transcript construction.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum HandshakeError {
    /// At least one required algorithm family has no common implementation.
    #[error("peers have no complete common algorithm suite")]
    NoCommonAlgorithms,
    /// A selected identifier is outside its offered family.
    #[error("selected algorithm was not offered by both peers")]
    InvalidSelection,
}

impl AlgorithmOffer {
    /// Intersect two offers without silently selecting an algorithm.
    #[must_use]
    pub fn intersect(self, peer: Self) -> Self {
        Self {
            aead: self.aead & peer.aead,
            coding: self.coding & peer.coding,
            compression: self.compression & peer.compression,
            representation: self.representation & peer.representation,
        }
    }

    /// Whether every required family retains at least one implementation.
    #[must_use]
    pub fn is_complete(self) -> bool {
        self.aead != 0 && self.coding != 0 && self.compression != 0 && self.representation != 0
    }

    /// Deterministically select the lowest common identifier in each family.
    /// Preference negotiation may replace this policy later without changing
    /// transcript validation.
    ///
    /// # Errors
    ///
    /// Returns [`HandshakeError::NoCommonAlgorithms`] when any required family
    /// has an empty intersection.
    pub fn select_lowest(self) -> Result<SelectedAlgorithms, HandshakeError> {
        if !self.is_complete() {
            return Err(HandshakeError::NoCommonAlgorithms);
        }
        Ok(SelectedAlgorithms {
            aead: lowest(self.aead)?,
            coding: lowest(self.coding)?,
            compression: lowest(self.compression)?,
            representation: lowest(self.representation)?,
        })
    }

    /// Prove that a selection belongs to this already-intersected offer.
    ///
    /// # Errors
    ///
    /// Returns [`HandshakeError::InvalidSelection`] when any identifier was
    /// not offered in its corresponding family.
    pub fn validate_selection(
        self,
        selected: SelectedAlgorithms,
    ) -> Result<SelectedAlgorithms, HandshakeError> {
        let contains = |set: u32, id: u8| id < 32 && (set & (1_u32 << id)) != 0;
        if contains(self.aead, selected.aead)
            && contains(self.coding, selected.coding)
            && contains(self.compression, selected.compression)
            && contains(self.representation, selected.representation)
        {
            Ok(selected)
        } else {
            Err(HandshakeError::InvalidSelection)
        }
    }
}

fn lowest(set: u32) -> Result<u8, HandshakeError> {
    u8::try_from(set.trailing_zeros()).map_err(|_| HandshakeError::NoCommonAlgorithms)
}

impl HandshakePrologue {
    /// Canonical fixed-width transcript bytes consumed as Noise prologue data.
    #[must_use]
    pub fn encode(self) -> [u8; 71] {
        let mut output = [0_u8; 71];
        let mut cursor = 0;
        put(&mut output, &mut cursor, &PROLOGUE_MAGIC);
        put(&mut output, &mut cursor, &PROTOCOL_VERSION.to_be_bytes());
        put(&mut output, &mut cursor, &self.lookup_id);
        put(&mut output, &mut cursor, &[self.initiator_role.encode()]);
        put(
            &mut output,
            &mut cursor,
            &self.limits.max_entries.to_be_bytes(),
        );
        put(
            &mut output,
            &mut cursor,
            &self.limits.max_path_bytes.to_be_bytes(),
        );
        put(
            &mut output,
            &mut cursor,
            &self.limits.max_depth.to_be_bytes(),
        );
        put(
            &mut output,
            &mut cursor,
            &self.limits.max_active_blocks.to_be_bytes(),
        );
        put(
            &mut output,
            &mut cursor,
            &self.limits.max_packet_payload.to_be_bytes(),
        );
        put(
            &mut output,
            &mut cursor,
            &self.limits.max_object_bytes.to_be_bytes(),
        );
        put(
            &mut output,
            &mut cursor,
            &self.limits.max_reconstruction_bytes.to_be_bytes(),
        );
        put(
            &mut output,
            &mut cursor,
            &[
                self.algorithms.aead,
                self.algorithms.coding,
                self.algorithms.compression,
                self.algorithms.representation,
            ],
        );
        put(
            &mut output,
            &mut cursor,
            &self.initial_path_id.to_be_bytes(),
        );
        debug_assert_eq!(cursor, output.len());
        output
    }
}

impl Role {
    const fn encode(self) -> u8 {
        match self {
            Self::Sender => 1,
            Self::Receiver => 2,
        }
    }
}

fn put<const N: usize>(output: &mut [u8; N], cursor: &mut usize, bytes: &[u8]) {
    let end = *cursor + bytes.len();
    output[*cursor..end].copy_from_slice(bytes);
    *cursor = end;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intersection_and_selection_are_explicit() {
        let local = AlgorithmOffer {
            aead: 0b101,
            coding: 0b110,
            compression: 0b111,
            representation: 0b100,
        };
        let peer = AlgorithmOffer {
            aead: 0b100,
            coding: 0b010,
            compression: 0b010,
            representation: 0b101,
        };
        let common = local.intersect(peer);
        assert_eq!(
            common.select_lowest().unwrap(),
            SelectedAlgorithms {
                aead: 2,
                coding: 1,
                compression: 1,
                representation: 2,
            }
        );
    }

    #[test]
    fn prologue_changes_when_any_security_context_changes() {
        let base = HandshakePrologue {
            lookup_id: [1; 16],
            initiator_role: Role::Sender,
            limits: HardLimits::CONSERVATIVE,
            algorithms: SelectedAlgorithms {
                aead: 1,
                coding: 0,
                compression: 0,
                representation: 0,
            },
            initial_path_id: 4,
        };
        let mut changed = base;
        changed.initial_path_id = 5;
        assert_ne!(base.encode(), changed.encode());
        changed = base;
        changed.initiator_role = Role::Receiver;
        assert_ne!(base.encode(), changed.encode());
    }
}
