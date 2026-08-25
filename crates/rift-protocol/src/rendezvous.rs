//! Canonical cleartext envelope for blind relay matching.
//!
//! The transfer secret and all object metadata are deliberately absent. A
//! relay learns only an opaque lookup identifier, a peer role, and whether a
//! connection was admitted.

use thiserror::Error;

const JOIN_MAGIC: [u8; 4] = *b"RFTJ";
const ACK_MAGIC: [u8; 4] = *b"RFTA";
const VERSION: u8 = 1;

/// Fixed encoded length of a rendezvous join prelude.
pub const JOIN_PRELUDE_BYTES: usize = 24;
/// Fixed encoded length of a rendezvous admission response.
pub const JOIN_ACK_BYTES: usize = 8;

/// Role visible to the rendezvous matcher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RendezvousRole {
    /// Object source.
    Sender = 1,
    /// Object sink.
    Receiver = 2,
}

/// The only cleartext request understood by a relay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JoinPrelude {
    /// Opaque, independently random match identifier.
    pub lookup_id: [u8; 16],
    /// Endpoint role within the one-shot match.
    pub role: RendezvousRole,
}

impl JoinPrelude {
    /// Encode the exact canonical request.
    #[must_use]
    pub fn encode(self) -> [u8; JOIN_PRELUDE_BYTES] {
        let mut encoded = [0_u8; JOIN_PRELUDE_BYTES];
        encoded[..4].copy_from_slice(&JOIN_MAGIC);
        encoded[4] = VERSION;
        encoded[5] = self.role as u8;
        encoded[8..].copy_from_slice(&self.lookup_id);
        encoded
    }

    /// Decode an exact, fixed-width request.
    ///
    /// # Errors
    ///
    /// Rejects bad magic, unsupported versions, unknown roles, or nonzero
    /// reserved bits before the relay accepts ownership of the connection.
    pub fn decode(encoded: &[u8; JOIN_PRELUDE_BYTES]) -> Result<Self, RendezvousError> {
        if encoded[..4] != JOIN_MAGIC {
            return Err(RendezvousError::BadMagic);
        }
        if encoded[4] != VERSION {
            return Err(RendezvousError::UnsupportedVersion);
        }
        let role = match encoded[5] {
            1 => RendezvousRole::Sender,
            2 => RendezvousRole::Receiver,
            _ => return Err(RendezvousError::UnknownRole),
        };
        if encoded[6..8] != [0, 0] {
            return Err(RendezvousError::NonCanonical);
        }
        let mut lookup_id = [0_u8; 16];
        lookup_id.copy_from_slice(&encoded[8..]);
        Ok(Self { lookup_id, role })
    }
}

/// Relay admission result. Peers begin Noise only after `Matched`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum JoinStatus {
    /// The complementary role arrived and the byte path is now connected.
    Matched = 0,
    /// This lookup-role is already owned by another live connection.
    RoleOccupied = 1,
    /// Relay admission is at its fixed resource limit.
    CapacityExhausted = 2,
    /// Prelude was malformed or unsupported.
    InvalidPrelude = 3,
    /// A waiting match expired before the peer arrived.
    Expired = 4,
    /// Relay is shutting down or cannot own the session.
    Unavailable = 5,
    /// This live endpoint exclusively owns its lookup-role until matching or expiry.
    Reserved = 6,
    /// A receiver arrived before any sender reserved this lookup.
    SenderAbsent = 7,
    /// The pair matched and a bounded route bootstrap follows this response.
    MatchedWithRoutes = 8,
}

impl JoinStatus {
    /// Encode an exact canonical response.
    #[must_use]
    pub fn encode(self) -> [u8; JOIN_ACK_BYTES] {
        let mut encoded = [0_u8; JOIN_ACK_BYTES];
        encoded[..4].copy_from_slice(&ACK_MAGIC);
        encoded[4] = VERSION;
        encoded[5] = self as u8;
        encoded
    }

    /// Decode a fixed-width response.
    ///
    /// # Errors
    ///
    /// Rejects bad magic, versions, status values, and reserved bits.
    pub fn decode(encoded: &[u8; JOIN_ACK_BYTES]) -> Result<Self, RendezvousError> {
        if encoded[..4] != ACK_MAGIC {
            return Err(RendezvousError::BadMagic);
        }
        if encoded[4] != VERSION {
            return Err(RendezvousError::UnsupportedVersion);
        }
        let status = match encoded[5] {
            0 => Self::Matched,
            1 => Self::RoleOccupied,
            2 => Self::CapacityExhausted,
            3 => Self::InvalidPrelude,
            4 => Self::Expired,
            5 => Self::Unavailable,
            6 => Self::Reserved,
            7 => Self::SenderAbsent,
            8 => Self::MatchedWithRoutes,
            _ => return Err(RendezvousError::UnknownStatus),
        };
        if encoded[6..] != [0, 0] {
            return Err(RendezvousError::NonCanonical);
        }
        Ok(status)
    }
}

/// Canonical rendezvous-envelope failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RendezvousError {
    /// Envelope is not a RIFT rendezvous record.
    #[error("invalid rendezvous envelope magic")]
    BadMagic,
    /// Peer uses a rendezvous protocol generation this implementation lacks.
    #[error("unsupported rendezvous envelope version")]
    UnsupportedVersion,
    /// Join request declares no known endpoint role.
    #[error("unknown rendezvous endpoint role")]
    UnknownRole,
    /// Relay response declares no known admission result.
    #[error("unknown rendezvous admission status")]
    UnknownStatus,
    /// Reserved bits or fields are nonzero.
    #[error("non-canonical rendezvous envelope")]
    NonCanonical,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_round_trip_reveals_only_lookup_and_role() {
        let join = JoinPrelude {
            lookup_id: [0xA5; 16],
            role: RendezvousRole::Receiver,
        };
        let encoded = join.encode();
        assert_eq!(JoinPrelude::decode(&encoded), Ok(join));
        assert_eq!(encoded.len(), JOIN_PRELUDE_BYTES);
    }

    #[test]
    fn reserved_bits_fail_closed() {
        let mut join = JoinPrelude {
            lookup_id: [7; 16],
            role: RendezvousRole::Sender,
        }
        .encode();
        join[7] = 1;
        assert_eq!(
            JoinPrelude::decode(&join),
            Err(RendezvousError::NonCanonical)
        );

        let mut ack = JoinStatus::Matched.encode();
        ack[6] = 1;
        assert_eq!(JoinStatus::decode(&ack), Err(RendezvousError::NonCanonical));
    }

    #[test]
    fn all_statuses_round_trip() {
        for status in [
            JoinStatus::Matched,
            JoinStatus::RoleOccupied,
            JoinStatus::CapacityExhausted,
            JoinStatus::InvalidPrelude,
            JoinStatus::Expired,
            JoinStatus::Unavailable,
            JoinStatus::Reserved,
            JoinStatus::SenderAbsent,
            JoinStatus::MatchedWithRoutes,
        ] {
            assert_eq!(JoinStatus::decode(&status.encode()), Ok(status));
        }
    }
}
