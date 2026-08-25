//! Fixed-width wire records for the human-code PAKE.

use thiserror::Error;

use crate::Role;

const MAGIC: [u8; 4] = *b"RFTP";
const VERSION: u8 = 1;
const HEADER_BYTES: usize = 8;
const SHARE_KIND: u8 = 1;
const CONFIRMATION_KIND: u8 = 2;

/// Uncompressed SEC1 P-256 SPAKE2 public-share length.
pub const PAIRING_SHARE_BYTES: usize = 65;
/// SHA-512 HMAC confirmation length.
pub const PAIRING_CONFIRMATION_BYTES: usize = 64;
/// Encoded fixed-width SPAKE2 public-share record length.
pub const PAIRING_SHARE_FRAME_BYTES: usize = HEADER_BYTES + PAIRING_SHARE_BYTES;
/// Encoded fixed-width explicit-confirmation record length.
pub const PAIRING_CONFIRMATION_FRAME_BYTES: usize = HEADER_BYTES + PAIRING_CONFIRMATION_BYTES;

/// Canonical SPAKE2 public share with an explicit endpoint role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairingShare {
    /// Endpoint that generated the share.
    pub role: Role,
    /// Canonical uncompressed SEC1 P-256 point.
    pub bytes: [u8; PAIRING_SHARE_BYTES],
}

impl PairingShare {
    /// Encode this share into its exact wire form.
    #[must_use]
    pub fn encode(self) -> [u8; PAIRING_SHARE_FRAME_BYTES] {
        encode_frame(SHARE_KIND, self.role, &self.bytes)
    }

    /// Decode an exact SPAKE2 share frame.
    ///
    /// # Errors
    ///
    /// Rejects the wrong magic, version, kind, role, or reserved byte.
    pub fn decode(encoded: &[u8; PAIRING_SHARE_FRAME_BYTES]) -> Result<Self, PairingFrameError> {
        let role = decode_header(encoded, SHARE_KIND)?;
        let mut bytes = [0_u8; PAIRING_SHARE_BYTES];
        bytes.copy_from_slice(&encoded[HEADER_BYTES..]);
        Ok(Self { role, bytes })
    }
}

/// Canonical explicit key-confirmation MAC with an endpoint role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairingConfirmation {
    /// Endpoint that generated the confirmation.
    pub role: Role,
    /// HMAC-SHA-512 confirmation over the SPAKE2 transcript.
    pub bytes: [u8; PAIRING_CONFIRMATION_BYTES],
}

impl PairingConfirmation {
    /// Encode this confirmation into its exact wire form.
    #[must_use]
    pub fn encode(self) -> [u8; PAIRING_CONFIRMATION_FRAME_BYTES] {
        encode_frame(CONFIRMATION_KIND, self.role, &self.bytes)
    }

    /// Decode an exact confirmation frame.
    ///
    /// # Errors
    ///
    /// Rejects the wrong magic, version, kind, role, or reserved byte.
    pub fn decode(
        encoded: &[u8; PAIRING_CONFIRMATION_FRAME_BYTES],
    ) -> Result<Self, PairingFrameError> {
        let role = decode_header(encoded, CONFIRMATION_KIND)?;
        let mut bytes = [0_u8; PAIRING_CONFIRMATION_BYTES];
        bytes.copy_from_slice(&encoded[HEADER_BYTES..]);
        Ok(Self { role, bytes })
    }
}

/// Malformed or cross-protocol pairing-handshake record.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PairingFrameError {
    /// Record does not carry the RIFT pairing magic.
    #[error("invalid pairing frame magic")]
    BadMagic,
    /// Record uses an unsupported pairing protocol version.
    #[error("unsupported pairing frame version")]
    UnsupportedVersion,
    /// Record is not the expected pairing-message kind.
    #[error("unexpected pairing frame kind")]
    UnexpectedKind,
    /// Record claims an unknown endpoint role.
    #[error("unknown pairing frame role")]
    UnknownRole,
    /// Reserved wire bits are nonzero.
    #[error("non-canonical pairing frame")]
    NonCanonical,
}

fn encode_frame<const PAYLOAD: usize, const OUTPUT: usize>(
    kind: u8,
    role: Role,
    payload: &[u8; PAYLOAD],
) -> [u8; OUTPUT] {
    debug_assert_eq!(OUTPUT, HEADER_BYTES + PAYLOAD);
    let mut encoded = [0_u8; OUTPUT];
    encoded[..4].copy_from_slice(&MAGIC);
    encoded[4] = VERSION;
    encoded[5] = kind;
    encoded[6] = match role {
        Role::Sender => 1,
        Role::Receiver => 2,
    };
    encoded[HEADER_BYTES..].copy_from_slice(payload);
    encoded
}

fn decode_header(encoded: &[u8], expected_kind: u8) -> Result<Role, PairingFrameError> {
    if encoded[..4] != MAGIC {
        return Err(PairingFrameError::BadMagic);
    }
    if encoded[4] != VERSION {
        return Err(PairingFrameError::UnsupportedVersion);
    }
    if encoded[5] != expected_kind {
        return Err(PairingFrameError::UnexpectedKind);
    }
    let role = match encoded[6] {
        1 => Role::Sender,
        2 => Role::Receiver,
        _ => return Err(PairingFrameError::UnknownRole),
    };
    if encoded[7] != 0 {
        return Err(PairingFrameError::NonCanonical);
    }
    Ok(role)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_record_kinds_round_trip_exactly() {
        let share = PairingShare {
            role: Role::Sender,
            bytes: [0xA5; PAIRING_SHARE_BYTES],
        };
        assert_eq!(PairingShare::decode(&share.encode()), Ok(share));

        let confirmation = PairingConfirmation {
            role: Role::Receiver,
            bytes: [0x5A; PAIRING_CONFIRMATION_BYTES],
        };
        assert_eq!(
            PairingConfirmation::decode(&confirmation.encode()),
            Ok(confirmation)
        );
    }

    #[test]
    fn cross_kind_role_and_reserved_mutations_fail_closed() {
        let share = PairingShare {
            role: Role::Sender,
            bytes: [7; PAIRING_SHARE_BYTES],
        }
        .encode();

        let mut wrong_kind = share;
        wrong_kind[5] = CONFIRMATION_KIND;
        assert_eq!(
            PairingShare::decode(&wrong_kind),
            Err(PairingFrameError::UnexpectedKind)
        );

        let mut wrong_role = share;
        wrong_role[6] = 3;
        assert_eq!(
            PairingShare::decode(&wrong_role),
            Err(PairingFrameError::UnknownRole)
        );

        let mut reserved = share;
        reserved[7] = 1;
        assert_eq!(
            PairingShare::decode(&reserved),
            Err(PairingFrameError::NonCanonical)
        );
    }
}
