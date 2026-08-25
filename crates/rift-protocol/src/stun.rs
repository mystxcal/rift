//! Bounded RFC 8489 STUN binding codec for server-reflexive discovery.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use thiserror::Error;

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const BINDING_ERROR: u16 = 0x0111;
const MAGIC_COOKIE: u32 = 0x2112_A442;
const MAPPED_ADDRESS: u16 = 0x0001;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const FINGERPRINT: u16 = 0x8028;
const FINGERPRINT_XOR: u32 = 0x5354_554e;
const HEADER_BYTES: usize = 20;

/// Binding request header plus a final FINGERPRINT attribute.
pub const BINDING_REQUEST_BYTES: usize = 28;
/// Datagram allocation ceiling for candidate discovery.
pub const MAX_STUN_MESSAGE_BYTES: usize = 1_200;

/// Uniformly random RFC 8489 transaction identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionId(pub [u8; 12]);

/// Malformed, unrelated, or unsuccessful STUN response.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum StunError {
    /// Datagram is too short, too large, truncated, or has trailing bytes.
    #[error("malformed STUN message length")]
    InvalidLength,
    /// Header is not canonical STUN.
    #[error("invalid STUN header")]
    InvalidHeader,
    /// Response belongs to another transaction.
    #[error("STUN transaction id mismatch")]
    TransactionMismatch,
    /// Server returned a Binding error response.
    #[error("STUN server rejected the Binding request")]
    BindingRejected,
    /// Response uses an unsupported comprehension-required attribute.
    #[error("unsupported required STUN attribute")]
    UnknownRequiredAttribute,
    /// Address attribute is missing, malformed, or internally conflicting.
    #[error("invalid STUN mapped address")]
    InvalidMappedAddress,
    /// Optional fingerprint is malformed, misplaced, or incorrect.
    #[error("invalid STUN fingerprint")]
    InvalidFingerprint,
}

/// Encode an unauthenticated Binding request with a demultiplexing fingerprint.
#[must_use]
pub fn encode_binding_request(transaction: TransactionId) -> [u8; BINDING_REQUEST_BYTES] {
    let mut message = [0_u8; BINDING_REQUEST_BYTES];
    message[..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    message[2..4].copy_from_slice(&8_u16.to_be_bytes());
    message[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    message[8..20].copy_from_slice(&transaction.0);
    message[20..22].copy_from_slice(&FINGERPRINT.to_be_bytes());
    message[22..24].copy_from_slice(&4_u16.to_be_bytes());
    let fingerprint = crc32fast::hash(&message[..20]) ^ FINGERPRINT_XOR;
    message[24..28].copy_from_slice(&fingerprint.to_be_bytes());
    message
}

/// Decode one exact Binding success response and recover its mapped address.
///
/// # Errors
///
/// Parsing is total and bounded. It rejects wrong transactions, error
/// responses, truncation, trailing bytes, unknown required attributes,
/// conflicting mapped addresses, and bad fingerprints.
pub fn decode_binding_response(
    message: &[u8],
    transaction: TransactionId,
) -> Result<SocketAddr, StunError> {
    if !(HEADER_BYTES..=MAX_STUN_MESSAGE_BYTES).contains(&message.len()) {
        return Err(StunError::InvalidLength);
    }
    if message[0] & 0xC0 != 0 {
        return Err(StunError::InvalidHeader);
    }
    let message_type = u16::from_be_bytes([message[0], message[1]]);
    if message_type == BINDING_ERROR {
        return Err(StunError::BindingRejected);
    }
    if message_type != BINDING_SUCCESS
        || u32::from_be_bytes([message[4], message[5], message[6], message[7]]) != MAGIC_COOKIE
    {
        return Err(StunError::InvalidHeader);
    }
    if message[8..20] != transaction.0 {
        return Err(StunError::TransactionMismatch);
    }
    let body_length = usize::from(u16::from_be_bytes([message[2], message[3]]));
    if body_length % 4 != 0 || HEADER_BYTES.checked_add(body_length) != Some(message.len()) {
        return Err(StunError::InvalidLength);
    }

    let mut direct = None;
    let mut obfuscated = None;
    let mut offset = HEADER_BYTES;
    while offset < message.len() {
        let header_end = offset.checked_add(4).ok_or(StunError::InvalidLength)?;
        if header_end > message.len() {
            return Err(StunError::InvalidLength);
        }
        let attribute_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let value_length = usize::from(u16::from_be_bytes([
            message[offset + 2],
            message[offset + 3],
        ]));
        let value_end = header_end
            .checked_add(value_length)
            .ok_or(StunError::InvalidLength)?;
        let padded_end = header_end
            .checked_add(value_length.saturating_add(3) & !3)
            .ok_or(StunError::InvalidLength)?;
        if value_end > message.len() || padded_end > message.len() {
            return Err(StunError::InvalidLength);
        }
        let value = &message[header_end..value_end];

        match attribute_type {
            XOR_MAPPED_ADDRESS => {
                merge_address(&mut obfuscated, decode_address(value, true, transaction)?)?;
            }
            MAPPED_ADDRESS => {
                merge_address(&mut direct, decode_address(value, false, transaction)?)?;
            }
            FINGERPRINT => {
                if value_length != 4 || padded_end != message.len() {
                    return Err(StunError::InvalidFingerprint);
                }
                let supplied = u32::from_be_bytes(
                    value
                        .try_into()
                        .map_err(|_| StunError::InvalidFingerprint)?,
                );
                let observed = crc32fast::hash(&message[..offset]) ^ FINGERPRINT_XOR;
                if supplied != observed {
                    return Err(StunError::InvalidFingerprint);
                }
            }
            unknown if unknown < 0x8000 => {
                return Err(StunError::UnknownRequiredAttribute);
            }
            _ => {}
        }
        offset = padded_end;
    }

    if direct
        .zip(obfuscated)
        .is_some_and(|(direct, obfuscated)| direct != obfuscated)
    {
        return Err(StunError::InvalidMappedAddress);
    }
    obfuscated.or(direct).ok_or(StunError::InvalidMappedAddress)
}

fn merge_address(slot: &mut Option<SocketAddr>, address: SocketAddr) -> Result<(), StunError> {
    if slot.is_some_and(|existing| existing != address) {
        return Err(StunError::InvalidMappedAddress);
    }
    *slot = Some(address);
    Ok(())
}

fn decode_address(
    value: &[u8],
    xor: bool,
    transaction: TransactionId,
) -> Result<SocketAddr, StunError> {
    if value.len() < 4 || value[0] != 0 {
        return Err(StunError::InvalidMappedAddress);
    }
    let mut port = u16::from_be_bytes([value[2], value[3]]);
    if xor {
        port ^= (MAGIC_COOKIE >> 16) as u16;
    }

    match value[1] {
        0x01 if value.len() == 8 => {
            let mut octets: [u8; 4] = value[4..]
                .try_into()
                .map_err(|_| StunError::InvalidMappedAddress)?;
            if xor {
                for (byte, mask) in octets.iter_mut().zip(MAGIC_COOKIE.to_be_bytes()) {
                    *byte ^= mask;
                }
            }
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        0x02 if value.len() == 20 => {
            let mut octets: [u8; 16] = value[4..]
                .try_into()
                .map_err(|_| StunError::InvalidMappedAddress)?;
            if xor {
                let mut mask = [0_u8; 16];
                mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                mask[4..].copy_from_slice(&transaction.0);
                for (byte, mask) in octets.iter_mut().zip(mask) {
                    *byte ^= mask;
                }
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => Err(StunError::InvalidMappedAddress),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(transaction: TransactionId, mapped: SocketAddr, fingerprint: bool) -> Vec<u8> {
        let address_bytes = match mapped.ip() {
            IpAddr::V4(address) => {
                let mut value = vec![0, 1];
                value.extend_from_slice(&(mapped.port() ^ 0x2112).to_be_bytes());
                for (byte, mask) in address.octets().iter().zip(MAGIC_COOKIE.to_be_bytes()) {
                    value.push(*byte ^ mask);
                }
                value
            }
            IpAddr::V6(address) => {
                let mut value = vec![0, 2];
                value.extend_from_slice(&(mapped.port() ^ 0x2112).to_be_bytes());
                let mut mask = [0_u8; 16];
                mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                mask[4..].copy_from_slice(&transaction.0);
                for (byte, mask) in address.octets().iter().zip(mask) {
                    value.push(*byte ^ mask);
                }
                value
            }
        };
        let mut message = vec![0_u8; HEADER_BYTES];
        message[..2].copy_from_slice(&BINDING_SUCCESS.to_be_bytes());
        message[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        message[8..20].copy_from_slice(&transaction.0);
        message.extend_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
        message.extend_from_slice(&u16::try_from(address_bytes.len()).unwrap().to_be_bytes());
        message.extend_from_slice(&address_bytes);
        if fingerprint {
            let body_length = u16::try_from(message.len() + 8 - HEADER_BYTES).unwrap();
            message[2..4].copy_from_slice(&body_length.to_be_bytes());
            let observed = crc32fast::hash(&message) ^ FINGERPRINT_XOR;
            message.extend_from_slice(&FINGERPRINT.to_be_bytes());
            message.extend_from_slice(&4_u16.to_be_bytes());
            message.extend_from_slice(&observed.to_be_bytes());
        } else {
            let body_length = u16::try_from(message.len() - HEADER_BYTES).unwrap();
            message[2..4].copy_from_slice(&body_length.to_be_bytes());
        }
        message
    }

    #[test]
    fn request_has_random_identity_slot_and_valid_fingerprint() {
        let transaction = TransactionId([7; 12]);
        let request = encode_binding_request(transaction);
        assert_eq!(&request[..2], &BINDING_REQUEST.to_be_bytes());
        assert_eq!(&request[4..8], &MAGIC_COOKIE.to_be_bytes());
        assert_eq!(&request[8..20], &transaction.0);
        let supplied = u32::from_be_bytes(request[24..28].try_into().unwrap());
        assert_eq!(supplied, crc32fast::hash(&request[..20]) ^ FINGERPRINT_XOR);
    }

    #[test]
    fn decodes_ipv4_and_ipv6_xor_mapped_addresses() {
        let transaction = TransactionId([3; 12]);
        for mapped in [
            "203.0.113.9:4242".parse().unwrap(),
            "[2001:db8::1234]:6553".parse().unwrap(),
        ] {
            assert_eq!(
                decode_binding_response(&response(transaction, mapped, true), transaction),
                Ok(mapped)
            );
        }
    }

    #[test]
    fn conflicting_direct_and_obfuscated_addresses_fail_closed() {
        let transaction = TransactionId([4; 12]);
        let mut message = response(transaction, "203.0.113.9:4242".parse().unwrap(), false);
        let direct: SocketAddr = "198.51.100.7:9000".parse().unwrap();
        let SocketAddr::V4(direct) = direct else {
            unreachable!();
        };
        message.extend_from_slice(&MAPPED_ADDRESS.to_be_bytes());
        message.extend_from_slice(&8_u16.to_be_bytes());
        message.extend_from_slice(&[0, 1]);
        message.extend_from_slice(&direct.port().to_be_bytes());
        message.extend_from_slice(&direct.ip().octets());
        let body_length = u16::try_from(message.len() - HEADER_BYTES).unwrap();
        message[2..4].copy_from_slice(&body_length.to_be_bytes());

        assert_eq!(
            decode_binding_response(&message, transaction),
            Err(StunError::InvalidMappedAddress)
        );
    }

    #[test]
    fn rejects_wrong_transaction_trailing_bytes_and_bad_fingerprint() {
        let transaction = TransactionId([1; 12]);
        let mapped = "203.0.113.1:9".parse().unwrap();
        let valid = response(transaction, mapped, true);
        assert_eq!(
            decode_binding_response(&valid, TransactionId([2; 12])),
            Err(StunError::TransactionMismatch)
        );
        let mut trailing = valid.clone();
        trailing.push(0);
        assert_eq!(
            decode_binding_response(&trailing, transaction),
            Err(StunError::InvalidLength)
        );
        let mut corrupt = valid;
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert_eq!(
            decode_binding_response(&corrupt, transaction),
            Err(StunError::InvalidFingerprint)
        );
    }

    #[test]
    fn unknown_required_attribute_fails_closed() {
        let transaction = TransactionId([4; 12]);
        let mut message = response(transaction, "203.0.113.2:8".parse().unwrap(), false);
        message.extend_from_slice(&0x0002_u16.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        let length = u16::try_from(message.len() - HEADER_BYTES).unwrap();
        message[2..4].copy_from_slice(&length.to_be_bytes());
        assert_eq!(
            decode_binding_response(&message, transaction),
            Err(StunError::UnknownRequiredAttribute)
        );
    }
}
