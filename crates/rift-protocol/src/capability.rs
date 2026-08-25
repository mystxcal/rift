//! Canonical, high-entropy transfer capabilities.

use std::{fmt, net::SocketAddr, str::FromStr};

use data_encoding::{BASE32_NOPAD, BASE64URL_NOPAD};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

const VERSION: &str = "rift1";
const LOOKUP_LEN: usize = 16;
const SECRET_LEN: usize = 32;
const CHECKSUM_LEN: usize = 6;
const MAX_LOCATOR_LEN: usize = 2_048;

/// Possession capability for exactly one transfer rendezvous.
#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct Capability {
    #[zeroize(skip)]
    rendezvous: String,
    lookup_id: [u8; LOOKUP_LEN],
    secret: [u8; SECRET_LEN],
}

impl Capability {
    /// Create a capability from explicit cryptographic material.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityError::InvalidLocator`] when the rendezvous is not a
    /// bounded, visible ASCII `HTTPS` locator.
    pub fn from_parts(
        rendezvous: impl Into<String>,
        lookup_id: [u8; LOOKUP_LEN],
        secret: [u8; SECRET_LEN],
    ) -> Result<Self, CapabilityError> {
        let rendezvous = rendezvous.into();
        validate_locator(&rendezvous)?;
        Ok(Self {
            rendezvous,
            lookup_id,
            secret,
        })
    }

    /// Generate independent lookup and authorization material from the OS CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityError`] when the locator is invalid or the operating
    /// system cannot provide cryptographic entropy.
    pub fn generate(rendezvous: impl Into<String>) -> Result<Self, CapabilityError> {
        let mut lookup_id = [0_u8; LOOKUP_LEN];
        let mut secret = [0_u8; SECRET_LEN];
        getrandom::fill(&mut lookup_id).map_err(|_| CapabilityError::EntropyUnavailable)?;
        getrandom::fill(&mut secret).map_err(|_| CapabilityError::EntropyUnavailable)?;
        Self::from_parts(rendezvous, lookup_id, secret)
    }

    /// Rendezvous endpoint carried by the capability.
    #[must_use]
    pub fn rendezvous(&self) -> &str {
        &self.rendezvous
    }

    /// Opaque identifier that may be disclosed to the rendezvous.
    #[must_use]
    pub fn lookup_id(&self) -> &[u8; LOOKUP_LEN] {
        &self.lookup_id
    }

    /// PSK material. Callers must avoid logs and long-lived copies.
    #[must_use]
    pub fn secret(&self) -> &[u8; SECRET_LEN] {
        &self.secret
    }

    /// Canonical printable capability.
    #[must_use]
    pub fn expose(&self) -> String {
        let locator = BASE64URL_NOPAD.encode(self.rendezvous.as_bytes());
        let lookup = BASE32_NOPAD.encode(&self.lookup_id);
        let secret = BASE32_NOPAD.encode(&self.secret);
        let prefix = format!("{VERSION}.{locator}.{lookup}.{secret}");
        let checksum = checksum(&prefix);
        format!("{prefix}.{}", BASE32_NOPAD.encode(&checksum))
    }
}

impl fmt::Debug for Capability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Capability")
            .field("rendezvous", &self.rendezvous)
            .field("lookup_id", &BASE32_NOPAD.encode(&self.lookup_id))
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.expose())
    }
}

impl FromStr for Capability {
    type Err = CapabilityError;

    fn from_str(encoded: &str) -> Result<Self, Self::Err> {
        let mut fields = encoded.split('.');
        let version = fields.next().ok_or(CapabilityError::Malformed)?;
        let locator_text = fields.next().ok_or(CapabilityError::Malformed)?;
        let lookup_text = fields.next().ok_or(CapabilityError::Malformed)?;
        let secret_text = fields.next().ok_or(CapabilityError::Malformed)?;
        let checksum_text = fields.next().ok_or(CapabilityError::Malformed)?;
        if fields.next().is_some() || version != VERSION {
            return Err(if version == VERSION {
                CapabilityError::Malformed
            } else {
                CapabilityError::UnsupportedVersion
            });
        }

        let prefix = format!("{version}.{locator_text}.{lookup_text}.{secret_text}");
        let supplied_checksum = decode_canonical::<CHECKSUM_LEN>(checksum_text)?;
        if checksum(&prefix).ct_eq(&supplied_checksum).unwrap_u8() != 1 {
            return Err(CapabilityError::ChecksumMismatch);
        }

        let locator_bytes = BASE64URL_NOPAD
            .decode(locator_text.as_bytes())
            .map_err(|_| CapabilityError::Malformed)?;
        if BASE64URL_NOPAD.encode(&locator_bytes) != locator_text {
            return Err(CapabilityError::NonCanonical);
        }
        let rendezvous =
            String::from_utf8(locator_bytes).map_err(|_| CapabilityError::Malformed)?;
        let lookup_id = decode_canonical::<LOOKUP_LEN>(lookup_text)?;
        let secret = decode_canonical::<SECRET_LEN>(secret_text)?;
        Self::from_parts(rendezvous, lookup_id, secret)
    }
}

/// Capability decoding or generation failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CapabilityError {
    /// Token syntax or encoding is malformed.
    #[error("malformed RIFT capability")]
    Malformed,
    /// Token uses an unsupported protocol generation.
    #[error("unsupported RIFT capability version")]
    UnsupportedVersion,
    /// Token text is valid but not in canonical form.
    #[error("non-canonical RIFT capability")]
    NonCanonical,
    /// Checksum does not authenticate the typed token.
    #[error("RIFT capability checksum mismatch")]
    ChecksumMismatch,
    /// Rendezvous locator violates the capability contract.
    #[error("invalid rendezvous locator")]
    InvalidLocator,
    /// Secure OS entropy was unavailable.
    #[error("secure operating-system entropy unavailable")]
    EntropyUnavailable,
}

fn validate_locator(locator: &str) -> Result<(), CapabilityError> {
    if locator.is_empty() || locator.len() > MAX_LOCATOR_LEN || !locator.is_ascii() {
        return Err(CapabilityError::InvalidLocator);
    }
    if locator.starts_with("https://") && locator.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Ok(());
    }
    if let Some(address) = locator.strip_prefix("rift+tcp://") {
        let address = address
            .parse::<SocketAddr>()
            .map_err(|_| CapabilityError::InvalidLocator)?;
        if address.ip().is_loopback() {
            return Ok(());
        }
    }
    Err(CapabilityError::InvalidLocator)
}

fn checksum(prefix: &str) -> [u8; CHECKSUM_LEN] {
    let digest = blake3::hash(prefix.as_bytes());
    let mut result = [0_u8; CHECKSUM_LEN];
    result.copy_from_slice(&digest.as_bytes()[..CHECKSUM_LEN]);
    result
}

fn decode_canonical<const N: usize>(encoded: &str) -> Result<[u8; N], CapabilityError> {
    let bytes = BASE32_NOPAD
        .decode(encoded.as_bytes())
        .map_err(|_| CapabilityError::Malformed)?;
    if bytes.len() != N {
        return Err(CapabilityError::Malformed);
    }
    if BASE32_NOPAD.encode(&bytes) != encoded {
        return Err(CapabilityError::NonCanonical);
    }
    bytes.try_into().map_err(|_| CapabilityError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_round_trip_and_redacted_debug() {
        let capability = Capability::from_parts("https://r.example", [1; 16], [2; 32]).unwrap();
        let encoded = capability.expose();
        assert_eq!(encoded.parse::<Capability>().unwrap(), capability);
        let debug = format!("{capability:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains(&BASE32_NOPAD.encode(&[2; 32])));
    }

    #[test]
    fn typo_fails_checksum_before_use() {
        let capability = Capability::from_parts("https://r.example", [1; 16], [2; 32]).unwrap();
        let mut encoded = capability.expose();
        let last = encoded.pop().unwrap();
        encoded.push(if last == 'A' { 'B' } else { 'A' });
        assert_eq!(
            encoded.parse::<Capability>(),
            Err(CapabilityError::ChecksumMismatch)
        );
    }

    #[test]
    fn rejects_insecure_or_noncanonical_locator() {
        assert_eq!(
            Capability::from_parts("http://r.example", [1; 16], [2; 32]),
            Err(CapabilityError::InvalidLocator)
        );
    }

    #[test]
    fn raw_tcp_capabilities_are_loopback_only() {
        assert!(Capability::from_parts("rift+tcp://127.0.0.1:7000", [1; 16], [2; 32]).is_ok());
        assert_eq!(
            Capability::from_parts("rift+tcp://192.0.2.1:7000", [1; 16], [2; 32]),
            Err(CapabilityError::InvalidLocator)
        );
    }
}
