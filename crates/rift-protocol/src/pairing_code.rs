//! Compact, human-readable pairing codes.

use std::{fmt, str::FromStr};

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const CONSONANTS: &[u8; 16] = b"bcdfghjklmnprstv";
const VOWELS: &[u8; 6] = b"aeiouy";
const VOWEL_SLOTS: u32 = 6;
const SYLLABLE_SLOTS: u32 = 96;
const WORD_SLOTS: u32 = SYLLABLE_SLOTS * SYLLABLE_SLOTS * SYLLABLE_SLOTS;
const NAMEPLATE_SLOTS: u16 = 10_000;
const CODE_BYTES: usize = 11;
const WORD_BYTES: usize = 6;

/// A four-digit public nameplate and one pronounceable secret word.
///
/// The digits locate a live rendezvous. The word is intended to be consumed by
/// a one-shot PAKE and must never be sent to or logged by the relay.
#[derive(Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct PairingCode {
    nameplate: u16,
    word: u32,
}

impl PairingCode {
    /// Generate a uniformly distributed pairing code from the OS CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns [`PairingCodeError::EntropyUnavailable`] if the operating
    /// system cannot provide cryptographic entropy.
    pub fn generate() -> Result<Self, PairingCodeError> {
        let nameplate = random_nameplate()?;
        let word = random_below(WORD_SLOTS)?;
        Ok(Self { nameplate, word })
    }

    /// Public four-digit rendezvous nameplate.
    #[must_use]
    pub fn nameplate(&self) -> u16 {
        self.nameplate
    }

    /// Opaque relay lookup derived only from the public nameplate.
    #[must_use]
    pub fn lookup_id(&self) -> [u8; 16] {
        let digest = blake3::derive_key(
            "RIFT v1 human nameplate lookup",
            &self.nameplate.to_be_bytes(),
        );
        let mut lookup = [0_u8; 16];
        lookup.copy_from_slice(&digest[..16]);
        lookup
    }

    /// Canonical bytes for the PAKE password input.
    ///
    /// The returned temporary erases itself on drop.
    #[must_use]
    pub fn password_bytes(&self) -> Zeroizing<[u8; CODE_BYTES]> {
        let mut output = [0_u8; CODE_BYTES];
        output[0] = b'0' + (self.nameplate / 1_000) as u8;
        output[1] = b'0' + ((self.nameplate / 100) % 10) as u8;
        output[2] = b'0' + ((self.nameplate / 10) % 10) as u8;
        output[3] = b'0' + (self.nameplate % 10) as u8;
        output[4] = b'-';
        encode_word(self.word, &mut output[5..]);
        Zeroizing::new(output)
    }
}

impl fmt::Debug for PairingCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingCode")
            .field("nameplate", &format_args!("{:04}", self.nameplate))
            .field("word", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Display for PairingCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.password_bytes();
        let text = std::str::from_utf8(bytes.as_ref()).map_err(|_| fmt::Error)?;
        formatter.write_str(text)
    }
}

impl FromStr for PairingCode {
    type Err = PairingCodeError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let bytes = text.as_bytes();
        if bytes.len() != CODE_BYTES
            || bytes[4] != b'-'
            || !bytes[..4].iter().all(u8::is_ascii_digit)
        {
            return Err(PairingCodeError::Malformed);
        }
        let nameplate = bytes[..4]
            .iter()
            .fold(0_u16, |value, digit| value * 10 + u16::from(*digit - b'0'));
        let word = decode_word(&bytes[5..])?;
        Ok(Self { nameplate, word })
    }
}

/// Pairing-code generation or decoding failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PairingCodeError {
    /// Code syntax is malformed or not canonical.
    #[error("malformed RIFT pairing code")]
    Malformed,
    /// Secure OS entropy was unavailable.
    #[error("secure operating-system entropy unavailable")]
    EntropyUnavailable,
}

fn random_below(limit: u32) -> Result<u32, PairingCodeError> {
    debug_assert!(limit > 0);
    let acceptance = u32::MAX - (u32::MAX % limit);
    loop {
        let mut bytes = [0_u8; 4];
        getrandom::fill(&mut bytes).map_err(|_| PairingCodeError::EntropyUnavailable)?;
        let candidate = u32::from_le_bytes(bytes);
        if candidate < acceptance {
            return Ok(candidate % limit);
        }
    }
}

fn random_nameplate() -> Result<u16, PairingCodeError> {
    const ACCEPTANCE: u16 = 60_000;
    loop {
        let mut bytes = [0_u8; 2];
        getrandom::fill(&mut bytes).map_err(|_| PairingCodeError::EntropyUnavailable)?;
        let candidate = u16::from_le_bytes(bytes);
        if candidate < ACCEPTANCE {
            return Ok(candidate % NAMEPLATE_SLOTS);
        }
    }
}

fn encode_word(mut word: u32, output: &mut [u8]) {
    debug_assert_eq!(output.len(), WORD_BYTES);
    for syllable in (0..3).rev() {
        let value = word % SYLLABLE_SLOTS;
        word /= SYLLABLE_SLOTS;
        let consonant = usize::try_from(value / VOWEL_SLOTS).expect("consonant index fits");
        let vowel = usize::try_from(value % VOWEL_SLOTS).expect("vowel index fits");
        output[syllable * 2] = CONSONANTS[consonant];
        output[syllable * 2 + 1] = VOWELS[vowel];
    }
}

fn decode_word(word: &[u8]) -> Result<u32, PairingCodeError> {
    if word.len() != WORD_BYTES {
        return Err(PairingCodeError::Malformed);
    }
    let mut result = 0_u32;
    for syllable in word.chunks_exact(2) {
        let consonant = CONSONANTS
            .iter()
            .position(|candidate| *candidate == syllable[0])
            .ok_or(PairingCodeError::Malformed)?;
        let vowel = VOWELS
            .iter()
            .position(|candidate| *candidate == syllable[1])
            .ok_or(PairingCodeError::Malformed)?;
        result = result * SYLLABLE_SLOTS
            + u32::try_from(consonant * VOWELS.len() + vowel)
                .map_err(|_| PairingCodeError::Malformed)?;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pronounceable_word_round_trips() {
        let mut encoded = [0_u8; WORD_BYTES];
        for word in 0..WORD_SLOTS {
            encode_word(word, &mut encoded);
            assert_eq!(decode_word(&encoded), Ok(word));
        }
    }

    #[test]
    fn display_parse_and_debug_are_canonical() {
        let code = PairingCode {
            nameplate: 4_827,
            word: decode_word(b"lumeko").unwrap(),
        };
        assert_eq!(code.to_string(), "4827-lumeko");
        assert_eq!("4827-lumeko".parse::<PairingCode>().unwrap(), code);
        let debug = format!("{code:?}");
        assert!(debug.contains("4827"));
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("lumeko"));
    }

    #[test]
    fn malformed_codes_are_rejected() {
        for malformed in [
            "4827-lumek",
            "4827-lumekoo",
            "4827_lumeko",
            "x827-lumeko",
            "4827-LUMEKO",
            "4827-zumeko",
        ] {
            assert_eq!(
                malformed.parse::<PairingCode>(),
                Err(PairingCodeError::Malformed)
            );
        }
    }

    #[test]
    fn generated_codes_have_stable_public_lookups() {
        for _ in 0..128 {
            let code = PairingCode::generate().unwrap();
            let encoded = code.to_string();
            assert_eq!(encoded.len(), CODE_BYTES);
            assert_eq!(encoded.parse::<PairingCode>().unwrap(), code);
            assert_eq!(code.lookup_id(), code.lookup_id());
        }
    }
}
