//! Bounded systematic repair coding for one direct-record fragment set.

use std::collections::BTreeSet;

use thiserror::Error;

/// Maximum source symbols supported by the information plane.
pub const MAX_CODING_SOURCES: usize = 64;
/// Maximum bytes in one source or repair symbol.
pub const MAX_CODING_SYMBOL_BYTES: usize = 4_096;
/// Distinct repair identities available for one source generation.
pub const MAX_REPAIR_SYMBOLS: u8 = 128;

/// One authenticated repair equation over a systematic source generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairSymbol {
    /// Zero-based repair identity. Any distinct subset is linearly independent.
    pub index: u8,
    /// Source symbols participating in this repair generation.
    pub source_bitmap: u64,
    /// Cauchy-coded bytes, padded to the generation symbol width.
    pub data: Vec<u8>,
}

/// Invalid or contradictory bounded repair state.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CodingError {
    /// A generation must contain at least one source symbol.
    #[error("repair generation has no source symbols")]
    EmptyGeneration,
    /// A generation exceeded the fixed source-symbol bound.
    #[error("repair generation exceeds the source-symbol bound")]
    TooManySources,
    /// Symbol width is zero or exceeds the fixed memory bound.
    #[error("invalid repair symbol width")]
    InvalidSymbolWidth,
    /// A source symbol is empty or wider than the generation width.
    #[error("invalid source symbol length")]
    InvalidSourceLength,
    /// The declared final source width is impossible.
    #[error("invalid final source symbol length")]
    InvalidFinalSourceLength,
    /// Repair identity exceeds the fixed Cauchy row space.
    #[error("repair identity exceeds the fixed bound")]
    InvalidRepairIndex,
    /// Repair bytes do not match the generation width.
    #[error("repair symbol has the wrong length")]
    InvalidRepairLength,
    /// One repair identity appeared more than once.
    #[error("duplicate repair identity")]
    DuplicateRepair,
    /// The repair generation is empty or names sources outside the record.
    #[error("invalid repair source bitmap")]
    InvalidSourceBitmap,
    /// Repair equations from different source generations were mixed.
    #[error("repair equations belong to different source generations")]
    MixedGenerations,
    /// Authenticated equations are algebraically singular.
    #[error("repair equations are singular")]
    Singular,
    /// Authenticated repair bytes contradict the source generation.
    #[error("repair equation contradicts reconstructed source bytes")]
    ContradictoryRepair,
}

/// Encode one deterministic Cauchy repair symbol.
///
/// Source symbols may be shorter than `symbol_bytes`; their absent suffix is
/// canonically zero. For direct records, only the final source is shorter.
/// Distinct repair identities form an MDS matrix: any `m` received repairs can
/// recover any `m` missing source symbols.
///
/// # Errors
///
/// Rejects empty or oversized generations, invalid source widths, and repair
/// identities outside the bounded row space.
pub fn encode_repair(
    sources: &[&[u8]],
    symbol_bytes: usize,
    repair_index: u8,
    source_bitmap: u64,
) -> Result<RepairSymbol, CodingError> {
    validate_generation(sources.len(), symbol_bytes)?;
    if repair_index >= MAX_REPAIR_SYMBOLS {
        return Err(CodingError::InvalidRepairIndex);
    }
    validate_source_bitmap(sources.len(), source_bitmap)?;
    if sources.iter().enumerate().any(|(index, source)| {
        source_bitmap & (1_u64 << index) != 0 && (source.is_empty() || source.len() > symbol_bytes)
    }) {
        return Err(CodingError::InvalidSourceLength);
    }

    let mut data = vec![0_u8; symbol_bytes];
    for (source_index, source) in sources.iter().enumerate() {
        if source_bitmap & (1_u64 << source_index) == 0 {
            continue;
        }
        let coefficient = cauchy_coefficient(source_index, repair_index);
        for (output, input) in data.iter_mut().zip(source.iter().copied()) {
            *output ^= gf_mul(coefficient, input);
        }
    }
    Ok(RepairSymbol {
        index: repair_index,
        source_bitmap,
        data,
    })
}

/// Recover a bounded source generation from authenticated repair equations.
///
/// Returns `Ok(false)` without modifying `sources` when fewer independent
/// repair symbols than missing generation members are available. On
/// `Ok(true)`, every source selected by the shared generation bitmap is present
/// and every supplied repair equation has been verified. Sources outside the
/// generation are untouched and may still be absent.
///
/// # Errors
///
/// Rejects impossible geometry, duplicate repair identities, singular
/// equations, or authenticated repair bytes that contradict the result.
pub fn recover_sources(
    sources: &mut [Option<Vec<u8>>],
    symbol_bytes: usize,
    final_source_bytes: usize,
    repairs: &[RepairSymbol],
) -> Result<bool, CodingError> {
    validate_generation(sources.len(), symbol_bytes)?;
    if final_source_bytes == 0 || final_source_bytes > symbol_bytes {
        return Err(CodingError::InvalidFinalSourceLength);
    }
    for (index, source) in sources.iter().enumerate() {
        let expected = if index + 1 == sources.len() {
            final_source_bytes
        } else {
            symbol_bytes
        };
        if source.as_ref().is_some_and(|bytes| bytes.len() != expected) {
            return Err(CodingError::InvalidSourceLength);
        }
    }
    let mut identities = BTreeSet::new();
    let source_bitmap = repairs.first().map(|repair| repair.source_bitmap);
    for repair in repairs {
        if repair.index >= MAX_REPAIR_SYMBOLS {
            return Err(CodingError::InvalidRepairIndex);
        }
        if repair.data.len() != symbol_bytes {
            return Err(CodingError::InvalidRepairLength);
        }
        if !identities.insert(repair.index) {
            return Err(CodingError::DuplicateRepair);
        }
        validate_source_bitmap(sources.len(), repair.source_bitmap)?;
        if Some(repair.source_bitmap) != source_bitmap {
            return Err(CodingError::MixedGenerations);
        }
    }

    let Some(source_bitmap) = source_bitmap else {
        return Ok(sources.iter().all(Option::is_some));
    };

    let missing = sources
        .iter()
        .enumerate()
        .filter_map(|(index, source)| {
            (source.is_none() && source_bitmap & (1_u64 << index) != 0).then_some(index)
        })
        .collect::<Vec<_>>();
    if repairs.len() < missing.len() {
        return Ok(false);
    }
    if !missing.is_empty() {
        let equation_count = missing.len();
        let mut matrix = vec![vec![0_u8; equation_count]; equation_count];
        let mut right = vec![vec![0_u8; symbol_bytes]; equation_count];
        for (row, repair) in repairs.iter().take(equation_count).enumerate() {
            right[row].copy_from_slice(&repair.data);
            for (source_index, source) in sources.iter().enumerate() {
                if source_bitmap & (1_u64 << source_index) == 0 {
                    continue;
                }
                let coefficient = cauchy_coefficient(source_index, repair.index);
                if let Some(source) = source {
                    add_scaled(&mut right[row], source, coefficient);
                }
            }
            for (column, source_index) in missing.iter().copied().enumerate() {
                matrix[row][column] = cauchy_coefficient(source_index, repair.index);
            }
        }
        reduce_to_identity(&mut matrix, &mut right)?;
        for (row, source_index) in missing.iter().copied().enumerate() {
            let length = if source_index + 1 == sources.len() {
                final_source_bytes
            } else {
                symbol_bytes
            };
            right[row].truncate(length);
            sources[source_index] = Some(std::mem::take(&mut right[row]));
        }
    }

    let borrowed = sources
        .iter()
        .map(|source| source.as_deref().unwrap_or_default())
        .collect::<Vec<_>>();
    for repair in repairs {
        if encode_repair(&borrowed, symbol_bytes, repair.index, repair.source_bitmap)? != *repair {
            return Err(CodingError::ContradictoryRepair);
        }
    }
    Ok(true)
}

fn validate_generation(source_count: usize, symbol_bytes: usize) -> Result<(), CodingError> {
    if source_count == 0 {
        return Err(CodingError::EmptyGeneration);
    }
    if source_count > MAX_CODING_SOURCES {
        return Err(CodingError::TooManySources);
    }
    if symbol_bytes == 0 || symbol_bytes > MAX_CODING_SYMBOL_BYTES {
        return Err(CodingError::InvalidSymbolWidth);
    }
    Ok(())
}

fn validate_source_bitmap(source_count: usize, source_bitmap: u64) -> Result<(), CodingError> {
    let allowed = if source_count == 64 {
        u64::MAX
    } else {
        (1_u64 << source_count) - 1
    };
    if source_bitmap == 0 || source_bitmap & !allowed != 0 {
        return Err(CodingError::InvalidSourceBitmap);
    }
    Ok(())
}

fn reduce_to_identity(matrix: &mut [Vec<u8>], right: &mut [Vec<u8>]) -> Result<(), CodingError> {
    let width = matrix.len();
    for column in 0..width {
        let pivot = (column..width)
            .find(|row| matrix[*row][column] != 0)
            .ok_or(CodingError::Singular)?;
        matrix.swap(column, pivot);
        right.swap(column, pivot);

        let inverse = gf_inv(matrix[column][column]).ok_or(CodingError::Singular)?;
        scale(&mut matrix[column], inverse);
        scale(&mut right[column], inverse);

        for row in 0..width {
            if row == column {
                continue;
            }
            let factor = matrix[row][column];
            if factor == 0 {
                continue;
            }
            let pivot_row = matrix[column].clone();
            let pivot_right = right[column].clone();
            add_scaled(&mut matrix[row], &pivot_row, factor);
            add_scaled(&mut right[row], &pivot_right, factor);
        }
    }
    Ok(())
}

fn scale(bytes: &mut [u8], coefficient: u8) {
    for byte in bytes {
        *byte = gf_mul(*byte, coefficient);
    }
}

fn add_scaled(output: &mut [u8], input: &[u8], coefficient: u8) {
    for (output, input) in output.iter_mut().zip(input.iter().copied()) {
        *output ^= gf_mul(input, coefficient);
    }
}

fn cauchy_coefficient(source_index: usize, repair_index: u8) -> u8 {
    let source = u8::try_from(source_index + 1).expect("source index is bounded at 64");
    let repair = repair_index | 0x80;
    gf_inv(source ^ repair).expect("Cauchy row and column sets are disjoint")
}

fn gf_inv(value: u8) -> Option<u8> {
    (value != 0).then(|| gf_pow(value, 254))
}

fn gf_pow(mut base: u8, mut exponent: u8) -> u8 {
    let mut output = 1_u8;
    while exponent != 0 {
        if exponent & 1 != 0 {
            output = gf_mul(output, base);
        }
        base = gf_mul(base, base);
        exponent >>= 1;
    }
    output
}

fn gf_mul(mut left: u8, mut right: u8) -> u8 {
    let mut output = 0_u8;
    for _ in 0..8 {
        if right & 1 != 0 {
            output ^= left;
        }
        let carry = left & 0x80 != 0;
        left <<= 1;
        if carry {
            left ^= 0x1d;
        }
        right >>= 1;
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generation() -> Vec<Vec<u8>> {
        (0_u8..8)
            .map(|source| {
                let length = if source == 7 { 29 } else { 64 };
                (0..length)
                    .map(|offset| source.wrapping_mul(31) ^ u8::try_from(offset).unwrap())
                    .collect()
            })
            .collect()
    }

    const FULL: u64 = 0xff;

    #[test]
    fn every_nonzero_field_element_has_an_inverse() {
        for value in 1..=u8::MAX {
            assert_eq!(gf_mul(value, gf_inv(value).unwrap()), 1);
        }
    }

    #[test]
    fn arbitrary_repair_subset_recovers_arbitrary_missing_sources() {
        let expected = generation();
        let borrowed = expected.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let repairs = [3, 11, 47, 92]
            .into_iter()
            .map(|index| encode_repair(&borrowed, 64, index, FULL).unwrap())
            .collect::<Vec<_>>();
        let mut received = expected.iter().cloned().map(Some).collect::<Vec<_>>();
        for missing in [0, 2, 5, 7] {
            received[missing] = None;
        }

        assert!(recover_sources(&mut received, 64, 29, &repairs).unwrap());
        assert_eq!(
            received.into_iter().collect::<Option<Vec<_>>>().unwrap(),
            expected
        );
    }

    #[test]
    fn insufficient_rank_is_non_destructive() {
        let expected = generation();
        let borrowed = expected.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let repair = encode_repair(&borrowed, 64, 7, FULL).unwrap();
        let mut received = expected.iter().cloned().map(Some).collect::<Vec<_>>();
        received[1] = None;
        received[4] = None;
        let before = received.clone();

        assert!(!recover_sources(&mut received, 64, 29, &[repair]).unwrap());
        assert_eq!(received, before);
    }

    #[test]
    fn contradictory_authenticated_repair_fails_closed() {
        let expected = generation();
        let borrowed = expected.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let mut repairs = [1, 2]
            .into_iter()
            .map(|index| encode_repair(&borrowed, 64, index, FULL).unwrap())
            .collect::<Vec<_>>();
        repairs[1].data[17] ^= 0x80;
        let mut received = expected.iter().cloned().map(Some).collect::<Vec<_>>();
        received[3] = None;

        assert_eq!(
            recover_sources(&mut received, 64, 29, &repairs),
            Err(CodingError::ContradictoryRepair)
        );
    }

    #[test]
    fn duplicate_repair_identity_is_rejected() {
        let expected = generation();
        let borrowed = expected.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let repair = encode_repair(&borrowed, 64, 1, FULL).unwrap();
        let mut received = expected.iter().cloned().map(Some).collect::<Vec<_>>();
        received[3] = None;

        assert_eq!(
            recover_sources(&mut received, 64, 29, &[repair.clone(), repair]),
            Err(CodingError::DuplicateRepair)
        );
    }

    #[test]
    fn one_flight_generation_ignores_unsent_sources() {
        let expected = generation();
        let borrowed = expected.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let flight = 0b0011_1100;
        let repairs = [5, 17]
            .into_iter()
            .map(|index| encode_repair(&borrowed, 64, index, flight).unwrap())
            .collect::<Vec<_>>();
        let mut received = expected.iter().cloned().map(Some).collect::<Vec<_>>();
        received[2] = None;
        received[5] = None;
        received[7] = None;

        assert!(recover_sources(&mut received, 64, 29, &repairs).unwrap());
        assert_eq!(received[2], Some(expected[2].clone()));
        assert_eq!(received[5], Some(expected[5].clone()));
        assert_eq!(received[7], None);
    }
}
