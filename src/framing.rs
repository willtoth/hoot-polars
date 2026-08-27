use serde::Serialize;
use std::collections::HashMap;

use crate::error::{HootError, Result};
use crate::huffman::{DecodedByte, HuffmanDecoder};

const RECORD_PREFIX_LEN: usize = 10;
const ARBITRATION_ID_MASK: u32 = 0x1fff_ffff;
const MAX_PAYLOAD_STATES: usize = 65_536;

/// Behavior when the entropy marker or final record is truncated.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TailPolicy {
    /// Return a structured error for any incomplete tail.
    #[default]
    Strict,
    /// Return all complete records and expose the discarded tail in
    /// [`FrameIter::tail_recovery`].
    Lenient,
}

/// Location of a final partial record discarded in lenient mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TailRecovery {
    pub decoded_offset: u64,
    pub compressed_byte_offset: u64,
    /// Bit within `compressed_byte_offset` where the discarded tail begins.
    pub compressed_bit: u8,
    /// Bit offset from the start of the compressed body (after the 80-byte
    /// file header) where a canonical repair must append the end marker.
    pub discard_from_body_bit: u64,
    pub decoded_bytes_available: usize,
    pub decoded_bytes_needed: usize,
    /// True when the physical stream ended without the entropy terminator.
    pub missing_end_marker: bool,
    /// Bits already accumulated for the incomplete final prefix code.
    pub partial_code_bits: u8,
}

/// One record after entropy decoding but before signal semantics are applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RawFrame {
    pub decoded_offset: u64,
    pub compressed_byte_offset: u64,
    pub compressed_bit: u8,
    pub header: u32,
    pub arbitration_id: u32,
    pub record_class: u8,
    /// Timestamp as stored in the frame, before the verified one-microsecond
    /// export adjustment.
    pub encoded_timestamp_us: u64,
    /// Normalized timestamp (`encoded_timestamp_us + 1`).
    pub timestamp_us: i64,
    pub dlc: u8,
    pub dlc_flags: u8,
    /// Entropy-decoded byte-wise modular delta stored in the file.
    pub payload_delta: Vec<u8>,
    /// Reconstructed frame payload after adding `payload_delta` to the
    /// previous payload for the same 32-bit header, independently per byte.
    pub payload: Vec<u8>,
}

impl RawFrame {
    pub fn is_custom(&self) -> bool {
        self.record_class == 7
    }
}

/// Streaming, allocation-bounded iterator over framed records.
pub struct FrameIter<'a> {
    decoder: HuffmanDecoder<'a>,
    decoded_offset: u64,
    policy: TailPolicy,
    finished: bool,
    tail_recovery: Option<TailRecovery>,
    payload_state: HashMap<u32, Vec<u8>>,
    body_file_offset: u64,
}

impl<'a> FrameIter<'a> {
    pub fn new(body: &'a [u8], body_file_offset: u64, policy: TailPolicy) -> Self {
        Self {
            decoder: HuffmanDecoder::new(body, body_file_offset, policy == TailPolicy::Strict),
            decoded_offset: 0,
            policy,
            finished: false,
            tail_recovery: None,
            payload_state: HashMap::new(),
            body_file_offset,
        }
    }

    pub fn tail_recovery(&self) -> Option<&TailRecovery> {
        self.tail_recovery.as_ref()
    }

    pub fn saw_end_marker(&self) -> bool {
        self.decoder.end_marker_bit().is_some()
    }

    fn read_byte(&mut self) -> Option<Result<DecodedByte>> {
        self.decoder.next()
    }

    fn truncated(
        &mut self,
        start: &DecodedByte,
        available: usize,
        needed: usize,
    ) -> Option<Result<RawFrame>> {
        self.finished = true;
        let recovery = TailRecovery {
            decoded_offset: self.decoded_offset,
            compressed_byte_offset: self.body_file_offset + start.compressed_bit_offset / 8,
            compressed_bit: (start.compressed_bit_offset % 8) as u8,
            discard_from_body_bit: start.compressed_bit_offset,
            decoded_bytes_available: available,
            decoded_bytes_needed: needed,
            missing_end_marker: self.decoder.is_truncated(),
            partial_code_bits: self.decoder.partial_code_bits(),
        };
        if self.policy == TailPolicy::Lenient {
            self.tail_recovery = Some(recovery);
            None
        } else {
            Some(Err(HootError::TruncatedRecord {
                decoded_offset: recovery.decoded_offset,
                compressed_offset: recovery.compressed_byte_offset,
                needed,
                available,
            }))
        }
    }
}

impl Iterator for FrameIter<'_> {
    type Item = Result<RawFrame>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        let first = match self.read_byte() {
            None => {
                self.finished = true;
                if self.policy == TailPolicy::Lenient && self.decoder.is_truncated() {
                    self.tail_recovery = Some(TailRecovery {
                        decoded_offset: self.decoded_offset,
                        compressed_byte_offset: self.body_file_offset
                            + self.decoder.complete_bit_position() / 8,
                        compressed_bit: (self.decoder.complete_bit_position() % 8) as u8,
                        discard_from_body_bit: self.decoder.complete_bit_position(),
                        decoded_bytes_available: 0,
                        decoded_bytes_needed: 0,
                        missing_end_marker: true,
                        partial_code_bits: self.decoder.partial_code_bits(),
                    });
                }
                return None;
            }
            Some(result) => match result {
                Ok(byte) => byte,
                Err(error) => {
                    self.finished = true;
                    return Some(Err(error));
                }
            },
        };
        let record_offset = self.decoded_offset;
        let mut prefix = [0_u8; RECORD_PREFIX_LEN];
        prefix[0] = first.value;
        for (index, slot) in prefix.iter_mut().enumerate().skip(1) {
            match self.read_byte() {
                Some(Ok(byte)) => *slot = byte.value,
                Some(Err(error)) => {
                    self.finished = true;
                    return Some(Err(error));
                }
                None => return self.truncated(&first, index, RECORD_PREFIX_LEN),
            }
        }

        let dlc_byte = prefix[9];
        let dlc = dlc_byte >> 4;
        let payload_len = dlc_payload_len(dlc);
        let mut payload_delta = Vec::with_capacity(payload_len);
        for index in 0..payload_len {
            match self.read_byte() {
                Some(Ok(byte)) => payload_delta.push(byte.value),
                Some(Err(error)) => {
                    self.finished = true;
                    return Some(Err(error));
                }
                None => {
                    return self.truncated(
                        &first,
                        RECORD_PREFIX_LEN + index,
                        RECORD_PREFIX_LEN + payload_len,
                    );
                }
            }
        }

        self.decoded_offset += (RECORD_PREFIX_LEN + payload_len) as u64;
        let header = u32::from_le_bytes(prefix[..4].try_into().expect("fixed prefix"));
        if !self.payload_state.contains_key(&header)
            && self.payload_state.len() == MAX_PAYLOAD_STATES
        {
            self.finished = true;
            return Some(Err(HootError::PayloadStateLimit {
                decoded_offset: record_offset,
                limit: MAX_PAYLOAD_STATES,
            }));
        }
        let previous = self
            .payload_state
            .entry(header)
            .or_insert_with(|| vec![0; payload_len]);
        if previous.len() < payload_len {
            previous.resize(payload_len, 0);
        }
        for (current, delta) in previous.iter_mut().zip(&payload_delta) {
            *current = current.wrapping_add(*delta);
        }
        let payload = previous[..payload_len].to_vec();
        let encoded_timestamp_us = prefix[4..9]
            .iter()
            .enumerate()
            .fold(0_u64, |value, (shift, byte)| {
                value | (u64::from(*byte) << (shift * 8))
            });
        let timestamp_us = match encoded_timestamp_us
            .checked_add(1)
            .and_then(|value| i64::try_from(value).ok())
        {
            Some(value) => value,
            None => {
                self.finished = true;
                return Some(Err(HootError::InvalidCustomPayload {
                    decoded_offset: record_offset,
                    raw_id: 0,
                    field: "timestamp",
                    reason: "40-bit timestamp overflowed Int64 after adjustment".to_owned(),
                }));
            }
        };

        Some(Ok(RawFrame {
            decoded_offset: record_offset,
            compressed_byte_offset: self.body_file_offset + first.compressed_bit_offset / 8,
            compressed_bit: (first.compressed_bit_offset % 8) as u8,
            header,
            arbitration_id: header & ARBITRATION_ID_MASK,
            record_class: (header >> 29) as u8,
            encoded_timestamp_us,
            timestamp_us,
            dlc,
            dlc_flags: dlc_byte & 0x0f,
            payload_delta,
            payload,
        }))
    }
}

fn dlc_payload_len(dlc: u8) -> usize {
    const LENGTHS: [usize; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64];
    LENGTHS[usize::from(dlc)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::huffman::decode_body;

    #[test]
    fn dlc_table_matches_can_fd() {
        assert_eq!(dlc_payload_len(0), 0);
        assert_eq!(dlc_payload_len(8), 8);
        assert_eq!(dlc_payload_len(9), 12);
        assert_eq!(dlc_payload_len(15), 64);
    }

    #[test]
    fn decoded_controlled_records_have_exact_boundaries() {
        let compressed = hex::decode(
            "a4bbf45c94032ff635244838ff4824d7902021e323c154032011433e91620ff85d11a7019088c1952af6801f89060c",
        )
        .unwrap();
        let decoded = decode_body(&compressed, 80, true, 4096).unwrap();
        // The entropy test independently verifies the compressed layer. Feed
        // the same bytes through a tiny test encoder by reusing the original
        // compressed body here and verify record boundaries/timestamps.
        let records = FrameIter::new(&compressed, 80, TailPolicy::Strict)
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(records.len(), 5);
        assert_eq!(records[0].payload.len(), 0);
        assert_eq!(records[1].payload, b"x");
        assert_eq!(records[2].payload, b"V");
        assert_eq!(records[3].timestamp_us, 937_511);
        assert_eq!(records[4].timestamp_us, 968_018);
        assert_eq!(
            f64::from_le_bytes(records[3].payload.clone().try_into().unwrap()),
            1.0
        );
        assert_eq!(
            f64::from_le_bytes(records[4].payload.clone().try_into().unwrap()),
            2.0
        );
        assert_eq!(decoded.bytes.len(), 68);
    }

    #[test]
    fn every_controlled_truncation_is_structured() {
        let compressed = hex::decode(
            "a4bbf45c94032ff635244838ff4824d7902021e323c154032011433e91620ff85d11a7019088c1952af6801f89060c",
        )
        .unwrap();
        for cut in 0..compressed.len() {
            let strict = FrameIter::new(&compressed[..cut], 80, TailPolicy::Strict)
                .collect::<Result<Vec<_>>>();
            assert!(strict.is_err(), "cut {cut} unexpectedly passed strict mode");

            let mut lenient = FrameIter::new(&compressed[..cut], 80, TailPolicy::Lenient);
            for frame in lenient.by_ref() {
                frame.unwrap();
            }
            assert!(
                lenient.tail_recovery().is_some(),
                "cut {cut} lacked a recovery diagnostic"
            );
        }
    }
}
