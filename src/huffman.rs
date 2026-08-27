//! Static entropy decoder used by compliancy-19 HOOT streams.
//!
//! Bytes are encoded with a fixed 257-symbol prefix code. Bits are consumed
//! least-significant-bit first within each source byte; the codewords below
//! are written in their consumption order.

use std::sync::OnceLock;

use crate::error::{HootError, Result};

const MAX_CODE_BITS: u8 = 11;
const LOOKUP_SIZE: usize = 1 << (MAX_CODE_BITS + 1);
const END_OF_STREAM: u16 = 256;

/// A byte emitted by the entropy layer and the compressed bit where its
/// codeword began.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedByte {
    pub value: u8,
    pub compressed_bit_offset: u64,
}

/// Result of decoding a complete entropy stream.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedBody {
    pub bytes: Vec<u8>,
    pub end_marker_bit: Option<u64>,
    pub trailing_bits: u64,
    pub truncated: bool,
}

/// Checked iterator over decoded HOOT bytes.
pub struct HuffmanDecoder<'a> {
    input: &'a [u8],
    file_offset: u64,
    bit_position: u64,
    code_start: u64,
    code: u16,
    code_len: u8,
    strict: bool,
    done: bool,
    error_emitted: bool,
    end_marker_bit: Option<u64>,
}

impl<'a> HuffmanDecoder<'a> {
    pub fn new(input: &'a [u8], file_offset: u64, strict: bool) -> Self {
        Self {
            input,
            file_offset,
            bit_position: 0,
            code_start: 0,
            code: 0,
            code_len: 0,
            strict,
            done: false,
            error_emitted: false,
            end_marker_bit: None,
        }
    }

    /// Position immediately after the last complete prefix-code symbol.
    /// Any currently accumulated incomplete code begins at this bit.
    pub fn complete_bit_position(&self) -> u64 {
        if self.code_len == 0 {
            self.bit_position
        } else {
            self.code_start
        }
    }

    pub fn partial_code_bits(&self) -> u8 {
        self.code_len
    }

    pub fn end_marker_bit(&self) -> Option<u64> {
        self.end_marker_bit
    }

    #[cfg(test)]
    pub fn trailing_bits(&self) -> u64 {
        (self.input.len() as u64)
            .saturating_mul(8)
            .saturating_sub(self.bit_position)
    }

    pub fn is_truncated(&self) -> bool {
        self.done && self.end_marker_bit.is_none()
    }

    fn absolute_byte_offset(&self) -> u64 {
        self.file_offset + self.bit_position / 8
    }
}

impl Iterator for HuffmanDecoder<'_> {
    type Item = Result<DecodedByte>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let total_bits = (self.input.len() as u64).saturating_mul(8);
        while self.bit_position < total_bits {
            if self.code_len == 0 {
                self.code_start = self.bit_position;
            }

            let byte = self.input[(self.bit_position / 8) as usize];
            let bit = (byte >> (self.bit_position % 8)) & 1;
            self.bit_position += 1;
            self.code = (self.code << 1) | u16::from(bit);
            self.code_len += 1;

            let key = (1_usize << self.code_len) | usize::from(self.code);
            let symbol = decode_lookup()[key];
            if symbol >= 0 {
                let symbol = symbol as u16;
                let source_bit = self.code_start;
                self.code = 0;
                self.code_len = 0;
                if symbol == END_OF_STREAM {
                    self.end_marker_bit = Some(source_bit);
                    self.done = true;
                    return None;
                }
                return Some(Ok(DecodedByte {
                    value: symbol as u8,
                    compressed_bit_offset: source_bit,
                }));
            }

            if self.code_len == MAX_CODE_BITS {
                self.done = true;
                return Some(Err(HootError::InvalidPrefixCode {
                    offset: self.absolute_byte_offset(),
                    bit: (self.bit_position - 1) % 8,
                    code: self.code,
                }));
            }
        }

        self.done = true;
        if self.strict && !self.error_emitted {
            self.error_emitted = true;
            return Some(Err(HootError::MissingEndMarker {
                offset: self.file_offset + self.input.len() as u64,
                partial_code_bits: self.code_len,
            }));
        }
        None
    }
}

/// Decode a complete body with an explicit output allocation ceiling.
#[cfg(test)]
pub fn decode_body(
    input: &[u8],
    file_offset: u64,
    strict: bool,
    max_decoded_bytes: usize,
) -> Result<DecodedBody> {
    let mut decoder = HuffmanDecoder::new(input, file_offset, strict);
    let mut bytes = Vec::with_capacity(input.len().min(max_decoded_bytes));
    for decoded in decoder.by_ref() {
        let decoded = decoded?;
        if bytes.len() == max_decoded_bytes {
            return Err(HootError::DecodedSizeLimit {
                offset: file_offset + decoded.compressed_bit_offset / 8,
                limit: max_decoded_bytes,
            });
        }
        bytes.push(decoded.value);
    }

    Ok(DecodedBody {
        bytes,
        end_marker_bit: decoder.end_marker_bit(),
        trailing_bits: decoder.trailing_bits(),
        truncated: decoder.is_truncated(),
    })
}

fn decode_lookup() -> &'static [i16; LOOKUP_SIZE] {
    static LOOKUP: OnceLock<[i16; LOOKUP_SIZE]> = OnceLock::new();
    LOOKUP.get_or_init(|| {
        let mut table = [-1_i16; LOOKUP_SIZE];
        for (symbol, &(code, length)) in CODEBOOK.iter().enumerate() {
            let key = (1_usize << length) | usize::from(code);
            debug_assert_eq!(table[key], -1);
            table[key] = symbol as i16;
        }
        table
    })
}

// Verified against Phoenix 6 26.3.0 controlled raw-byte vectors. The final
// symbol is the stream terminator.
const CODEBOOK: [(u16, u8); 257] = [
    (0b1, 1),            // 0x00
    (0b010110, 6),       // 0x01
    (0b01011101, 8),     // 0x02
    (0b011000111, 9),    // 0x03
    (0b01111, 5),        // 0x04
    (0b001110010, 9),    // 0x05
    (0b001001010, 9),    // 0x06
    (0b000100011, 9),    // 0x07
    (0b010111101, 9),    // 0x08
    (0b0110001011, 10),  // 0x09
    (0b0101111101, 10),  // 0x0a
    (0b0101001010, 10),  // 0x0b
    (0b0111010001, 10),  // 0x0c
    (0b0100101111, 10),  // 0x0d
    (0b0100011011, 10),  // 0x0e
    (0b0100101010, 10),  // 0x0f
    (0b000100100, 9),    // 0x10
    (0b0011101011, 10),  // 0x11
    (0b0101001100, 10),  // 0x12
    (0b0110000, 7),      // 0x13
    (0b0111011, 7),      // 0x14
    (0b0100111101, 10),  // 0x15
    (0b0011011110, 10),  // 0x16
    (0b0011011100, 10),  // 0x17
    (0b0111010111, 10),  // 0x18
    (0b0011011001, 10),  // 0x19
    (0b0011011000, 10),  // 0x1a
    (0b0011001111, 10),  // 0x1b
    (0b0100110110, 10),  // 0x1c
    (0b0011001011, 10),  // 0x1d
    (0b0011001010, 10),  // 0x1e
    (0b0011001101, 10),  // 0x1f
    (0b010010010, 9),    // 0x20
    (0b0011001100, 10),  // 0x21
    (0b0010011100, 10),  // 0x22
    (0b0010011101, 10),  // 0x23
    (0b0100101000, 10),  // 0x24
    (0b0010011010, 10),  // 0x25
    (0b0010011111, 10),  // 0x26
    (0b0111010000, 10),  // 0x27
    (0b0110001010, 10),  // 0x28
    (0b0010010110, 10),  // 0x29
    (0b0010010000, 10),  // 0x2a
    (0b0010001111, 10),  // 0x2b
    (0b0100011010, 10),  // 0x2c
    (0b0010001010, 10),  // 0x2d
    (0b0001111111, 10),  // 0x2e
    (0b0010000110, 10),  // 0x2f
    (0b0101000110, 10),  // 0x30
    (0b0001110111, 10),  // 0x31
    (0b0001101100, 10),  // 0x32
    (0b0001110010, 10),  // 0x33
    (0b0100000100, 10),  // 0x34
    (0b0001110011, 10),  // 0x35
    (0b0001110000, 10),  // 0x36
    (0b0001100111, 10),  // 0x37
    (0b0101110000, 10),  // 0x38
    (0b0001011101, 10),  // 0x39
    (0b0001101011, 10),  // 0x3a
    (0b0001100000, 10),  // 0x3b
    (0b0011111101, 10),  // 0x3c
    (0b0001010100, 10),  // 0x3d
    (0b0001010101, 10),  // 0x3e
    (0b0010001110, 10),  // 0x3f
    (0b01001110, 8),     // 0x40
    (0b0010011001, 10),  // 0x41
    (0b011100, 6),       // 0x42
    (0b0001111110, 10),  // 0x43
    (0b0100001001, 10),  // 0x44
    (0b0001111001, 10),  // 0x45
    (0b0010000011, 10),  // 0x46
    (0b011001, 6),       // 0x47
    (0b0100111100, 10),  // 0x48
    (0b0010000010, 10),  // 0x49
    (0b0001111011, 10),  // 0x4a
    (0b0001111000, 10),  // 0x4b
    (0b0100000001, 10),  // 0x4c
    (0b0001111100, 10),  // 0x4d
    (0b0010001001, 10),  // 0x4e
    (0b0001101111, 10),  // 0x4f
    (0b0100110111, 10),  // 0x50
    (0b0001110101, 10),  // 0x51
    (0b0001110100, 10),  // 0x52
    (0b0001110110, 10),  // 0x53
    (0b0100010101, 10),  // 0x54
    (0b0001101010, 10),  // 0x55
    (0b0001100101, 10),  // 0x56
    (0b0001100010, 10),  // 0x57
    (0b0100110100, 10),  // 0x58
    (0b0001100100, 10),  // 0x59
    (0b0001100011, 10),  // 0x5a
    (0b0001100001, 10),  // 0x5b
    (0b0100000000, 10),  // 0x5c
    (0b0001011100, 10),  // 0x5d
    (0b0001010111, 10),  // 0x5e
    (0b0010000101, 10),  // 0x5f
    (0b001110100, 9),    // 0x60
    (0b0001001100, 10),  // 0x61
    (0b01101, 5),        // 0x62
    (0b0101001011, 10),  // 0x63
    (0b0011110100, 10),  // 0x64
    (0b0000100100, 10),  // 0x65
    (0b0000100110, 10),  // 0x66
    (0b0000110010, 10),  // 0x67
    (0b0100100001, 10),  // 0x68
    (0b0000100010, 10),  // 0x69
    (0b0000101001, 10),  // 0x6a
    (0b0101000111, 10),  // 0x6b
    (0b0011110101, 10),  // 0x6c
    (0b0000101111, 10),  // 0x6d
    (0b0000110100, 10),  // 0x6e
    (0b0000100001, 10),  // 0x6f
    (0b0100100010, 10),  // 0x70
    (0b0001111010, 10),  // 0x71
    (0b0000001101, 10),  // 0x72
    (0b0000101100, 10),  // 0x73
    (0b0011111011, 10),  // 0x74
    (0b0000110101, 10),  // 0x75
    (0b0000101101, 10),  // 0x76
    (0b0000100000, 10),  // 0x77
    (0b0100100111, 10),  // 0x78
    (0b00000011001, 11), // 0x79
    (0b0000001110, 10),  // 0x7a
    (0b0000100101, 10),  // 0x7b
    (0b0100001000, 10),  // 0x7c
    (0b0000100011, 10),  // 0x7d
    (0b0000101010, 10),  // 0x7e
    (0b0101001101, 10),  // 0x7f
    (0b0000000, 7),      // 0x80
    (0b010010110, 9),    // 0x81
    (0b010001110, 9),    // 0x82
    (0b010001011, 9),    // 0x83
    (0b010100010, 9),    // 0x84
    (0b010001000, 9),    // 0x85
    (0b010000111, 9),    // 0x86
    (0b010001001, 9),    // 0x87
    (0b010111001, 9),    // 0x88
    (0b010000110, 9),    // 0x89
    (0b010000011, 9),    // 0x8a
    (0b010000101, 9),    // 0x8b
    (0b010100000, 9),    // 0x8c
    (0b010000001, 9),    // 0x8d
    (0b001111111, 9),    // 0x8e
    (0b010001111, 9),    // 0x8f
    (0b0100100110, 10),  // 0x90
    (0b0000111001, 10),  // 0x91
    (0b0000101110, 10),  // 0x92
    (0b0000101000, 10),  // 0x93
    (0b0011110110, 10),  // 0x94
    (0b0000001111, 10),  // 0x95
    (0b0000110001, 10),  // 0x96
    (0b0000101011, 10),  // 0x97
    (0b0100100011, 10),  // 0x98
    (0b0000100111, 10),  // 0x99
    (0b0000110011, 10),  // 0x9a
    (0b0000110000, 10),  // 0x9b
    (0b0011111000, 10),  // 0x9c
    (0b0000110110, 10),  // 0x9d
    (0b0000110111, 10),  // 0x9e
    (0b0001101101, 10),  // 0x9f
    (0b000101111, 9),    // 0xa0
    (0b0001010110, 10),  // 0xa1
    (0b0000111000, 10),  // 0xa2
    (0b0000111010, 10),  // 0xa3
    (0b0011111001, 10),  // 0xa4
    (0b0000111111, 10),  // 0xa5
    (0b0000111100, 10),  // 0xa6
    (0b0000111011, 10),  // 0xa7
    (0b0100101110, 10),  // 0xa8
    (0b0000111110, 10),  // 0xa9
    (0b0001001110, 10),  // 0xaa
    (0b0000111101, 10),  // 0xab
    (0b0011110111, 10),  // 0xac
    (0b0001000100, 10),  // 0xad
    (0b0001000000, 10),  // 0xae
    (0b0001010000, 10),  // 0xaf
    (0b0100101001, 10),  // 0xb0
    (0b0001001010, 10),  // 0xb1
    (0b0001000101, 10),  // 0xb2
    (0b0001000001, 10),  // 0xb3
    (0b0011111010, 10),  // 0xb4
    (0b0001000011, 10),  // 0xb5
    (0b0001000010, 10),  // 0xb6
    (0b0001001011, 10),  // 0xb7
    (0b0100110101, 10),  // 0xb8
    (0b0001001101, 10),  // 0xb9
    (0b0001001111, 10),  // 0xba
    (0b0001010011, 10),  // 0xbb
    (0b0011111100, 10),  // 0xbc
    (0b0001010001, 10),  // 0xbd
    (0b0001010010, 10),  // 0xbe
    (0b0010010111, 10),  // 0xbf
    (0b01001100, 8),     // 0xc0
    (0b0011000, 7),      // 0xc1
    (0b0000011, 7),      // 0xc2
    (0b0010100, 7),      // 0xc3
    (0b0011010, 7),      // 0xc4
    (0b0010101, 7),      // 0xc5
    (0b0010110, 7),      // 0xc6
    (0b0001101110, 10),  // 0xc7
    (0b0101110001, 10),  // 0xc8
    (0b0001101000, 10),  // 0xc9
    (0b0001100110, 10),  // 0xca
    (0b0001101001, 10),  // 0xcb
    (0b0100000101, 10),  // 0xcc
    (0b0010111, 7),      // 0xcd
    (0b0001110001, 10),  // 0xce
    (0b0001111101, 10),  // 0xcf
    (0b0101000011, 10),  // 0xd0
    (0b0010000000, 10),  // 0xd1
    (0b0010000001, 10),  // 0xd2
    (0b0010000100, 10),  // 0xd3
    (0b0100010100, 10),  // 0xd4
    (0b0010000111, 10),  // 0xd5
    (0b0010001000, 10),  // 0xd6
    (0b0010001011, 10),  // 0xd7
    (0b0101111100, 10),  // 0xd8
    (0b0010001101, 10),  // 0xd9
    (0b0010001100, 10),  // 0xda
    (0b0010010001, 10),  // 0xdb
    (0b0100100000, 10),  // 0xdc
    (0b0010010010, 10),  // 0xdd
    (0b0010010011, 10),  // 0xde
    (0b0011011111, 10),  // 0xdf
    (0b010001100, 9),    // 0xe0
    (0b0011100111, 10),  // 0xe1
    (0b0010011000, 10),  // 0xe2
    (0b0010011011, 10),  // 0xe3
    (0b0100101011, 10),  // 0xe4
    (0b0010011110, 10),  // 0xe5
    (0b0011001000, 10),  // 0xe6
    (0b0011001001, 10),  // 0xe7
    (0b0111010110, 10),  // 0xe8
    (0b0011001110, 10),  // 0xe9
    (0b0011011010, 10),  // 0xea
    (0b0011011011, 10),  // 0xeb
    (0b0101000010, 10),  // 0xec
    (0b0011011101, 10),  // 0xed
    (0b0011100110, 10),  // 0xee
    (0b0011101010, 10),  // 0xef
    (0b011101010, 9),    // 0xf0
    (0b010100111, 9),    // 0xf1
    (0b010011111, 9),    // 0xf2
    (0b010100100, 9),    // 0xf3
    (0b011000110, 9),    // 0xf4
    (0b010111100, 9),    // 0xf5
    (0b010111111, 9),    // 0xf6
    (0b011000100, 9),    // 0xf7
    (0b00111000, 8),     // 0xf8
    (0b011101001, 9),    // 0xf9
    (0b00000010, 8),     // 0xfa
    (0b00010110, 8),     // 0xfb
    (0b00111011, 8),     // 0xfc
    (0b00111100, 8),     // 0xfd
    (0b0000010, 7),      // 0xfe
    (0b010101, 6),       // 0xff
    (0b00000011000, 11), // end-of-stream
];

/// Copy a prefix of an entropy body and append the canonical end-of-stream
/// symbol. `prefix_bits` must end at a decoded-symbol boundary.
pub(crate) fn terminate_prefix(input: &[u8], prefix_bits: u64) -> Result<Vec<u8>> {
    let input_bits = (input.len() as u64).saturating_mul(8);
    if prefix_bits > input_bits {
        return Err(HootError::InvalidArgument(format!(
            "entropy prefix has {prefix_bits} bits but the body has only {input_bits}"
        )));
    }

    let whole_bytes = usize::try_from(prefix_bits / 8)
        .map_err(|_| HootError::InvalidArgument("entropy prefix is too large".to_owned()))?;
    let partial_bits = (prefix_bits % 8) as u8;
    let mut output = input[..whole_bytes].to_vec();
    if partial_bits != 0 {
        let mask = (1_u8 << partial_bits) - 1;
        output.push(input[whole_bytes] & mask);
    }

    let (code, length) = CODEBOOK[usize::from(END_OF_STREAM)];
    let mut position = prefix_bits;
    for shift in (0..length).rev() {
        let byte_index = usize::try_from(position / 8)
            .map_err(|_| HootError::InvalidArgument("repaired stream is too large".to_owned()))?;
        if byte_index == output.len() {
            output.push(0);
        }
        let bit = ((code >> shift) & 1) as u8;
        output[byte_index] |= bit << (position % 8);
        position += 1;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(values: &[u8], include_end: bool) -> Vec<u8> {
        let mut output = Vec::new();
        let mut current = 0_u8;
        let mut used = 0_u8;
        let symbols = values
            .iter()
            .map(|value| usize::from(*value))
            .chain(include_end.then_some(usize::from(END_OF_STREAM)));
        for symbol in symbols {
            let (code, length) = CODEBOOK[symbol];
            for shift in (0..length).rev() {
                let bit = ((code >> shift) & 1) as u8;
                current |= bit << used;
                used += 1;
                if used == 8 {
                    output.push(current);
                    current = 0;
                    used = 0;
                }
            }
        }
        if used != 0 {
            output.push(current);
        }
        output
    }

    #[test]
    fn all_byte_symbols_round_trip() {
        let expected = (0_u8..=u8::MAX).collect::<Vec<_>>();
        let encoded = encode(&expected, true);
        let decoded = decode_body(&encoded, 80, true, 4096).unwrap();
        assert_eq!(decoded.bytes, expected);
        assert!(!decoded.truncated);
        assert!(decoded.end_marker_bit.is_some());
    }

    #[test]
    fn controlled_two_double_body_decodes_exactly() {
        let compressed = hex::decode(
            "a4bbf45c94032ff635244838ff4824d7902021e323c154032011433e91620ff85d11a7019088c1952af6801f89060c",
        )
        .unwrap();
        let decoded = decode_body(&compressed, 80, true, 4096).unwrap();
        assert_eq!(
            hex::encode(decoded.bytes),
            "bff90460f1950e000000011010e100000000001078011010e200000000001056018010e0264e0e000080000000000000f03f018010e051c50e0000800000000000001001"
        );
        assert_eq!(decoded.trailing_bits, 1);
    }

    #[test]
    fn strict_requires_end_marker() {
        let encoded = encode(b"abc", false);
        assert!(matches!(
            decode_body(&encoded, 80, true, 1024),
            Err(HootError::MissingEndMarker { .. })
        ));
        let recovered = decode_body(&encoded, 80, false, 1024).unwrap();
        assert!(recovered.truncated);
    }

    #[test]
    fn output_limit_is_checked() {
        let encoded = encode(&[0; 32], true);
        assert!(matches!(
            decode_body(&encoded, 80, true, 8),
            Err(HootError::DecodedSizeLimit { limit: 8, .. })
        ));
    }
}
