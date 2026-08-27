use serde::Serialize;

use crate::error::{HootError, Result};

/// Fixed byte length of the verified compliancy-19 header.
pub const HEADER_LEN: usize = 80;
/// Byte containing the HOOT compliancy value.
pub const COMPLIANCY_OFFSET: usize = 70;
/// Compliancy version implemented by this decoder.
pub const SUPPORTED_COMPLIANCY: u8 = 19;

/// Plain-text and version information at the start of a HOOT file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HootHeader {
    /// CAN bus or simulation source, from the 64-byte NUL-padded field.
    pub source: String,
    /// Six bytes between the source and compliancy fields. Their semantics are
    /// not yet published, so they are preserved verbatim.
    pub reserved: [u8; 6],
    /// Format compliancy read at byte 70.
    pub compliancy: u8,
    /// Format flag/version byte at byte 71 (observed as 1 for compliancy 19).
    pub format_flags: u8,
    /// Little-endian Unix timestamp in seconds at bytes 72..80.
    pub start_time_unix_seconds: u64,
}

impl HootHeader {
    /// Parse the fixed header without reading beyond `data`.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_LEN {
            return Err(HootError::TruncatedHeader {
                required: HEADER_LEN,
                actual: data.len(),
            });
        }

        let source_end = data[..64].iter().position(|byte| *byte == 0).unwrap_or(64);
        let source = std::str::from_utf8(&data[..source_end])
            .map_err(|source| HootError::InvalidHeaderText {
                field: "source",
                offset: 0,
                source,
            })?
            .to_owned();
        let reserved = data[64..70]
            .try_into()
            .expect("slice length was checked above");
        let start_time_unix_seconds = u64::from_le_bytes(
            data[72..80]
                .try_into()
                .expect("slice length was checked above"),
        );

        Ok(Self {
            source,
            reserved,
            compliancy: data[COMPLIANCY_OFFSET],
            format_flags: data[71],
            start_time_unix_seconds,
        })
    }

    pub(crate) fn require_supported(&self) -> Result<()> {
        if self.compliancy != SUPPORTED_COMPLIANCY {
            return Err(HootError::UnsupportedCompliancy {
                offset: COMPLIANCY_OFFSET as u64,
                compliancy: self.compliancy,
                supported: "19",
            });
        }
        if self.format_flags != 1 {
            return Err(HootError::UnsupportedFormatFlags {
                offset: 71,
                flags: self.format_flags,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> [u8; HEADER_LEN] {
        let mut bytes = [0_u8; HEADER_LEN];
        bytes[..10].copy_from_slice(b"Simulation");
        bytes[70] = 19;
        bytes[71] = 1;
        bytes[72..80].copy_from_slice(&1_787_835_538_u64.to_le_bytes());
        bytes
    }

    #[test]
    fn parses_verified_fields() {
        let parsed = HootHeader::parse(&header()).unwrap();
        assert_eq!(parsed.source, "Simulation");
        assert_eq!(parsed.compliancy, 19);
        assert_eq!(parsed.format_flags, 1);
        assert_eq!(parsed.start_time_unix_seconds, 1_787_835_538);
        parsed.require_supported().unwrap();
    }

    #[test]
    fn rejects_short_input() {
        assert!(matches!(
            HootHeader::parse(&[0; HEADER_LEN - 1]),
            Err(HootError::TruncatedHeader { .. })
        ));
    }

    #[test]
    fn reports_unsupported_compliancy() {
        let mut bytes = header();
        bytes[70] = 18;
        assert!(matches!(
            HootHeader::parse(&bytes).unwrap().require_supported(),
            Err(HootError::UnsupportedCompliancy { compliancy: 18, .. })
        ));
    }

    #[test]
    fn reports_unsupported_format_flags() {
        let mut bytes = header();
        bytes[71] = 2;
        assert!(matches!(
            HootHeader::parse(&bytes).unwrap().require_supported(),
            Err(HootError::UnsupportedFormatFlags { flags: 2, .. })
        ));
    }
}
