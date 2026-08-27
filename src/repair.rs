//! Canonical recovery for logs that end during a buffered record.
//!
//! Repair never mutates its input. It retains every complete physical record,
//! discards only the incomplete tail reported by the checked framing layer,
//! and appends the compliancy-19 entropy terminator.

use serde::Serialize;

use crate::error::{HootError, Result};
use crate::framing::{FrameIter, TailPolicy, TailRecovery};
use crate::header::{HEADER_LEN, HootHeader};
use crate::huffman::terminate_prefix;

/// Audit information accompanying a canonicalized byte stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TailRepairReport {
    pub changed: bool,
    pub original_bytes: usize,
    pub repaired_bytes: usize,
    pub retained_frames: u64,
    pub discarded_tail: Option<TailRecovery>,
}

/// An owned canonical HOOT stream and its audit report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailRepair {
    pub bytes: Vec<u8>,
    pub report: TailRepairReport,
}

/// Return a strict, entropy-terminated copy of `data`.
///
/// A complete input is copied unchanged. A truncated input is cut at the
/// beginning of its final incomplete physical record (or incomplete prefix
/// code when it ended between records) before the end marker is appended.
pub fn canonicalize_tail(data: &[u8]) -> Result<TailRepair> {
    let header = HootHeader::parse(data)?;
    header.require_supported()?;

    let body = &data[HEADER_LEN..];
    let mut frames = FrameIter::new(body, HEADER_LEN as u64, TailPolicy::Lenient);
    let mut retained_frames = 0_u64;
    for frame in frames.by_ref() {
        frame?;
        retained_frames += 1;
    }

    let discarded_tail = frames.tail_recovery().cloned();
    let changed = discarded_tail.is_some();
    let bytes = if let Some(recovery) = &discarded_tail {
        let repaired_body = terminate_prefix(body, recovery.discard_from_body_bit)?;
        let mut repaired = Vec::with_capacity(HEADER_LEN + repaired_body.len());
        repaired.extend_from_slice(&data[..HEADER_LEN]);
        repaired.extend_from_slice(&repaired_body);
        repaired
    } else if frames.saw_end_marker() {
        data.to_vec()
    } else {
        return Err(HootError::MissingEndMarker {
            offset: data.len() as u64,
            partial_code_bits: 0,
        });
    };

    // Treat repair as a checked transformation: the result must be strict and
    // retain exactly the complete frame count observed above.
    let mut strict = FrameIter::new(&bytes[HEADER_LEN..], HEADER_LEN as u64, TailPolicy::Strict);
    let mut verified_frames = 0_u64;
    for frame in strict.by_ref() {
        frame?;
        verified_frames += 1;
    }
    if !strict.saw_end_marker() || verified_frames != retained_frames {
        return Err(HootError::Schema(format!(
            "tail repair verification failed: retained={retained_frames}, decoded={verified_frames}, end_marker={}",
            strict.saw_end_marker()
        )));
    }

    Ok(TailRepair {
        report: TailRepairReport {
            changed,
            original_bytes: data.len(),
            repaired_bytes: bytes.len(),
            retained_frames,
            discarded_tail,
        },
        bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controlled_file() -> Vec<u8> {
        let body = hex::decode(
            "a4bbf45c94032ff635244838ff4824d7902021e323c154032011433e91620ff85d11a7019088c1952af6801f89060c",
        )
        .unwrap();
        let mut data = vec![0_u8; HEADER_LEN];
        data[..10].copy_from_slice(b"Simulation");
        data[70] = 19;
        data[71] = 1;
        data.extend(body);
        data
    }

    #[test]
    fn complete_stream_is_unchanged() {
        let input = controlled_file();
        let repaired = canonicalize_tail(&input).unwrap();
        assert!(!repaired.report.changed);
        assert_eq!(repaired.bytes, input);
        assert_eq!(repaired.report.retained_frames, 5);
    }

    #[test]
    fn every_byte_truncation_becomes_a_strict_stream() {
        let input = controlled_file();
        for cut in HEADER_LEN..input.len() {
            let truncated = &input[..cut];
            let expected = FrameIter::new(
                &truncated[HEADER_LEN..],
                HEADER_LEN as u64,
                TailPolicy::Lenient,
            )
            .filter_map(std::result::Result::ok)
            .count();
            let repaired = canonicalize_tail(truncated).unwrap();
            assert!(repaired.report.changed, "cut {cut}");
            let decoded = FrameIter::new(
                &repaired.bytes[HEADER_LEN..],
                HEADER_LEN as u64,
                TailPolicy::Strict,
            )
            .collect::<Result<Vec<_>>>()
            .unwrap();
            assert_eq!(decoded.len(), expected, "cut {cut}");
        }
    }
}
