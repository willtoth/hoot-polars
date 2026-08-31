//! Native CTRE Phoenix 6 HOOT decoding.

mod catalog;
pub mod error;
pub mod framing;
pub mod header;
mod huffman;
pub mod model;
mod polars_adapter;
mod repair;
mod semantic;

use header::HEADER_LEN;

pub use error::{HootError, Result};
pub use framing::{FrameIter, RawFrame, TailPolicy, TailRecovery};
pub use header::{COMPLIANCY_OFFSET, HootHeader, SUPPORTED_COMPLIANCY};
pub use model::{
    HootSchema, PhoenixDeviceInfo, PhoenixTransport, SchemaReport, SignalInfo, SignalSource,
    SignalSupport, SignalType, SignalUpdate, SignalValue, UnsupportedFrameInfo,
};
pub use polars_adapter::{HootParser, NarrowBatch, PreparedHoot, infer_schema};
pub use repair::{TailRepair, TailRepairReport, canonicalize_tail};

/// Reader configuration shared by raw and semantic passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeOptions {
    pub tail_policy: TailPolicy,
    /// Minimum timestamp regression retained while producing ordered sparse
    /// rows. Materializing APIs automatically widen this to the maximum
    /// regression measured during schema discovery. The raw frame iterator is
    /// unaffected.
    pub reorder_window_us: i64,
    /// Hard ceiling on unique timestamps retained by the reorder buffer.
    pub max_buffered_rows: usize,
}

impl Default for DecodeOptions {
    fn default() -> Self {
        Self {
            tail_policy: TailPolicy::Strict,
            reorder_window_us: 5_000_000,
            max_buffered_rows: 100_000,
        }
    }
}

/// Checked, Polars-independent view over one in-memory HOOT file.
#[derive(Debug, Clone)]
pub struct HootReader<'a> {
    data: &'a [u8],
    header: HootHeader,
    options: DecodeOptions,
    #[cfg(test)]
    frame_iter_calls: std::cell::Cell<usize>,
}

impl<'a> HootReader<'a> {
    /// Validate the fixed header and construct a strict reader.
    pub fn new(data: &'a [u8]) -> Result<Self> {
        Self::with_options(data, DecodeOptions::default())
    }

    /// Validate the fixed header and construct a configured reader.
    pub fn with_options(data: &'a [u8], options: DecodeOptions) -> Result<Self> {
        let header = HootHeader::parse(data)?;
        header.require_supported()?;
        Ok(Self {
            data,
            header,
            options,
            #[cfg(test)]
            frame_iter_calls: std::cell::Cell::new(0),
        })
    }

    pub fn header(&self) -> &HootHeader {
        &self.header
    }

    /// Iterate entropy-decoded physical records without applying a catalog.
    pub fn frames(&self) -> FrameIter<'_> {
        #[cfg(test)]
        self.frame_iter_calls
            .set(self.frame_iter_calls.get().saturating_add(1));
        FrameIter::new(
            &self.data[HEADER_LEN..],
            HEADER_LEN as u64,
            self.options.tail_policy,
        )
    }

    #[cfg(test)]
    pub(crate) fn frame_iter_calls(&self) -> usize {
        self.frame_iter_calls.get()
    }

    /// Scan signal definitions and retain exact unsupported physical IDs.
    pub fn infer_schema(&self) -> Result<SchemaReport> {
        semantic::infer_schema(&self.header, self.frames())
    }

    /// Iterate sparse semantic updates for the supplied companion schema.
    pub fn updates<'b>(
        &'b self,
        schema: &'b HootSchema,
    ) -> impl Iterator<Item = Result<SignalUpdate>> + 'b {
        semantic::UpdateIter::new(self.frames(), schema)
    }

    pub(crate) fn decoded_updates<'b>(
        &'b self,
        schema: &'b HootSchema,
    ) -> impl Iterator<Item = Result<model::DecodedUpdate>> + 'b {
        semantic::DecodedUpdateIter::new(self.frames(), schema)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn arbitrary_short_inputs_are_checked() {
        for len in 0..HEADER_LEN {
            let data = vec![0_u8; len];
            assert!(matches!(
                HootReader::new(&data),
                Err(HootError::TruncatedHeader { .. })
            ));
        }
    }

    #[test]
    fn schema_then_updates_create_exactly_two_physical_traversals() {
        let data = include_bytes!("../tests/fixtures/synthetic-two-double.hoot");
        let reader = HootReader::with_options(
            data,
            DecodeOptions {
                tail_policy: TailPolicy::Lenient,
                ..DecodeOptions::default()
            },
        )
        .unwrap();
        let report = reader.infer_schema().unwrap();
        assert_eq!(reader.frame_iter_calls(), 1);
        let updates = reader
            .updates(&report.schema)
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert!(!updates.is_empty());
        assert_eq!(reader.frame_iter_calls(), 2);
    }

    proptest! {
        #[test]
        fn arbitrary_entropy_bodies_never_panic(
            body in proptest::collection::vec(any::<u8>(), 0..4096),
            lenient in any::<bool>(),
        ) {
            let mut data = vec![0_u8; HEADER_LEN];
            data[70] = SUPPORTED_COMPLIANCY;
            data[71] = 1;
            data.extend(body);
            let reader = HootReader::with_options(
                &data,
                DecodeOptions {
                    tail_policy: if lenient { TailPolicy::Lenient } else { TailPolicy::Strict },
                    ..DecodeOptions::default()
                },
            ).unwrap();
            let _ = reader.frames().collect::<Result<Vec<_>>>();
            let _ = reader.infer_schema();
        }
    }
}
