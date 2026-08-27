use thiserror::Error;

/// Result type used throughout the native decoder.
pub type Result<T> = std::result::Result<T, HootError>;

/// Structured failures emitted by the HOOT reader and Polars adapter.
#[derive(Debug, Error)]
pub enum HootError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Polars error: {0}")]
    Polars(#[from] polars::error::PolarsError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("HOOT header is truncated at byte {actual}; at least {required} bytes are required")]
    TruncatedHeader { required: usize, actual: usize },

    #[error("header field {field} is not valid UTF-8 at byte {offset}: {source}")]
    InvalidHeaderText {
        field: &'static str,
        offset: u64,
        #[source]
        source: std::str::Utf8Error,
    },

    #[error("unsupported HOOT compliancy {compliancy} at byte {offset}; supported: {supported}")]
    UnsupportedCompliancy {
        offset: u64,
        compliancy: u8,
        supported: &'static str,
    },

    #[error("unsupported HOOT format flags 0x{flags:02x} at byte {offset}; supported: 0x01")]
    UnsupportedFormatFlags { offset: u64, flags: u8 },

    #[error("invalid entropy code 0b{code:b} at byte {offset}, bit {bit}")]
    InvalidPrefixCode { offset: u64, bit: u64, code: u16 },

    #[error(
        "entropy stream ended without its end marker at byte {offset} ({partial_code_bits} partial code bits)"
    )]
    MissingEndMarker { offset: u64, partial_code_bits: u8 },

    #[error(
        "decoded body exceeds the configured {limit}-byte ceiling near compressed byte {offset}"
    )]
    DecodedSizeLimit { offset: u64, limit: usize },

    #[error(
        "record at decoded byte {decoded_offset} is truncated near compressed byte {compressed_offset}; needed {needed} decoded bytes, found {available}"
    )]
    TruncatedRecord {
        decoded_offset: u64,
        compressed_offset: u64,
        needed: usize,
        available: usize,
    },

    #[error("record at decoded byte {decoded_offset} has invalid DLC byte 0x{dlc:02x}")]
    InvalidDlc { decoded_offset: u64, dlc: u8 },

    #[error(
        "payload delta state exceeded {limit} distinct record headers at decoded byte {decoded_offset}"
    )]
    PayloadStateLimit { decoded_offset: u64, limit: usize },

    #[error(
        "custom record 0x{header:08x} at decoded byte {decoded_offset} has an invalid descriptor: {reason}"
    )]
    InvalidCustomDescriptor {
        decoded_offset: u64,
        header: u32,
        reason: String,
    },

    #[error(
        "custom signal 0x{raw_id:x} at decoded byte {decoded_offset} uses unsupported type code 0x{type_code:02x}"
    )]
    UnsupportedCustomType {
        decoded_offset: u64,
        raw_id: u32,
        type_code: u8,
    },

    #[error(
        "custom signal 0x{raw_id:x} at decoded byte {decoded_offset} has invalid {field}: {reason}"
    )]
    InvalidCustomPayload {
        decoded_offset: u64,
        raw_id: u32,
        field: &'static str,
        reason: String,
    },

    #[error(
        "custom signal 0x{raw_id:x} was updated at decoded byte {decoded_offset} before its name/type definition"
    )]
    MissingSignalDefinition { decoded_offset: u64, raw_id: u32 },

    #[error(
        "semantic decoding is unavailable for CAN frame 0x{arbitration_id:08x} at decoded byte {decoded_offset}"
    )]
    UnsupportedCanFrame {
        decoded_offset: u64,
        arbitration_id: u32,
    },

    #[error(
        "CAN frame 0x{arbitration_id:08x} at decoded byte {decoded_offset} has {actual} payload bytes; expected {expected}"
    )]
    InvalidCanPayload {
        decoded_offset: u64,
        arbitration_id: u32,
        expected: usize,
        actual: usize,
    },

    #[error(
        "timestamp {timestamp_us} at decoded byte {decoded_offset} arrived after rows through {emitted_through_us} were emitted; increase the {reorder_window_us} us reorder window"
    )]
    LateTimestamp {
        timestamp_us: i64,
        emitted_through_us: i64,
        decoded_offset: u64,
        reorder_window_us: i64,
    },

    #[error(
        "timestamp reorder buffer exceeded {limit} unique rows near timestamp {timestamp_us}; reduce logging disorder or raise max_buffered_rows"
    )]
    ReorderBufferLimit { timestamp_us: i64, limit: usize },

    #[error("schema error: {0}")]
    Schema(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}
