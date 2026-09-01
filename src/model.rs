use std::collections::{BTreeMap, BTreeSet};

use polars::prelude::{DataType, Field, Schema};
use serde::Serialize;

/// Logical value family exposed by a HOOT signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalType {
    Raw,
    Boolean,
    Int64,
    Float32,
    Float64,
    String,
    BooleanArray,
    Int64Array,
    Float32Array,
    Float64Array,
    StringArray,
    Unknown(u8),
}

impl SignalType {
    pub fn original_type(self) -> String {
        match self {
            Self::Raw => "raw",
            Self::Boolean => "boolean",
            Self::Int64 => "int64",
            Self::Float32 => "float",
            Self::Float64 => "double",
            Self::String => "string",
            Self::BooleanArray => "boolean[]",
            Self::Int64Array => "int64[]",
            Self::Float32Array => "float[]",
            Self::Float64Array => "double[]",
            Self::StringArray => "string[]",
            Self::Unknown(code) => return format!("unknown/0x{code:02x}"),
        }
        .to_owned()
    }

    pub fn polars_type(self) -> Option<DataType> {
        match self {
            // Raw columns are exposed as lossy UTF-8 strings. The neutral
            // update model still retains the original bytes losslessly.
            Self::Raw => Some(DataType::String),
            Self::Boolean => Some(DataType::Boolean),
            Self::Int64 => Some(DataType::Int64),
            Self::Float32 => Some(DataType::Float32),
            Self::Float64 => Some(DataType::Float64),
            Self::String => Some(DataType::String),
            Self::BooleanArray => Some(DataType::List(Box::new(DataType::Boolean))),
            Self::Int64Array => Some(DataType::List(Box::new(DataType::Int64))),
            Self::Float32Array => Some(DataType::List(Box::new(DataType::Float32))),
            Self::Float64Array => Some(DataType::List(Box::new(DataType::Float64))),
            Self::StringArray => Some(DataType::List(Box::new(DataType::String))),
            Self::Unknown(_) => None,
        }
    }
}

/// Source family for a signal definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalSource {
    Custom,
    PhoenixCan,
}

/// Completeness of a semantic definition in the active versioned catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalSupport {
    /// The complete stream is decoded for the tested catalog/fixture scope.
    Full,
    /// Values are useful but depend on frame families not all decoded yet.
    Partial,
}

/// Stable schema information independent of Polars.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignalInfo {
    pub raw_id: u32,
    pub name: String,
    pub signal_type: SignalType,
    pub original_type: String,
    pub units: String,
    pub metadata: String,
    pub source: SignalSource,
    pub support: SignalSupport,
    pub bus: String,
    pub device: Option<String>,
    pub definition_decoded_offset: u64,
}

/// CAN transport selected for a discovered Phoenix device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PhoenixTransport {
    Can2,
    CanFd,
}

/// Version/device evidence used to select a semantic frame catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PhoenixDeviceInfo {
    pub device_type: String,
    pub device_id: u8,
    pub firmware_major: u8,
    pub firmware_minor: u8,
    pub firmware_bugfix: u8,
    pub firmware_build: u8,
    pub firmware_full: u32,
    pub is_pro_licensed: bool,
    pub transport: PhoenixTransport,
    /// Multiple incompatible firmware majors were observed for this device ID.
    pub version_conflict: bool,
    pub catalog_supported: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FrameKey {
    pub arbitration_id: u32,
    pub record_class: u8,
    pub payload_len: usize,
}

/// Deterministically ordered companion schema for a decoded log.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct HootSchema {
    signals: BTreeMap<u32, SignalInfo>,
    devices: BTreeMap<u8, PhoenixDeviceInfo>,
    #[serde(skip)]
    enabled_frames: BTreeSet<FrameKey>,
}

impl HootSchema {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, signal: SignalInfo) {
        self.signals.insert(signal.raw_id, signal);
    }

    pub fn get(&self, raw_id: u32) -> Option<&SignalInfo> {
        self.signals.get(&raw_id)
    }

    pub fn get_mut(&mut self, raw_id: u32) -> Option<&mut SignalInfo> {
        self.signals.get_mut(&raw_id)
    }

    pub fn signals(&self) -> impl ExactSizeIterator<Item = &SignalInfo> {
        self.signals.values()
    }

    pub fn devices(&self) -> impl ExactSizeIterator<Item = &PhoenixDeviceInfo> {
        self.devices.values()
    }

    pub(crate) fn insert_device(&mut self, device: PhoenixDeviceInfo) {
        self.devices.insert(device.device_id, device);
    }

    pub(crate) fn device(&self, device_id: u8) -> Option<&PhoenixDeviceInfo> {
        self.devices.get(&device_id)
    }

    pub(crate) fn enable_frame(&mut self, key: FrameKey) {
        self.enabled_frames.insert(key);
    }

    pub(crate) fn frame_enabled(&self, key: FrameKey) -> bool {
        self.enabled_frames.contains(&key)
    }

    pub fn len(&self) -> usize {
        self.signals.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signals.is_empty()
    }

    pub fn to_polars_schema(&self) -> Schema {
        let mut fields = Vec::with_capacity(self.signals.len() + 1);
        fields.push(Field::new("timestamp".into(), DataType::Int64));
        fields.extend(self.signals.values().filter_map(|signal| {
            signal
                .signal_type
                .polars_type()
                .map(|data_type| Field::new(signal.name.as_str().into(), data_type))
        }));
        Schema::from_iter(fields)
    }
}

/// A decoded update value. Arrays own their elements so an update can outlive
/// the current frame buffer.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "value")]
pub enum SignalValue {
    Raw(Vec<u8>),
    Boolean(bool),
    Int64(i64),
    Float32(f32),
    Float64(f64),
    String(String),
    BooleanArray(Vec<bool>),
    Int64Array(Vec<i64>),
    Float32Array(Vec<f32>),
    Float64Array(Vec<f64>),
    StringArray(Vec<String>),
}

/// Compact semantic update used by ingestion adapters. Signal names remain in
/// the companion schema so high-volume conversion does not allocate a new
/// owned name for every observed value.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DecodedUpdate {
    pub timestamp_us: i64,
    pub raw_id: u32,
    pub value: SignalValue,
    pub decoded_offset: u64,
    pub compressed_byte_offset: u64,
}

/// One sparse signal update in integer microseconds.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SignalUpdate {
    pub timestamp_us: i64,
    pub raw_id: u32,
    pub name: String,
    pub value: SignalValue,
    pub decoded_offset: u64,
    pub compressed_byte_offset: u64,
}

/// A physical CAN frame for which the active versioned catalog has no
/// semantic decoder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnsupportedFrameInfo {
    pub arbitration_id: u32,
    pub record_class: u8,
    pub payload_len: usize,
    pub count: u64,
    pub first_decoded_offset: u64,
    pub first_compressed_byte_offset: u64,
    /// Reconstructed payload from the first occurrence.
    pub first_payload: Vec<u8>,
    /// On-disk modular delta bytes from the first occurrence.
    pub first_payload_delta: Vec<u8>,
}

/// Results of the schema/framing pass, including unsupported data rather than
/// silently dropping it.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SchemaReport {
    pub schema: HootSchema,
    pub raw_frames: u64,
    pub custom_frames: u64,
    /// Minimum timestamp among record layouts that can emit semantic updates.
    pub min_timestamp_us: Option<i64>,
    /// Maximum timestamp among record layouts that can emit semantic updates.
    pub max_timestamp_us: Option<i64>,
    /// Number of timestamp regressions among semantic-update candidates.
    pub out_of_order_frames: u64,
    /// Largest timestamp regression among semantic-update candidates.
    pub max_out_of_order_us: u64,
    pub unsupported_frames: Vec<UnsupportedFrameInfo>,
    pub recovered_tail: Option<crate::framing::TailRecovery>,
}
