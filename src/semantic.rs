use std::collections::{BTreeMap, HashSet, VecDeque};

use crate::catalog;
use crate::error::{HootError, Result};
use crate::framing::{FrameIter, RawFrame};
use crate::header::HootHeader;
use crate::model::{
    HootSchema, SchemaReport, SignalInfo, SignalSource, SignalSupport, SignalType, SignalUpdate,
    SignalValue, UnsupportedFrameInfo,
};

const CUSTOM_CLASS: u8 = 7;
const CUSTOM_DATA: u8 = 0;
const CUSTOM_NAME: u8 = 1;
const CUSTOM_UNITS: u8 = 2;

#[derive(Debug, Clone, Copy)]
struct CustomHeader {
    raw_id: u32,
    type_code: u8,
    exact_len: usize,
    subtype: u8,
}

pub(crate) fn infer_schema(
    header: &HootHeader,
    discovery_frames: FrameIter<'_>,
    mut frames: FrameIter<'_>,
) -> Result<SchemaReport> {
    let mut schema = HootSchema::new();
    catalog::apply_selection(&mut schema, catalog::discover(discovery_frames)?);
    let mut unsupported = BTreeMap::<(u32, u8, usize), UnsupportedFrameInfo>::new();
    let mut raw_frames = 0_u64;
    let mut custom_frames = 0_u64;
    let mut min_timestamp_us = None;
    let mut max_timestamp_us = None;
    let mut out_of_order_frames = 0_u64;
    let mut max_out_of_order_us = 0_u64;

    for frame in frames.by_ref() {
        let frame = frame?;
        raw_frames += 1;
        min_timestamp_us = Some(min_timestamp_us.map_or(frame.timestamp_us, |minimum: i64| {
            minimum.min(frame.timestamp_us)
        }));
        if let Some(maximum) = max_timestamp_us {
            if frame.timestamp_us < maximum {
                out_of_order_frames += 1;
                max_out_of_order_us =
                    max_out_of_order_us.max((maximum - frame.timestamp_us) as u64);
            }
            max_timestamp_us = Some(maximum.max(frame.timestamp_us));
        } else {
            max_timestamp_us = Some(frame.timestamp_us);
        }
        if frame.record_class == CUSTOM_CLASS {
            custom_frames += 1;
            apply_custom_definition(header, &frame, &mut schema)?;
        } else if let Some(kind) = catalog::classify(&frame, &schema) {
            catalog::add_schema(header, &frame, kind, &mut schema);
        } else {
            let key = (
                frame.arbitration_id,
                frame.record_class,
                frame.payload.len(),
            );
            let info = unsupported.entry(key).or_insert(UnsupportedFrameInfo {
                arbitration_id: frame.arbitration_id,
                record_class: frame.record_class,
                payload_len: frame.payload.len(),
                count: 0,
                first_decoded_offset: frame.decoded_offset,
                first_compressed_byte_offset: frame.compressed_byte_offset,
                first_payload: frame.payload.clone(),
                first_payload_delta: frame.payload_delta.clone(),
            });
            info.count += 1;
        }
    }

    Ok(SchemaReport {
        schema,
        raw_frames,
        custom_frames,
        min_timestamp_us,
        max_timestamp_us,
        out_of_order_frames,
        max_out_of_order_us,
        unsupported_frames: unsupported.into_values().collect(),
        recovered_tail: frames.tail_recovery().cloned(),
    })
}

fn apply_custom_definition(
    file_header: &HootHeader,
    frame: &RawFrame,
    schema: &mut HootSchema,
) -> Result<()> {
    let custom = parse_custom_header(frame)?;
    let payload = exact_payload(frame, custom)?;
    match custom.subtype {
        CUSTOM_NAME => {
            let signal_type = signal_type(custom.type_code);
            let name = parse_utf8(payload, frame, custom.raw_id, "name")?;
            let original_type = signal_type.original_type();
            schema.insert(SignalInfo {
                raw_id: custom.raw_id,
                name,
                signal_type,
                original_type,
                units: String::new(),
                metadata: "{}".to_owned(),
                source: SignalSource::Custom,
                support: SignalSupport::Full,
                bus: file_header.source.clone(),
                device: None,
                definition_decoded_offset: frame.decoded_offset,
            });
        }
        CUSTOM_UNITS => {
            let units = parse_utf8(payload, frame, custom.raw_id, "units")?;
            if let Some(signal) = schema.get_mut(custom.raw_id) {
                signal.units.clone_from(&units);
                signal.metadata = units_metadata(&units);
            }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) struct UpdateIter<'a> {
    frames: FrameIter<'a>,
    schema: &'a HootSchema,
    pending: VecDeque<SignalUpdate>,
    initialized_devices: HashSet<u8>,
    catalog_decoder: catalog::CatalogDecoder,
}

impl<'a> UpdateIter<'a> {
    pub(crate) fn new(frames: FrameIter<'a>, schema: &'a HootSchema) -> Self {
        Self {
            frames,
            schema,
            pending: VecDeque::new(),
            initialized_devices: HashSet::new(),
            catalog_decoder: catalog::CatalogDecoder::default(),
        }
    }
}

impl Iterator for UpdateIter<'_> {
    type Item = Result<SignalUpdate>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(update) = self.pending.pop_front() {
            return Some(Ok(update));
        }
        loop {
            let frame = match self.frames.next()? {
                Ok(frame) => frame,
                Err(error) => return Some(Err(error)),
            };
            if let Some(kind) = catalog::classify(&frame, self.schema) {
                let device_id = kind.device_id();
                let mut updates = match self.catalog_decoder.decode_frame(&frame, kind) {
                    Ok(updates) => updates,
                    Err(error) => return Some(Err(error)),
                };
                if self.initialized_devices.insert(device_id) {
                    updates.push(catalog::reset_update(&frame, device_id));
                }
                self.pending.extend(updates);
                return self.pending.pop_front().map(Ok);
            }
            if frame.record_class != CUSTOM_CLASS {
                continue;
            }
            let custom = match parse_custom_header(&frame) {
                Ok(custom) => custom,
                Err(error) => return Some(Err(error)),
            };
            if custom.subtype != CUSTOM_DATA {
                continue;
            }
            let signal = match self.schema.get(custom.raw_id) {
                Some(signal) => signal,
                None => {
                    return Some(Err(HootError::MissingSignalDefinition {
                        decoded_offset: frame.decoded_offset,
                        raw_id: custom.raw_id,
                    }));
                }
            };
            let payload = match exact_payload(&frame, custom) {
                Ok(payload) => payload,
                Err(error) => return Some(Err(error)),
            };
            let value = match decode_value(signal.signal_type, payload, &frame, custom.raw_id) {
                Ok(value) => value,
                Err(error) => return Some(Err(error)),
            };
            return Some(Ok(SignalUpdate {
                timestamp_us: frame.timestamp_us,
                raw_id: custom.raw_id,
                name: signal.name.clone(),
                value,
                decoded_offset: frame.decoded_offset,
                compressed_byte_offset: frame.compressed_byte_offset,
            }));
        }
    }
}

fn parse_custom_header(frame: &RawFrame) -> Result<CustomHeader> {
    if frame.record_class != CUSTOM_CLASS {
        return Err(HootError::InvalidCustomDescriptor {
            decoded_offset: frame.decoded_offset,
            header: frame.header,
            reason: "record class is not custom".to_owned(),
        });
    }
    let descriptor = ((frame.header >> 8) & 0xffff) as u16;
    if descriptor & 0x0f != 0 {
        return Err(HootError::InvalidCustomDescriptor {
            decoded_offset: frame.decoded_offset,
            header: frame.header,
            reason: format!(
                "low descriptor nibble is 0x{:x}, expected zero",
                descriptor & 0x0f
            ),
        });
    }
    let combined = usize::from(descriptor >> 4);
    let type_code = ((combined / 64) * 4) as u8;
    let exact_len = combined % 64;
    let index = frame.header & 0xff;
    if index == 0 {
        return Err(HootError::InvalidCustomDescriptor {
            decoded_offset: frame.decoded_offset,
            header: frame.header,
            reason: "signal index zero is reserved".to_owned(),
        });
    }
    Ok(CustomHeader {
        raw_id: (index << 16) | 0xff00,
        type_code,
        exact_len,
        subtype: ((frame.header >> 24) & 0x1f) as u8,
    })
}

fn exact_payload(frame: &RawFrame, custom: CustomHeader) -> Result<&[u8]> {
    if custom.exact_len > frame.payload.len() {
        return Err(HootError::InvalidCustomPayload {
            decoded_offset: frame.decoded_offset,
            raw_id: custom.raw_id,
            field: "length",
            reason: format!(
                "descriptor requests {} bytes but DLC provides {}",
                custom.exact_len,
                frame.payload.len()
            ),
        });
    }
    Ok(&frame.payload[..custom.exact_len])
}

fn signal_type(code: u8) -> SignalType {
    match code {
        0x00 => SignalType::Raw,
        0x04 => SignalType::Boolean,
        0x08 => SignalType::Int64,
        0x0c => SignalType::Float32,
        0x10 => SignalType::Float64,
        0x14 => SignalType::String,
        0x18 => SignalType::BooleanArray,
        0x1c => SignalType::Int64Array,
        0x20 => SignalType::Float32Array,
        0x24 => SignalType::Float64Array,
        0x28 => SignalType::StringArray,
        other => SignalType::Unknown(other),
    }
}

fn parse_utf8(
    payload: &[u8],
    frame: &RawFrame,
    raw_id: u32,
    field: &'static str,
) -> Result<String> {
    std::str::from_utf8(payload)
        .map(str::to_owned)
        .map_err(|error| HootError::InvalidCustomPayload {
            decoded_offset: frame.decoded_offset,
            raw_id,
            field,
            reason: error.to_string(),
        })
}

fn units_metadata(units: &str) -> String {
    if units.is_empty() {
        "{}".to_owned()
    } else {
        let escaped = serde_json::to_string(units).expect("serializing a string cannot fail");
        format!("{{\"units\": {escaped}}}")
    }
}

fn decode_value(
    signal_type: SignalType,
    payload: &[u8],
    frame: &RawFrame,
    raw_id: u32,
) -> Result<SignalValue> {
    let invalid = |field, reason: String| HootError::InvalidCustomPayload {
        decoded_offset: frame.decoded_offset,
        raw_id,
        field,
        reason,
    };
    match signal_type {
        SignalType::Raw => Ok(SignalValue::Raw(payload.to_vec())),
        SignalType::Boolean => {
            require_len(payload, 1).map_err(|reason| invalid("boolean", reason))?;
            Ok(SignalValue::Boolean(payload[0] != 0))
        }
        SignalType::Int64 => {
            require_len(payload, 8).map_err(|reason| invalid("int64", reason))?;
            Ok(SignalValue::Int64(i64::from_le_bytes(
                payload.try_into().expect("length checked"),
            )))
        }
        SignalType::Float32 => {
            require_len(payload, 4).map_err(|reason| invalid("float", reason))?;
            Ok(SignalValue::Float32(f32::from_le_bytes(
                payload.try_into().expect("length checked"),
            )))
        }
        SignalType::Float64 => {
            require_len(payload, 8).map_err(|reason| invalid("double", reason))?;
            Ok(SignalValue::Float64(f64::from_le_bytes(
                payload.try_into().expect("length checked"),
            )))
        }
        SignalType::String => parse_utf8(payload, frame, raw_id, "string").map(SignalValue::String),
        SignalType::BooleanArray => Ok(SignalValue::BooleanArray(
            payload.iter().map(|value| *value != 0).collect(),
        )),
        SignalType::Int64Array => decode_fixed_array::<8, _, _>(payload, i64::from_le_bytes)
            .map(SignalValue::Int64Array)
            .map_err(|reason| invalid("int64[]", reason)),
        SignalType::Float32Array => decode_fixed_array::<4, _, _>(payload, f32::from_le_bytes)
            .map(SignalValue::Float32Array)
            .map_err(|reason| invalid("float[]", reason)),
        SignalType::Float64Array => decode_fixed_array::<8, _, _>(payload, f64::from_le_bytes)
            .map(SignalValue::Float64Array)
            .map_err(|reason| invalid("double[]", reason)),
        SignalType::StringArray => decode_string_array(payload)
            .map(SignalValue::StringArray)
            .map_err(|reason| invalid("string[]", reason)),
        SignalType::Unknown(type_code) => Err(HootError::UnsupportedCustomType {
            decoded_offset: frame.decoded_offset,
            raw_id,
            type_code,
        }),
    }
}

fn require_len(payload: &[u8], expected: usize) -> std::result::Result<(), String> {
    if payload.len() == expected {
        Ok(())
    } else {
        Err(format!(
            "expected {expected} bytes, found {}",
            payload.len()
        ))
    }
}

fn decode_fixed_array<const WIDTH: usize, T, F>(
    payload: &[u8],
    decode: F,
) -> std::result::Result<Vec<T>, String>
where
    F: Fn([u8; WIDTH]) -> T,
{
    if !payload.len().is_multiple_of(WIDTH) {
        return Err(format!(
            "payload length {} is not divisible by element width {WIDTH}",
            payload.len()
        ));
    }
    Ok(payload
        .chunks_exact(WIDTH)
        .map(|chunk| decode(chunk.try_into().expect("chunks_exact width")))
        .collect())
}

fn decode_string_array(payload: &[u8]) -> std::result::Result<Vec<String>, String> {
    let mut offset = 0_usize;
    let mut values = Vec::new();
    while offset < payload.len() {
        let index = values.len();
        let len = read_u32(payload, &mut offset)? as usize;
        let end = offset
            .checked_add(len)
            .ok_or_else(|| format!("string {index} length overflow"))?;
        let bytes = payload
            .get(offset..end)
            .ok_or_else(|| format!("string {index} is truncated"))?;
        let value = std::str::from_utf8(bytes)
            .map_err(|error| format!("string {index} is not UTF-8: {error}"))?;
        values.push(value.to_owned());
        offset = end;
    }
    Ok(values)
}

fn read_u32(payload: &[u8], offset: &mut usize) -> std::result::Result<u32, String> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| "offset overflow".to_owned())?;
    let bytes = payload
        .get(*offset..end)
        .ok_or_else(|| "truncated 32-bit length".to_owned())?;
    *offset = end;
    Ok(u32::from_le_bytes(
        bytes.try_into().expect("length checked"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_metadata_is_stable() {
        assert_eq!(units_metadata(""), "{}");
        assert_eq!(units_metadata("V"), "{\"units\": \"V\"}");
    }

    #[test]
    fn string_arrays_use_hoot_length_sequence() {
        let mut payload = Vec::new();
        for value in ["alpha", "", "omega"] {
            payload.extend_from_slice(&(value.len() as u32).to_le_bytes());
            payload.extend_from_slice(value.as_bytes());
        }
        assert_eq!(
            decode_string_array(&payload).unwrap(),
            ["alpha", "", "omega"]
        );
    }

    #[test]
    fn fixed_array_rejects_partial_element() {
        assert!(decode_fixed_array::<8, _, _>(&[0; 9], i64::from_le_bytes).is_err());
    }

    #[test]
    fn neutral_values_cover_every_custom_family() {
        let frame = RawFrame {
            decoded_offset: 12,
            compressed_byte_offset: 90,
            compressed_bit: 0,
            header: 0xe000_0001,
            arbitration_id: 1,
            record_class: CUSTOM_CLASS,
            encoded_timestamp_us: 0,
            timestamp_us: 1,
            dlc: 0,
            dlc_flags: 0,
            payload_delta: Vec::new(),
            payload: Vec::new(),
        };
        let decode = |signal_type, payload: &[u8]| {
            decode_value(signal_type, payload, &frame, 0x1ff00).unwrap()
        };
        assert_eq!(
            decode(SignalType::Raw, b"raw"),
            SignalValue::Raw(b"raw".to_vec())
        );
        assert_eq!(
            decode(SignalType::Boolean, &[2]),
            SignalValue::Boolean(true)
        );
        assert_eq!(
            decode(SignalType::Int64, &(-7_i64).to_le_bytes()),
            SignalValue::Int64(-7)
        );
        assert_eq!(
            decode(SignalType::Float32, &1.5_f32.to_le_bytes()),
            SignalValue::Float32(1.5)
        );
        assert_eq!(
            decode(SignalType::Float64, &2.5_f64.to_le_bytes()),
            SignalValue::Float64(2.5)
        );
        assert_eq!(
            decode(SignalType::String, b"text"),
            SignalValue::String("text".to_owned())
        );
        assert_eq!(
            decode(SignalType::BooleanArray, &[0, 1, 2]),
            SignalValue::BooleanArray(vec![false, true, true])
        );

        let int_payload = [1_i64, -2]
            .into_iter()
            .flat_map(i64::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(
            decode(SignalType::Int64Array, &int_payload),
            SignalValue::Int64Array(vec![1, -2])
        );
        let float_payload = [1.0_f32, -2.0]
            .into_iter()
            .flat_map(f32::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(
            decode(SignalType::Float32Array, &float_payload),
            SignalValue::Float32Array(vec![1.0, -2.0])
        );
        let double_payload = [1.0_f64, -2.0]
            .into_iter()
            .flat_map(f64::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(
            decode(SignalType::Float64Array, &double_payload),
            SignalValue::Float64Array(vec![1.0, -2.0])
        );
        let mut string_payload = 1_u32.to_le_bytes().to_vec();
        string_payload.push(b'x');
        string_payload.extend_from_slice(&0_u32.to_le_bytes());
        assert_eq!(
            decode(SignalType::StringArray, &string_payload),
            SignalValue::StringArray(vec!["x".to_owned(), String::new()])
        );
    }
}
