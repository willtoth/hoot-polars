//! Sparse Polars conversion over the neutral native decoder.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::path::Path;

use memmap2::Mmap;
use polars::prelude::{DataFrame, DataType, Field, NamedFrom, Schema, Series};

use crate::error::{HootError, Result};
use crate::model::{HootSchema, SignalInfo, SignalType, SignalUpdate, SignalValue};
use crate::{DecodeOptions, HootReader, SchemaReport, TailPolicy};

/// Compatibility facade for native HOOT-to-Polars conversion.
pub struct HootParser;

impl HootParser {
    /// Decode an owned HOOT buffer using documented lenient tail recovery.
    pub fn from_bytes(data: Vec<u8>) -> Result<DataFrame> {
        Self::from_bytes_with_options(&data, facade_options())
    }

    /// Decode a borrowed HOOT buffer with explicit reader options.
    pub fn from_bytes_with_options(data: &[u8], options: DecodeOptions) -> Result<DataFrame> {
        let reader = HootReader::with_options(data, options)?;
        let report = reader.infer_schema()?;
        dataframe_from_reader(&reader, &report.schema, options, None)
    }

    /// Decode only the named signals while retaining the normal sparse-row
    /// contract. This avoids allocating hundreds of unused columns for a
    /// focused analysis.
    pub fn from_bytes_selected(data: Vec<u8>, signal_names: &[&str]) -> Result<DataFrame> {
        Self::from_bytes_selected_with_options(&data, signal_names, facade_options())
    }

    /// Narrow projection with explicit reader options.
    pub fn from_bytes_selected_with_options(
        data: &[u8],
        signal_names: &[&str],
        options: DecodeOptions,
    ) -> Result<DataFrame> {
        let reader = HootReader::with_options(data, options)?;
        let report = reader.infer_schema()?;
        dataframe_from_reader(&reader, &report.schema, options, Some(signal_names))
    }

    /// Decode a file through a read-only memory map.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<DataFrame> {
        Self::from_file_with_options(path, facade_options())
    }

    /// Decode a memory-mapped file with explicit reader options.
    pub fn from_file_with_options<P: AsRef<Path>>(
        path: P,
        options: DecodeOptions,
    ) -> Result<DataFrame> {
        let file = File::open(path)?;
        // SAFETY: the map is read-only, remains scoped inside this function,
        // and `file` is kept alive until all decoder borrows have ended.
        let mmap = unsafe { Mmap::map(&file)? };
        Self::from_bytes_with_options(&mmap, options)
    }

    /// Decode only the named signals from a memory-mapped file.
    pub fn from_file_selected<P: AsRef<Path>>(path: P, signal_names: &[&str]) -> Result<DataFrame> {
        let file = File::open(path)?;
        // SAFETY: the map is read-only, remains scoped inside this function,
        // and `file` is kept alive until all decoder borrows have ended.
        let mmap = unsafe { Mmap::map(&file)? };
        Self::from_bytes_selected_with_options(&mmap, signal_names, facade_options())
    }

    /// Infer the companion schema and retain unsupported-frame evidence.
    pub fn inspect(data: &[u8]) -> Result<SchemaReport> {
        HootReader::with_options(data, facade_options())?.infer_schema()
    }

    /// Infer the stable, metadata-bearing HOOT schema.
    pub fn infer_schema(data: &[u8]) -> Result<HootSchema> {
        Ok(Self::inspect(data)?.schema)
    }

    /// Process a memory-mapped file in sparse row batches.
    ///
    /// A timestamp group is never split across callbacks. Memory used for
    /// decoded values is bounded by the batch plus at most
    /// `DecodeOptions::max_buffered_rows` reorder rows, in addition to the
    /// read-only mapping and first-pass schema.
    pub fn process_file_batched<P, F>(path: P, rows_per_batch: usize, on_batch: F) -> Result<Schema>
    where
        P: AsRef<Path>,
        F: FnMut(DataFrame) -> Result<()>,
    {
        Self::process_file_batched_with_options(path, rows_per_batch, facade_options(), on_batch)
    }

    /// Batched conversion with explicit strict/lenient tail behavior.
    pub fn process_file_batched_with_options<P, F>(
        path: P,
        rows_per_batch: usize,
        options: DecodeOptions,
        on_batch: F,
    ) -> Result<Schema>
    where
        P: AsRef<Path>,
        F: FnMut(DataFrame) -> Result<()>,
    {
        process_file_batched_inner(path.as_ref(), rows_per_batch, options, None, on_batch)
    }

    /// Process only the named signals in bounded sparse row batches.
    pub fn process_file_batched_selected<P, F>(
        path: P,
        rows_per_batch: usize,
        signal_names: &[&str],
        on_batch: F,
    ) -> Result<Schema>
    where
        P: AsRef<Path>,
        F: FnMut(DataFrame) -> Result<()>,
    {
        Self::process_file_batched_selected_with_options(
            path,
            rows_per_batch,
            signal_names,
            facade_options(),
            on_batch,
        )
    }

    /// Selected batched conversion with explicit reader options.
    pub fn process_file_batched_selected_with_options<P, F>(
        path: P,
        rows_per_batch: usize,
        signal_names: &[&str],
        options: DecodeOptions,
        on_batch: F,
    ) -> Result<Schema>
    where
        P: AsRef<Path>,
        F: FnMut(DataFrame) -> Result<()>,
    {
        process_file_batched_inner(
            path.as_ref(),
            rows_per_batch,
            options,
            Some(signal_names),
            on_batch,
        )
    }
}

/// Infer only the Polars-facing schema.
pub fn infer_schema(data: &[u8]) -> Result<Schema> {
    Ok(HootParser::infer_schema(data)?.to_polars_schema())
}

fn facade_options() -> DecodeOptions {
    DecodeOptions {
        tail_policy: TailPolicy::Lenient,
        ..DecodeOptions::default()
    }
}

fn dataframe_from_reader(
    reader: &HootReader<'_>,
    schema: &HootSchema,
    options: DecodeOptions,
    selection: Option<&[&str]>,
) -> Result<DataFrame> {
    let signals = supported_signals(schema, selection)?;
    let mut reorder = ReorderBuffer::new(&signals, options)?;
    let mut rows = SparseBatch::new(signals, 4096);
    for update in reader.updates(schema) {
        let update = update?;
        if reorder.contains(update.raw_id) {
            reorder.accept(update)?;
        }
        while let Some((timestamp, values)) = reorder.pop_ready(false) {
            rows.push_row(timestamp, values);
        }
        reorder.check_limit()?;
    }
    while let Some((timestamp, values)) = reorder.pop_ready(true) {
        rows.push_row(timestamp, values);
    }
    rows.build()
}

fn process_file_batched_inner<F>(
    path: &Path,
    rows_per_batch: usize,
    options: DecodeOptions,
    selection: Option<&[&str]>,
    mut on_batch: F,
) -> Result<Schema>
where
    F: FnMut(DataFrame) -> Result<()>,
{
    if rows_per_batch == 0 {
        return Err(HootError::InvalidArgument(
            "rows_per_batch must be greater than zero".to_owned(),
        ));
    }
    let file = File::open(path)?;
    // SAFETY: this is a read-only map, `file` outlives it, and neither the
    // callback nor returned schema can retain a borrow into the mapping.
    let mmap = unsafe { Mmap::map(&file)? };
    let reader = HootReader::with_options(&mmap, options)?;
    let report = reader.infer_schema()?;
    let signals = supported_signals(&report.schema, selection)?;
    let polars_schema = polars_schema(&signals);
    stream_batches(
        &reader,
        &report.schema,
        rows_per_batch,
        options,
        signals,
        &mut on_batch,
    )?;
    Ok(polars_schema)
}

fn stream_batches<F>(
    reader: &HootReader<'_>,
    _schema: &HootSchema,
    rows_per_batch: usize,
    options: DecodeOptions,
    signals: Vec<SignalInfo>,
    on_batch: &mut F,
) -> Result<()>
where
    F: FnMut(DataFrame) -> Result<()>,
{
    let mut reorder = ReorderBuffer::new(&signals, options)?;
    let mut rows = SparseBatch::new(signals.clone(), rows_per_batch);
    for update in reader.updates(_schema) {
        let update = update?;
        if reorder.contains(update.raw_id) {
            reorder.accept(update)?;
        }
        while let Some((timestamp, values)) = reorder.pop_ready(false) {
            rows.push_row(timestamp, values);
            if rows.len() == rows_per_batch {
                let batch =
                    std::mem::replace(&mut rows, SparseBatch::new(signals.clone(), rows_per_batch))
                        .build()?;
                on_batch(batch)?;
            }
        }
        reorder.check_limit()?;
    }
    while let Some((timestamp, values)) = reorder.pop_ready(true) {
        rows.push_row(timestamp, values);
        if rows.len() == rows_per_batch {
            let batch =
                std::mem::replace(&mut rows, SparseBatch::new(signals.clone(), rows_per_batch))
                    .build()?;
            on_batch(batch)?;
        }
    }
    if !rows.is_empty() {
        on_batch(rows.build()?)?;
    }
    Ok(())
}

fn polars_schema(signals: &[SignalInfo]) -> Schema {
    let mut fields = Vec::with_capacity(signals.len() + 1);
    fields.push(Field::new("timestamp".into(), DataType::Int64));
    fields.extend(signals.iter().map(|signal| {
        Field::new(
            signal.name.as_str().into(),
            signal
                .signal_type
                .polars_type()
                .expect("supported_signals filters unknown types"),
        )
    }));
    Schema::from_iter(fields)
}

fn supported_signals(schema: &HootSchema, selection: Option<&[&str]>) -> Result<Vec<SignalInfo>> {
    let wanted = selection.map(|names| names.iter().copied().collect::<HashSet<_>>());
    if wanted.as_ref().is_some_and(HashSet::is_empty) {
        return Err(HootError::InvalidArgument(
            "at least one selected signal is required".to_owned(),
        ));
    }
    let mut names = HashSet::new();
    let mut signals = Vec::with_capacity(schema.len());
    for signal in schema.signals() {
        if wanted
            .as_ref()
            .is_some_and(|wanted| !wanted.contains(signal.name.as_str()))
        {
            continue;
        }
        if signal.signal_type.polars_type().is_none() {
            return Err(HootError::Schema(format!(
                "signal 0x{:x} ({}) has unsupported type {}",
                signal.raw_id, signal.name, signal.original_type
            )));
        }
        if signal.name == "timestamp" {
            return Err(HootError::Schema(format!(
                "signal 0x{:x} uses reserved column name timestamp",
                signal.raw_id
            )));
        }
        if !names.insert(signal.name.clone()) {
            return Err(HootError::Schema(format!(
                "duplicate signal column name {}",
                signal.name
            )));
        }
        signals.push(signal.clone());
    }
    if let Some(wanted) = wanted {
        let missing = wanted
            .into_iter()
            .filter(|name| !names.contains(*name))
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(HootError::Schema(format!(
                "selected signals are absent from the native schema: {}",
                missing.join(", ")
            )));
        }
    }
    Ok(signals)
}

struct SparseBatch {
    signals: Vec<SignalInfo>,
    timestamps: Vec<i64>,
    columns: Vec<Vec<Option<SignalValue>>>,
}

impl SparseBatch {
    fn new(signals: Vec<SignalInfo>, capacity: usize) -> Self {
        let columns = (0..signals.len())
            .map(|_| Vec::with_capacity(capacity))
            .collect();
        Self {
            signals,
            timestamps: Vec::with_capacity(capacity),
            columns,
        }
    }

    fn len(&self) -> usize {
        self.timestamps.len()
    }

    fn is_empty(&self) -> bool {
        self.timestamps.is_empty()
    }

    fn push_row(&mut self, timestamp: i64, mut values: Vec<Option<SignalValue>>) {
        debug_assert_eq!(values.len(), self.columns.len());
        self.timestamps.push(timestamp);
        for (column, value) in self.columns.iter_mut().zip(&mut values) {
            column.push(value.take());
        }
    }

    fn build(self) -> Result<DataFrame> {
        let mut columns = Vec::with_capacity(self.signals.len() + 1);
        columns.push(Series::new("timestamp".into(), self.timestamps).into());
        for (signal, values) in self.signals.into_iter().zip(self.columns) {
            columns.push(build_series(&signal, values)?.into());
        }
        Ok(DataFrame::new(columns)?)
    }
}

struct ReorderBuffer {
    index: HashMap<u32, usize>,
    column_count: usize,
    pending: BTreeMap<i64, Vec<Option<SignalValue>>>,
    max_timestamp: Option<i64>,
    emitted_through: Option<i64>,
    reorder_window_us: i64,
    max_buffered_rows: usize,
}

impl ReorderBuffer {
    fn new(signals: &[SignalInfo], options: DecodeOptions) -> Result<Self> {
        if options.reorder_window_us < 0 {
            return Err(HootError::InvalidArgument(
                "reorder_window_us cannot be negative".to_owned(),
            ));
        }
        if options.max_buffered_rows == 0 {
            return Err(HootError::InvalidArgument(
                "max_buffered_rows must be greater than zero".to_owned(),
            ));
        }
        Ok(Self {
            index: signals
                .iter()
                .enumerate()
                .map(|(index, signal)| (signal.raw_id, index))
                .collect(),
            column_count: signals.len(),
            pending: BTreeMap::new(),
            max_timestamp: None,
            emitted_through: None,
            reorder_window_us: options.reorder_window_us,
            max_buffered_rows: options.max_buffered_rows,
        })
    }

    fn accept(&mut self, update: SignalUpdate) -> Result<()> {
        if let Some(emitted) = self.emitted_through
            && update.timestamp_us <= emitted
        {
            return Err(HootError::LateTimestamp {
                timestamp_us: update.timestamp_us,
                emitted_through_us: emitted,
                decoded_offset: update.decoded_offset,
                reorder_window_us: self.reorder_window_us,
            });
        }
        self.max_timestamp = Some(self.max_timestamp.map_or(update.timestamp_us, |maximum| {
            maximum.max(update.timestamp_us)
        }));
        let index = self.index.get(&update.raw_id).copied().ok_or_else(|| {
            HootError::Schema(format!(
                "update for signal 0x{:x} ({}) is absent from the inferred schema",
                update.raw_id, update.name
            ))
        })?;
        let values = self
            .pending
            .entry(update.timestamp_us)
            .or_insert_with(|| vec![None; self.column_count]);
        values[index] = Some(update.value);
        Ok(())
    }

    fn contains(&self, raw_id: u32) -> bool {
        self.index.contains_key(&raw_id)
    }

    fn pop_ready(&mut self, force: bool) -> Option<(i64, Vec<Option<SignalValue>>)> {
        let timestamp = *self.pending.first_key_value()?.0;
        let ready = force
            || self
                .max_timestamp
                .is_some_and(|maximum| maximum.saturating_sub(timestamp) > self.reorder_window_us);
        if !ready {
            return None;
        }
        let row = self.pending.pop_first()?;
        self.emitted_through = Some(row.0);
        Some(row)
    }

    fn check_limit(&self) -> Result<()> {
        if self.pending.len() > self.max_buffered_rows {
            return Err(HootError::ReorderBufferLimit {
                timestamp_us: self.max_timestamp.unwrap_or_default(),
                limit: self.max_buffered_rows,
            });
        }
        Ok(())
    }
}

fn build_series(signal: &SignalInfo, values: Vec<Option<SignalValue>>) -> Result<Series> {
    let name = signal.name.as_str().into();
    let mismatch = || {
        HootError::Schema(format!(
            "value type did not match inferred type for {}",
            signal.name
        ))
    };
    let series = match signal.signal_type {
        SignalType::Raw => Series::new(
            name,
            values
                .into_iter()
                .map(|value| match value {
                    Some(SignalValue::Raw(value)) => {
                        Ok(Some(String::from_utf8_lossy(&value).into_owned()))
                    }
                    None => Ok(None),
                    _ => Err(mismatch()),
                })
                .collect::<Result<Vec<Option<String>>>>()?,
        ),
        SignalType::Boolean => Series::new(
            name,
            typed_values(values, |value| match value {
                SignalValue::Boolean(value) => Some(value),
                _ => None,
            })?,
        ),
        SignalType::Int64 => Series::new(
            name,
            typed_values(values, |value| match value {
                SignalValue::Int64(value) => Some(value),
                _ => None,
            })?,
        ),
        SignalType::Float32 => Series::new(
            name,
            typed_values(values, |value| match value {
                SignalValue::Float32(value) => Some(value),
                _ => None,
            })?,
        ),
        SignalType::Float64 => Series::new(
            name,
            typed_values(values, |value| match value {
                SignalValue::Float64(value) => Some(value),
                _ => None,
            })?,
        ),
        SignalType::String => Series::new(
            name,
            typed_values(values, |value| match value {
                SignalValue::String(value) => Some(value),
                _ => None,
            })?,
        ),
        SignalType::BooleanArray => {
            list_series(name, values, DataType::Boolean, |value| match value {
                SignalValue::BooleanArray(value) => Some(Series::new("".into(), value)),
                _ => None,
            })?
        }
        SignalType::Int64Array => {
            list_series(name, values, DataType::Int64, |value| match value {
                SignalValue::Int64Array(value) => Some(Series::new("".into(), value)),
                _ => None,
            })?
        }
        SignalType::Float32Array => {
            list_series(name, values, DataType::Float32, |value| match value {
                SignalValue::Float32Array(value) => Some(Series::new("".into(), value)),
                _ => None,
            })?
        }
        SignalType::Float64Array => {
            list_series(name, values, DataType::Float64, |value| match value {
                SignalValue::Float64Array(value) => Some(Series::new("".into(), value)),
                _ => None,
            })?
        }
        SignalType::StringArray => {
            list_series(name, values, DataType::String, |value| match value {
                SignalValue::StringArray(value) => Some(Series::new("".into(), value)),
                _ => None,
            })?
        }
        SignalType::Unknown(_) => return Err(mismatch()),
    };
    Ok(series)
}

fn typed_values<T, F>(values: Vec<Option<SignalValue>>, convert: F) -> Result<Vec<Option<T>>>
where
    F: Fn(SignalValue) -> Option<T>,
{
    values
        .into_iter()
        .map(|value| match value {
            Some(value) => convert(value)
                .map(Some)
                .ok_or_else(|| HootError::Schema("value type mismatch".to_owned())),
            None => Ok(None),
        })
        .collect()
}

fn list_series<F>(
    name: polars::prelude::PlSmallStr,
    values: Vec<Option<SignalValue>>,
    inner_type: DataType,
    convert: F,
) -> Result<Series>
where
    F: Fn(SignalValue) -> Option<Series>,
{
    let values = values
        .into_iter()
        .map(|value| match value {
            Some(value) => convert(value)
                .map(Some)
                .ok_or_else(|| HootError::Schema("array value type mismatch".to_owned())),
            None => Ok(None),
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Series::new(name, values).cast(&DataType::List(Box::new(inner_type)))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controlled_two_double_file() -> Vec<u8> {
        include_bytes!("../tests/fixtures/synthetic-two-double.hoot").to_vec()
    }

    #[test]
    fn facade_batches_and_parquet_round_trip_agree() {
        use polars::io::parquet::read::ParquetReader;
        use polars::io::parquet::write::ParquetWriter;
        use polars::prelude::SerReader;

        let data = controlled_two_double_file();
        let full = HootParser::from_bytes(data.clone()).unwrap();
        assert_eq!(full.shape(), (2, 2));
        assert_eq!(
            full.column("timestamp").unwrap().i64().unwrap().get(0),
            Some(937_511)
        );
        assert_eq!(full.column("x").unwrap().f64().unwrap().get(1), Some(2.0));

        let input = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(input.path(), data).unwrap();
        let mut batches = Vec::new();
        let inferred = HootParser::process_file_batched(input.path(), 1, |batch| {
            batches.push(batch);
            Ok(())
        })
        .unwrap();
        assert_eq!(&inferred, full.schema().as_ref());
        let mut batched = batches.remove(0);
        for batch in batches {
            batched.vstack_mut(&batch).unwrap();
        }
        assert!(batched.equals_missing(&full));

        let parquet = tempfile::NamedTempFile::new().unwrap();
        let mut writable = full.clone();
        ParquetWriter::new(parquet.reopen().unwrap())
            .finish(&mut writable)
            .unwrap();
        let round_trip = ParquetReader::new(parquet.reopen().unwrap())
            .finish()
            .unwrap();
        assert!(round_trip.equals_missing(&full));
    }

    #[test]
    fn selected_projection_is_narrow_and_validated() {
        let data = controlled_two_double_file();
        let selected = HootParser::from_bytes_selected(data.clone(), &["x"]).unwrap();
        assert_eq!(selected.get_column_names_str(), ["timestamp", "x"]);
        assert_eq!(selected.height(), 2);

        let input = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(input.path(), data.clone()).unwrap();
        let mut batches = Vec::new();
        let schema = HootParser::process_file_batched_selected(input.path(), 1, &["x"], |batch| {
            batches.push(batch);
            Ok(())
        })
        .unwrap();
        assert_eq!(&schema, selected.schema().as_ref());
        let mut batched = batches.remove(0);
        for batch in batches {
            batched.vstack_mut(&batch).unwrap();
        }
        assert!(batched.equals_missing(&selected));

        assert!(HootParser::from_bytes_selected(data.clone(), &[]).is_err());
        assert!(HootParser::from_bytes_selected(data, &["missing"]).is_err());
    }

    #[test]
    fn row_builder_is_sparse_sorted_and_last_update_wins() {
        let signals = vec![SignalInfo {
            raw_id: 7,
            name: "x".to_owned(),
            signal_type: SignalType::Int64,
            original_type: "int64".to_owned(),
            units: String::new(),
            metadata: "{}".to_owned(),
            source: crate::model::SignalSource::Custom,
            support: crate::model::SignalSupport::Full,
            bus: "Simulation".to_owned(),
            device: None,
            definition_decoded_offset: 0,
        }];
        let mut reorder = ReorderBuffer::new(
            &signals,
            DecodeOptions {
                reorder_window_us: 100,
                ..DecodeOptions::default()
            },
        )
        .unwrap();
        let mut batch = SparseBatch::new(signals, 2);
        for (timestamp_us, value) in [(20, 3), (10, 1), (10, 2)] {
            reorder
                .accept(SignalUpdate {
                    timestamp_us,
                    raw_id: 7,
                    name: "x".to_owned(),
                    value: SignalValue::Int64(value),
                    decoded_offset: 0,
                    compressed_byte_offset: 80,
                })
                .unwrap();
        }
        while let Some((timestamp, values)) = reorder.pop_ready(true) {
            batch.push_row(timestamp, values);
        }
        let frame = batch.build().unwrap();
        assert_eq!(frame.height(), 2);
        assert_eq!(frame.column("x").unwrap().i64().unwrap().get(0), Some(2));
    }
}
