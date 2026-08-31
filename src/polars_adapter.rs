//! Sparse Polars conversion over the neutral native decoder.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet, hash_map::Entry};
use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use memmap2::Mmap;
use polars::prelude::{DataFrame, DataType, Field, NamedFrom, Schema, Series};

use crate::error::{HootError, Result};
use crate::model::{DecodedUpdate, HootSchema, SignalInfo, SignalType, SignalValue};
use crate::{DecodeOptions, HootHeader, HootReader, SchemaReport, TailPolicy};

/// Compatibility facade for native HOOT-to-Polars conversion.
pub struct HootParser;

/// One physically narrow batch. Batches are grouped by device (with custom
/// signals in their own group) and include `source_sequence` as a stable
/// tie-breaker for equal timestamps.
#[derive(Debug)]
pub struct NarrowBatch {
    pub group: String,
    pub frame: DataFrame,
}

/// One prepared HOOT file that retains the schema-pass results for its later
/// semantic streaming traversal.
pub struct PreparedHoot {
    mmap: Mmap,
    options: DecodeOptions,
    header: HootHeader,
    report: SchemaReport,
    #[cfg(test)]
    frame_iter_calls: std::cell::Cell<usize>,
}

impl PreparedHoot {
    fn open(path: &Path, options: DecodeOptions) -> Result<Self> {
        let file = File::open(path)?;
        // SAFETY: the map is read-only, owns the operating-system mapping for
        // the lifetime of this object, and no mutable file handle is retained.
        let mmap = unsafe { Mmap::map(&file)? };
        let reader = HootReader::with_options(&mmap, options)?;
        let header = reader.header().clone();
        let report = reader.infer_schema()?;
        let options = options_for_report(options, &report)?;
        #[cfg(test)]
        let frame_iter_calls = std::cell::Cell::new(reader.frame_iter_calls());
        Ok(Self {
            mmap,
            options,
            header,
            report,
            #[cfg(test)]
            frame_iter_calls,
        })
    }

    /// Parsed fixed header retained from preparation.
    pub fn header(&self) -> &HootHeader {
        &self.header
    }

    /// Stable semantic schema and physical framing evidence from pass one.
    pub fn report(&self) -> &SchemaReport {
        &self.report
    }

    /// Stream every supported signal in bounded sparse row batches.
    pub fn process_batched<F>(&self, rows_per_batch: usize, on_batch: F) -> Result<Schema>
    where
        F: FnMut(DataFrame) -> Result<()>,
    {
        self.process_batched_inner(rows_per_batch, None, on_batch)
    }

    /// Stream only the selected supported signals in bounded sparse batches.
    pub fn process_batched_selected<F>(
        &self,
        rows_per_batch: usize,
        signal_names: &[&str],
        on_batch: F,
    ) -> Result<Schema>
    where
        F: FnMut(DataFrame) -> Result<()>,
    {
        self.process_batched_inner(rows_per_batch, Some(signal_names), on_batch)
    }

    /// Stream device-grouped batches instead of allocating every signal for
    /// every timestamp. The returned schema is the logical union of all
    /// batches, including the internal `source_sequence` ordering column.
    pub fn process_narrow_batched<F>(
        &self,
        rows_per_batch: usize,
        mut on_batch: F,
    ) -> Result<Schema>
    where
        F: FnMut(NarrowBatch) -> Result<()>,
    {
        if rows_per_batch == 0 {
            return Err(HootError::InvalidArgument(
                "rows_per_batch must be greater than zero".to_owned(),
            ));
        }
        let reader = HootReader::with_options(&self.mmap, self.options)?;
        let signals = supported_signals(&self.report.schema, None)?;
        let logical_schema = narrow_polars_schema(&signals);
        let result = stream_narrow_batches(
            &reader,
            &self.report.schema,
            rows_per_batch,
            self.options,
            signals,
            &mut on_batch,
        );
        #[cfg(test)]
        self.frame_iter_calls.set(
            self.frame_iter_calls
                .get()
                .saturating_add(reader.frame_iter_calls()),
        );
        result?;
        Ok(logical_schema)
    }

    fn process_batched_inner<F>(
        &self,
        rows_per_batch: usize,
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
        let reader = HootReader::with_options(&self.mmap, self.options)?;
        let signals = supported_signals(&self.report.schema, selection)?;
        let polars_schema = polars_schema(&signals);
        let result = stream_batches(
            &reader,
            &self.report.schema,
            rows_per_batch,
            self.options,
            signals,
            &mut on_batch,
        );
        #[cfg(test)]
        self.frame_iter_calls.set(
            self.frame_iter_calls
                .get()
                .saturating_add(reader.frame_iter_calls()),
        );
        result?;
        Ok(polars_schema)
    }

    #[cfg(test)]
    fn frame_iter_calls(&self) -> usize {
        self.frame_iter_calls.get()
    }
}

impl HootParser {
    /// Decode an owned HOOT buffer using documented lenient tail recovery.
    pub fn from_bytes(data: Vec<u8>) -> Result<DataFrame> {
        Self::from_bytes_with_options(&data, facade_options())
    }

    /// Decode a borrowed HOOT buffer with explicit reader options.
    pub fn from_bytes_with_options(data: &[u8], options: DecodeOptions) -> Result<DataFrame> {
        let reader = HootReader::with_options(data, options)?;
        let report = reader.infer_schema()?;
        let options = options_for_report(options, &report)?;
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
        let options = options_for_report(options, &report)?;
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

    /// Prepare a memory-mapped file with the normal lenient tail policy.
    pub fn prepare_file<P: AsRef<Path>>(path: P) -> Result<PreparedHoot> {
        Self::prepare_file_with_options(path, facade_options())
    }

    /// Prepare a memory-mapped file with explicit reader options. Preparation
    /// performs the schema/framing pass; `PreparedHoot::process_batched` then
    /// performs the semantic data pass without rediscovering that schema.
    pub fn prepare_file_with_options<P: AsRef<Path>>(
        path: P,
        options: DecodeOptions,
    ) -> Result<PreparedHoot> {
        PreparedHoot::open(path.as_ref(), options)
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

fn options_for_report(options: DecodeOptions, report: &SchemaReport) -> Result<DecodeOptions> {
    if options.reorder_window_us < 0 {
        return Err(HootError::InvalidArgument(
            "reorder_window_us cannot be negative".to_owned(),
        ));
    }
    let observed_reorder_window_us = i64::try_from(report.max_out_of_order_us).map_err(|_| {
        HootError::InvalidArgument(
            "observed timestamp regression exceeds signed 64-bit range".to_owned(),
        )
    })?;
    Ok(DecodeOptions {
        reorder_window_us: options.reorder_window_us.max(observed_reorder_window_us),
        ..options
    })
}

fn dataframe_from_reader(
    reader: &HootReader<'_>,
    schema: &HootSchema,
    options: DecodeOptions,
    selection: Option<&[&str]>,
) -> Result<DataFrame> {
    let signals: Arc<[SignalInfo]> = supported_signals(schema, selection)?.into();
    let mut reorder = ReorderBuffer::new(&signals, options)?;
    let mut rows = SparseBatch::new(Arc::clone(&signals), 4096);
    for update in reader.decoded_updates(schema) {
        let update = update?;
        reorder.accept(update)?;
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
    on_batch: F,
) -> Result<Schema>
where
    F: FnMut(DataFrame) -> Result<()>,
{
    if rows_per_batch == 0 {
        return Err(HootError::InvalidArgument(
            "rows_per_batch must be greater than zero".to_owned(),
        ));
    }
    let prepared = PreparedHoot::open(path, options)?;
    prepared.process_batched_inner(rows_per_batch, selection, on_batch)
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
    let signals: Arc<[SignalInfo]> = signals.into();
    let mut reorder = ReorderBuffer::new(&signals, options)?;
    let mut rows = SparseBatch::new(Arc::clone(&signals), rows_per_batch);
    for update in reader.decoded_updates(_schema) {
        let update = update?;
        reorder.accept(update)?;
        while let Some((timestamp, values)) = reorder.pop_ready(false) {
            rows.push_row(timestamp, values);
            if rows.len() == rows_per_batch {
                let batch = std::mem::replace(
                    &mut rows,
                    SparseBatch::new(Arc::clone(&signals), rows_per_batch),
                )
                .build()?;
                on_batch(batch)?;
            }
        }
        reorder.check_limit()?;
    }
    while let Some((timestamp, values)) = reorder.pop_ready(true) {
        rows.push_row(timestamp, values);
        if rows.len() == rows_per_batch {
            let batch = std::mem::replace(
                &mut rows,
                SparseBatch::new(Arc::clone(&signals), rows_per_batch),
            )
            .build()?;
            on_batch(batch)?;
        }
    }
    if !rows.is_empty() {
        on_batch(rows.build()?)?;
    }
    Ok(())
}

fn stream_narrow_batches<F>(
    reader: &HootReader<'_>,
    schema: &HootSchema,
    rows_per_batch: usize,
    options: DecodeOptions,
    signals: Vec<SignalInfo>,
    on_batch: &mut F,
) -> Result<()>
where
    F: FnMut(NarrowBatch) -> Result<()>,
{
    let groups = NarrowGroups::new(signals);
    let mut reorder = NarrowReorderBuffer::new(&groups, options)?;
    let mut batches = groups
        .groups
        .iter()
        .map(|group| NarrowSparseBatch::new(Arc::clone(&group.signals), rows_per_batch))
        .collect::<Vec<_>>();

    for update in reader.decoded_updates(schema) {
        reorder.accept(update?)?;
        while let Some(row) = reorder.pop_ready(false) {
            push_narrow_row(&groups, &mut batches, rows_per_batch, row, on_batch)?;
        }
        reorder.check_limit()?;
    }
    while let Some(row) = reorder.pop_ready(true) {
        push_narrow_row(&groups, &mut batches, rows_per_batch, row, on_batch)?;
    }
    for (group_index, rows) in batches.into_iter().enumerate() {
        if !rows.is_empty() {
            on_batch(NarrowBatch {
                group: groups.groups[group_index].key.clone(),
                frame: rows.build()?,
            })?;
        }
    }
    Ok(())
}

fn push_narrow_row<F>(
    groups: &NarrowGroups,
    batches: &mut [NarrowSparseBatch],
    rows_per_batch: usize,
    row: NarrowRow,
    on_batch: &mut F,
) -> Result<()>
where
    F: FnMut(NarrowBatch) -> Result<()>,
{
    let group = &groups.groups[row.group_index];
    let rows = &mut batches[row.group_index];
    rows.push_row(row.timestamp, row.source_sequence, row.values);
    if rows.len() == rows_per_batch {
        let frame = std::mem::replace(
            rows,
            NarrowSparseBatch::new(Arc::clone(&group.signals), rows_per_batch),
        )
        .build()?;
        on_batch(NarrowBatch {
            group: group.key.clone(),
            frame,
        })?;
    }
    Ok(())
}

struct NarrowGroup {
    key: String,
    signals: Arc<[SignalInfo]>,
}

struct NarrowGroups {
    groups: Vec<NarrowGroup>,
    index: HashMap<u32, (usize, usize)>,
}

impl NarrowGroups {
    fn new(signals: Vec<SignalInfo>) -> Self {
        let mut grouped = BTreeMap::<String, Vec<SignalInfo>>::new();
        for signal in signals {
            let key = signal
                .device
                .as_ref()
                .map_or_else(|| "custom".to_owned(), |device| format!("device/{device}"));
            grouped.entry(key).or_default().push(signal);
        }
        let groups = grouped
            .into_iter()
            .map(|(key, signals)| NarrowGroup {
                key,
                signals: signals.into(),
            })
            .collect::<Vec<_>>();
        let index = groups
            .iter()
            .enumerate()
            .flat_map(|(group_index, group)| {
                group
                    .signals
                    .iter()
                    .enumerate()
                    .map(move |(column_index, signal)| (signal.raw_id, (group_index, column_index)))
            })
            .collect();
        Self { groups, index }
    }
}

struct NarrowSparseBatch {
    signals: Arc<[SignalInfo]>,
    timestamps: Vec<i64>,
    source_sequences: Vec<i64>,
    columns: Vec<Vec<Option<SignalValue>>>,
}

impl NarrowSparseBatch {
    fn new(signals: Arc<[SignalInfo]>, capacity: usize) -> Self {
        let initial_capacity = capacity.min(1_024);
        let columns = (0..signals.len())
            .map(|_| Vec::with_capacity(initial_capacity))
            .collect();
        Self {
            signals,
            timestamps: Vec::with_capacity(initial_capacity),
            source_sequences: Vec::with_capacity(initial_capacity),
            columns,
        }
    }

    fn len(&self) -> usize {
        self.timestamps.len()
    }

    fn is_empty(&self) -> bool {
        self.timestamps.is_empty()
    }

    fn push_row(
        &mut self,
        timestamp: i64,
        source_sequence: i64,
        mut values: Vec<Option<SignalValue>>,
    ) {
        debug_assert_eq!(values.len(), self.columns.len());
        self.timestamps.push(timestamp);
        self.source_sequences.push(source_sequence);
        for (column, value) in self.columns.iter_mut().zip(&mut values) {
            column.push(value.take());
        }
    }

    fn build(self) -> Result<DataFrame> {
        let mut columns = Vec::with_capacity(self.signals.len() + 2);
        columns.push(Series::new("timestamp".into(), self.timestamps).into());
        columns.push(Series::new("source_sequence".into(), self.source_sequences).into());
        for (signal, values) in self.signals.iter().zip(self.columns) {
            columns.push(build_series(signal, values)?.into());
        }
        Ok(DataFrame::new(columns)?)
    }
}

struct NarrowPendingRow {
    source_sequence: i64,
    values: Vec<Option<SignalValue>>,
}

struct NarrowRow {
    timestamp: i64,
    source_sequence: i64,
    group_index: usize,
    values: Vec<Option<SignalValue>>,
}

struct NarrowReorderBuffer {
    index: HashMap<u32, (usize, usize)>,
    column_counts: Vec<usize>,
    pending: HashMap<(i64, usize), NarrowPendingRow>,
    rows: BinaryHeap<Reverse<(i64, usize)>>,
    timestamp_counts: HashMap<i64, usize>,
    max_timestamp: Option<i64>,
    emitted_through: Option<i64>,
    reorder_window_us: i64,
    max_buffered_rows: usize,
}

impl NarrowReorderBuffer {
    fn new(groups: &NarrowGroups, options: DecodeOptions) -> Result<Self> {
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
            index: groups.index.clone(),
            column_counts: groups
                .groups
                .iter()
                .map(|group| group.signals.len())
                .collect(),
            pending: HashMap::new(),
            rows: BinaryHeap::new(),
            timestamp_counts: HashMap::new(),
            max_timestamp: None,
            emitted_through: None,
            reorder_window_us: options.reorder_window_us,
            max_buffered_rows: options.max_buffered_rows,
        })
    }

    fn accept(&mut self, update: DecodedUpdate) -> Result<()> {
        let Some((group_index, column_index)) = self.index.get(&update.raw_id).copied() else {
            return Ok(());
        };
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
        let source_sequence = i64::try_from(update.decoded_offset).map_err(|_| {
            HootError::InvalidArgument("decoded offset exceeds signed 64-bit range".to_owned())
        })?;
        self.max_timestamp = Some(self.max_timestamp.map_or(update.timestamp_us, |maximum| {
            maximum.max(update.timestamp_us)
        }));
        let key = (update.timestamp_us, group_index);
        let row = match self.pending.entry(key) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                self.rows.push(Reverse(key));
                *self
                    .timestamp_counts
                    .entry(update.timestamp_us)
                    .or_default() += 1;
                entry.insert(NarrowPendingRow {
                    source_sequence,
                    values: (0..self.column_counts[group_index]).map(|_| None).collect(),
                })
            }
        };
        row.source_sequence = row.source_sequence.max(source_sequence);
        row.values[column_index] = Some(update.value);
        Ok(())
    }

    fn pop_ready(&mut self, force: bool) -> Option<NarrowRow> {
        let (timestamp, group_index) = self.rows.peek()?.0;
        let ready = force
            || self
                .max_timestamp
                .is_some_and(|maximum| maximum.saturating_sub(timestamp) > self.reorder_window_us);
        if !ready {
            return None;
        }
        self.rows.pop();
        let row = self
            .pending
            .remove(&(timestamp, group_index))
            .expect("narrow timestamp heap and pending map remain synchronized");
        match self.timestamp_counts.entry(timestamp) {
            Entry::Occupied(mut entry) if *entry.get() > 1 => *entry.get_mut() -= 1,
            Entry::Occupied(entry) => {
                entry.remove();
            }
            Entry::Vacant(_) => unreachable!("pending timestamp count remains synchronized"),
        }
        self.emitted_through = Some(timestamp);
        Some(NarrowRow {
            timestamp,
            source_sequence: row.source_sequence,
            group_index,
            values: row.values,
        })
    }

    fn check_limit(&self) -> Result<()> {
        if self.timestamp_counts.len() > self.max_buffered_rows {
            return Err(HootError::ReorderBufferLimit {
                timestamp_us: self.max_timestamp.unwrap_or_default(),
                limit: self.max_buffered_rows,
            });
        }
        Ok(())
    }
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

fn narrow_polars_schema(signals: &[SignalInfo]) -> Schema {
    let mut fields = Vec::with_capacity(signals.len() + 2);
    fields.push(Field::new("timestamp".into(), DataType::Int64));
    fields.push(Field::new("source_sequence".into(), DataType::Int64));
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
        if matches!(signal.name.as_str(), "timestamp" | "source_sequence") {
            return Err(HootError::Schema(format!(
                "signal 0x{:x} uses reserved column name {}",
                signal.raw_id, signal.name
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
    signals: Arc<[SignalInfo]>,
    timestamps: Vec<i64>,
    columns: Vec<Vec<Option<SignalValue>>>,
}

impl SparseBatch {
    fn new(signals: Arc<[SignalInfo]>, capacity: usize) -> Self {
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
        for (signal, values) in self.signals.iter().zip(self.columns) {
            columns.push(build_series(signal, values)?.into());
        }
        Ok(DataFrame::new(columns)?)
    }
}

struct ReorderBuffer {
    index: HashMap<u32, usize>,
    column_count: usize,
    pending: HashMap<i64, Vec<Option<SignalValue>>>,
    timestamps: BinaryHeap<Reverse<i64>>,
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
            pending: HashMap::new(),
            timestamps: BinaryHeap::new(),
            max_timestamp: None,
            emitted_through: None,
            reorder_window_us: options.reorder_window_us,
            max_buffered_rows: options.max_buffered_rows,
        })
    }

    fn accept(&mut self, update: DecodedUpdate) -> Result<()> {
        let Some(index) = self.index.get(&update.raw_id).copied() else {
            return Ok(());
        };
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
        let values = match self.pending.entry(update.timestamp_us) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                self.timestamps.push(Reverse(update.timestamp_us));
                entry.insert(vec![None; self.column_count])
            }
        };
        values[index] = Some(update.value);
        Ok(())
    }

    fn pop_ready(&mut self, force: bool) -> Option<(i64, Vec<Option<SignalValue>>)> {
        let timestamp = self.timestamps.peek()?.0;
        let ready = force
            || self
                .max_timestamp
                .is_some_and(|maximum| maximum.saturating_sub(timestamp) > self.reorder_window_us);
        if !ready {
            return None;
        }
        self.timestamps.pop();
        let values = self
            .pending
            .remove(&timestamp)
            .expect("timestamp heap and pending map remain synchronized");
        self.emitted_through = Some(timestamp);
        Some((timestamp, values))
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
    fn prepared_file_reuses_its_schema_for_streaming() {
        let data = controlled_two_double_file();
        let full = HootParser::from_bytes(data.clone()).unwrap();
        let input = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(input.path(), data).unwrap();

        let prepared = HootParser::prepare_file(input.path()).unwrap();
        assert_eq!(prepared.header().source, "Simulation");
        assert_eq!(prepared.report().schema.len(), 1);
        assert_eq!(prepared.frame_iter_calls(), 1);
        let mut batches = Vec::new();
        let schema = prepared
            .process_batched(1, |batch| {
                batches.push(batch);
                Ok(())
            })
            .unwrap();
        assert_eq!(prepared.frame_iter_calls(), 2);
        assert_eq!(&schema, full.schema().as_ref());
        let mut streamed = batches.remove(0);
        for batch in batches {
            streamed.vstack_mut(&batch).unwrap();
        }
        assert!(streamed.equals_missing(&full));
    }

    #[test]
    fn prepared_file_streams_narrow_batches_with_source_order() {
        let data = controlled_two_double_file();
        let input = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(input.path(), data).unwrap();

        let prepared = HootParser::prepare_file(input.path()).unwrap();
        let mut batches = Vec::new();
        let schema = prepared
            .process_narrow_batched(1, |batch| {
                assert_eq!(batch.group, "custom");
                batches.push(batch.frame);
                Ok(())
            })
            .unwrap();
        assert_eq!(
            schema
                .iter_names()
                .map(|name| name.as_str())
                .collect::<Vec<_>>(),
            ["timestamp", "source_sequence", "x"]
        );
        assert_eq!(batches.len(), 2);
        assert!(batches.iter().all(|batch| {
            batch
                .column("source_sequence")
                .unwrap()
                .i64()
                .unwrap()
                .get(0)
                .is_some_and(|sequence| sequence > 0)
        }));
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
    fn materializing_options_cover_the_regression_measured_in_pass_one() {
        let report = SchemaReport {
            max_out_of_order_us: 400,
            ..SchemaReport::default()
        };
        let adjusted = options_for_report(
            DecodeOptions {
                reorder_window_us: 100,
                ..DecodeOptions::default()
            },
            &report,
        )
        .unwrap();
        assert_eq!(adjusted.reorder_window_us, 400);

        let configured_larger = options_for_report(
            DecodeOptions {
                reorder_window_us: 1_000,
                ..DecodeOptions::default()
            },
            &report,
        )
        .unwrap();
        assert_eq!(configured_larger.reorder_window_us, 1_000);

        let signal = SignalInfo {
            raw_id: 1,
            name: "value".to_owned(),
            signal_type: SignalType::Int64,
            original_type: "int64".to_owned(),
            units: String::new(),
            metadata: "{}".to_owned(),
            source: crate::model::SignalSource::PhoenixCan,
            support: crate::model::SignalSupport::Full,
            bus: "Simulation".to_owned(),
            device: Some("device".to_owned()),
            definition_decoded_offset: 0,
        };
        let groups = NarrowGroups::new(vec![signal]);
        let mut reorder = NarrowReorderBuffer::new(&groups, adjusted).unwrap();
        let mut ordered = Vec::new();
        for (timestamp_us, decoded_offset) in [(300, 10), (500, 20), (100, 30)] {
            reorder
                .accept(DecodedUpdate {
                    timestamp_us,
                    raw_id: 1,
                    value: SignalValue::Int64(timestamp_us),
                    decoded_offset,
                    compressed_byte_offset: 80,
                })
                .unwrap();
            while let Some(row) = reorder.pop_ready(false) {
                ordered.push(row.timestamp);
            }
        }
        while let Some(row) = reorder.pop_ready(true) {
            ordered.push(row.timestamp);
        }
        assert_eq!(ordered, [100, 300, 500]);
    }

    #[test]
    fn adaptive_reordering_does_not_hide_invalid_negative_options() {
        let error = options_for_report(
            DecodeOptions {
                reorder_window_us: -1,
                ..DecodeOptions::default()
            },
            &SchemaReport::default(),
        )
        .unwrap_err();
        assert!(matches!(error, HootError::InvalidArgument(_)));
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
        let mut batch = SparseBatch::new(signals.into(), 2);
        for (timestamp_us, value) in [(20, 3), (10, 1), (10, 2)] {
            reorder
                .accept(DecodedUpdate {
                    timestamp_us,
                    raw_id: 7,
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

    #[test]
    fn narrow_reorder_separates_devices_and_orders_equal_timestamps() {
        let signal = |raw_id, device: &str| SignalInfo {
            raw_id,
            name: format!("{device}_value"),
            signal_type: SignalType::Int64,
            original_type: "int64".to_owned(),
            units: String::new(),
            metadata: "{}".to_owned(),
            source: crate::model::SignalSource::PhoenixCan,
            support: crate::model::SignalSupport::Full,
            bus: "Simulation".to_owned(),
            device: Some(device.to_owned()),
            definition_decoded_offset: 0,
        };
        let groups = NarrowGroups::new(vec![signal(1, "a"), signal(2, "b")]);
        assert_eq!(groups.groups.len(), 2);
        let mut reorder = NarrowReorderBuffer::new(
            &groups,
            DecodeOptions {
                reorder_window_us: 100,
                ..DecodeOptions::default()
            },
        )
        .unwrap();
        for (raw_id, decoded_offset) in [(2, 20), (1, 10)] {
            reorder
                .accept(DecodedUpdate {
                    timestamp_us: 50,
                    raw_id,
                    value: SignalValue::Int64(i64::from(raw_id)),
                    decoded_offset,
                    compressed_byte_offset: 80,
                })
                .unwrap();
        }
        let rows = std::iter::from_fn(|| reorder.pop_ready(true)).collect::<Vec<_>>();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].timestamp, 50);
        assert_eq!(rows[0].source_sequence, 10);
        assert_eq!(rows[1].source_sequence, 20);
    }
}
