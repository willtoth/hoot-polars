use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};
use hoot_polars::{
    DecodeOptions, HootError, HootParser, HootReader, Result, TailPolicy, canonicalize_tail,
};
use memmap2::Mmap;
use polars::io::parquet::write::{ParquetCompression, ParquetWriter};

#[derive(Debug, Parser)]
#[command(version, about = "Native CTRE Phoenix 6 HOOT decoder")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Inspect the file header, framing, and unsupported physical records.
    Info {
        input: PathBuf,
        #[arg(long, value_enum, default_value_t = TailMode::Lenient)]
        tail: TailMode,
        /// Emit one machine-readable JSON object.
        #[arg(long)]
        json: bool,
        /// Count native semantic updates and unique sparse-row timestamps.
        #[arg(long)]
        semantic_stats: bool,
    },
    /// Print the metadata-bearing native signal schema as JSON.
    Schema {
        input: PathBuf,
        #[arg(long, value_enum, default_value_t = TailMode::Lenient)]
        tail: TailMode,
    },
    /// Convert supported native signals to a sparse Parquet table.
    Convert {
        input: PathBuf,
        output: PathBuf,
        #[arg(long, default_value_t = 50_000)]
        rows_per_batch: usize,
        #[arg(long, value_enum, default_value_t = TailMode::Lenient)]
        tail: TailMode,
        /// Maximum timestamp disorder retained before emitting ordered rows.
        #[arg(long, default_value_t = 5_000_000)]
        reorder_window_us: i64,
        /// Hard ceiling for unique timestamp rows in the reorder buffer.
        #[arg(long, default_value_t = 100_000)]
        max_buffered_rows: usize,
        #[arg(long, value_enum, default_value_t = Compression::Zstd)]
        compression: Compression,
    },
    /// Write a strict derived copy by discarding an incomplete final record.
    RepairTail { input: PathBuf, output: PathBuf },
    /// Inspect exact physical records for one arbitration ID.
    Frames {
        input: PathBuf,
        /// Arbitration ID in decimal or with a 0x prefix.
        #[arg(long, value_parser = parse_u32)]
        arbitration_id: u32,
        /// Restrict to one record class.
        #[arg(long)]
        record_class: Option<u8>,
        /// Maximum distinct payload variants to print.
        #[arg(long, default_value_t = 32)]
        limit: usize,
        #[arg(long, value_enum, default_value_t = TailMode::Lenient)]
        tail: TailMode,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TailMode {
    Strict,
    Lenient,
}

impl From<TailMode> for DecodeOptions {
    fn from(value: TailMode) -> Self {
        Self {
            tail_policy: match value {
                TailMode::Strict => TailPolicy::Strict,
                TailMode::Lenient => TailPolicy::Lenient,
            },
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Compression {
    Uncompressed,
    Snappy,
    Gzip,
    Brotli,
    Zstd,
    Lz4Raw,
}

impl From<Compression> for ParquetCompression {
    fn from(value: Compression) -> Self {
        match value {
            Compression::Uncompressed => Self::Uncompressed,
            Compression::Snappy => Self::Snappy,
            Compression::Gzip => Self::Gzip(None),
            Compression::Brotli => Self::Brotli(None),
            Compression::Zstd => Self::Zstd(None),
            Compression::Lz4Raw => Self::Lz4Raw,
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    match Args::parse().command {
        Command::Info {
            input,
            tail,
            json,
            semantic_stats,
        } => info(&input, tail.into(), json, semantic_stats),
        Command::Schema { input, tail } => schema(&input, tail.into()),
        Command::Convert {
            input,
            output,
            rows_per_batch,
            tail,
            reorder_window_us,
            max_buffered_rows,
            compression,
        } => {
            let mut options: DecodeOptions = tail.into();
            options.reorder_window_us = reorder_window_us;
            options.max_buffered_rows = max_buffered_rows;
            convert(&input, &output, rows_per_batch, options, compression.into())
        }
        Command::RepairTail { input, output } => repair_tail(&input, &output),
        Command::Frames {
            input,
            arbitration_id,
            record_class,
            limit,
            tail,
        } => frames(&input, tail.into(), arbitration_id, record_class, limit),
    }
}

fn parse_u32(value: &str) -> std::result::Result<u32, String> {
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).map_err(|error| error.to_string())
    } else {
        value.parse::<u32>().map_err(|error| error.to_string())
    }
}

fn map_file(path: &Path) -> Result<(File, Mmap)> {
    let file = File::open(path)?;
    // SAFETY: the returned mapping is read-only. The tuple keeps the file
    // alive, and callers finish all borrows before either value is dropped.
    let mmap = unsafe { Mmap::map(&file)? };
    Ok((file, mmap))
}

fn info(
    input: &Path,
    options: DecodeOptions,
    json: bool,
    include_semantic_stats: bool,
) -> Result<()> {
    let (_file, mmap) = map_file(input)?;
    let reader = HootReader::with_options(&mmap, options)?;
    let report = reader.infer_schema()?;
    let semantic_stats = if include_semantic_stats {
        let mut updates = 0_u64;
        let mut rows = BTreeSet::new();
        let mut signals = BTreeSet::new();
        for update in reader.updates(&report.schema) {
            let update = update?;
            updates += 1;
            rows.insert(update.timestamp_us);
            signals.insert(update.raw_id);
        }
        Some((updates, rows.len(), signals.len()))
    } else {
        None
    };
    if json {
        let value = serde_json::json!({
            "path": input,
            "size": mmap.len(),
            "header": reader.header(),
            "report": report,
            "semantic_stats": semantic_stats.map(|(updates, rows, signals)| serde_json::json!({
                "updates": updates,
                "unique_sparse_rows": rows,
                "signals_with_updates": signals,
            })),
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("path: {}", input.display());
        println!("size: {} bytes", mmap.len());
        println!("source: {}", reader.header().source);
        println!("compliancy: {}", reader.header().compliancy);
        println!(
            "start Unix seconds: {}",
            reader.header().start_time_unix_seconds
        );
        println!("physical frames: {}", report.raw_frames);
        println!("custom frames: {}", report.custom_frames);
        println!(
            "timestamp range: {:?}..{:?} us",
            report.min_timestamp_us, report.max_timestamp_us
        );
        println!(
            "out-of-order frames: {} (maximum regression {} us)",
            report.out_of_order_frames, report.max_out_of_order_us
        );
        println!("supported columns: {}", report.schema.len());
        if let Some((updates, rows, signals)) = semantic_stats {
            println!("semantic updates: {updates}");
            println!("unique sparse rows: {rows}");
            println!("signals with updates: {signals}");
        }
        println!(
            "unsupported physical frame variants: {}",
            report.unsupported_frames.len()
        );
        for unsupported in &report.unsupported_frames {
            println!(
                "  id=0x{:08x} class={} bytes={} count={} first_decoded={} first_compressed={}",
                unsupported.arbitration_id,
                unsupported.record_class,
                unsupported.payload_len,
                unsupported.count,
                unsupported.first_decoded_offset,
                unsupported.first_compressed_byte_offset
            );
        }
        if let Some(recovery) = &report.recovered_tail {
            println!(
                "lenient tail recovery: decoded={} compressed={} available={} needed={} missing_marker={} partial_code_bits={}",
                recovery.decoded_offset,
                recovery.compressed_byte_offset,
                recovery.decoded_bytes_available,
                recovery.decoded_bytes_needed,
                recovery.missing_end_marker,
                recovery.partial_code_bits
            );
            println!(
                "repair boundary: compressed byte {} bit {} (body bit {})",
                recovery.compressed_byte_offset,
                recovery.compressed_bit,
                recovery.discard_from_body_bit
            );
        }
    }
    Ok(())
}

fn repair_tail(input: &Path, output: &Path) -> Result<()> {
    if input == output
        || (output.exists()
            && input
                .canonicalize()
                .ok()
                .zip(output.canonicalize().ok())
                .is_some_and(|(input, output)| input == output))
    {
        return Err(HootError::InvalidArgument(
            "repair output must differ from the input; originals are never overwritten".to_owned(),
        ));
    }
    if output.exists() {
        return Err(HootError::InvalidArgument(format!(
            "repair output already exists: {}",
            output.display()
        )));
    }

    let (_file, mmap) = map_file(input)?;
    let repaired = canonicalize_tail(&mmap)?;
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(&repaired.bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(output)
        .map_err(|error| std::io::Error::new(error.error.kind(), error.to_string()))?;
    println!(
        "wrote {} strict frames to {} ({} -> {} bytes, changed={})",
        repaired.report.retained_frames,
        output.display(),
        repaired.report.original_bytes,
        repaired.report.repaired_bytes,
        repaired.report.changed
    );
    Ok(())
}

fn frames(
    input: &Path,
    options: DecodeOptions,
    arbitration_id: u32,
    record_class: Option<u8>,
    limit: usize,
) -> Result<()> {
    let (_file, mmap) = map_file(input)?;
    let reader = HootReader::with_options(&mmap, options)?;
    let mut variants = BTreeMap::<(u8, Vec<u8>), (u64, i64, u64, u64, Vec<u8>)>::new();
    let mut total = 0_u64;
    for frame in reader.frames() {
        let frame = frame?;
        if frame.arbitration_id != arbitration_id
            || record_class.is_some_and(|class| frame.record_class != class)
        {
            continue;
        }
        total += 1;
        let entry = variants
            .entry((frame.record_class, frame.payload.clone()))
            .or_insert_with(|| {
                (
                    0,
                    frame.timestamp_us,
                    frame.decoded_offset,
                    frame.compressed_byte_offset,
                    frame.payload_delta.clone(),
                )
            });
        entry.0 += 1;
    }
    println!("arbitration ID: 0x{arbitration_id:08x}");
    println!("matching frames: {total}");
    println!("distinct class/payload variants: {}", variants.len());
    for ((class, payload), (count, timestamp, decoded, compressed, delta)) in
        variants.into_iter().take(limit)
    {
        println!(
            "class={class} bytes={} count={count} first_timestamp={timestamp} first_decoded={decoded} first_compressed={compressed} payload={} first_delta={}",
            payload.len(),
            hex::encode(payload),
            hex::encode(delta),
        );
    }
    Ok(())
}

fn schema(input: &Path, options: DecodeOptions) -> Result<()> {
    let (_file, mmap) = map_file(input)?;
    let reader = HootReader::with_options(&mmap, options)?;
    println!("{}", serde_json::to_string_pretty(&reader.infer_schema()?)?);
    Ok(())
}

fn convert(
    input: &Path,
    output: &Path,
    rows_per_batch: usize,
    options: DecodeOptions,
    compression: ParquetCompression,
) -> Result<()> {
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    let temporary = tempfile::NamedTempFile::new_in(parent)?;
    let output_file = temporary.as_file().try_clone()?;
    let mut writer = None;
    let mut rows = 0_usize;

    let schema =
        HootParser::process_file_batched_with_options(input, rows_per_batch, options, |batch| {
            rows += batch.height();
            if writer.is_none() {
                writer = Some(
                    ParquetWriter::new(output_file.try_clone()?)
                        .with_compression(compression)
                        .batched(batch.schema())?,
                );
            }
            writer
                .as_mut()
                .expect("writer initialized above")
                .write_batch(&batch)?;
            Ok(())
        })?;

    if writer.is_none() {
        writer = Some(
            ParquetWriter::new(output_file)
                .with_compression(compression)
                .batched(&schema)?,
        );
    }
    writer.expect("writer initialized above").finish()?;
    temporary
        .persist(output)
        .map_err(|error| std::io::Error::new(error.error.kind(), error.to_string()))?;
    println!(
        "wrote {} rows and {} columns to {}",
        rows,
        schema.len(),
        output.display()
    );
    Ok(())
}
