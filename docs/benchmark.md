# Benchmarking

Benchmarks use a maintainer-authorized local `.hoot` input. Do not commit robot
logs, converted outputs, absolute paths, file hashes, or identifying telemetry.

Build an optimized binary:

```powershell
cargo build --release
```

Measure a schema and framing scan:

```powershell
Measure-Command {
  target\release\hoot-polars.exe info C:\path\to\authorized-log.hoot --semantic-stats
}
```

Measure bounded Parquet conversion:

```powershell
Measure-Command {
  target\release\hoot-polars.exe convert `
    C:\path\to\authorized-log.hoot `
    target\benchmark.parquet `
    --rows-per-batch 50000
}
```

Record the following without identifying the input:

- build profile and Rust version;
- CPU, available memory, and operating system;
- input size rounded to an appropriate range;
- physical frame, semantic update, row, and column counts;
- wall-clock time and peak resident memory;
- batch size, reorder window, and compression settings.

Benchmark output belongs under `target/` and must not be committed.
