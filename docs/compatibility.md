# Compatibility

This document describes the decoder boundary implemented by the current
source. It is not an official vendor specification.

| Area | Supported boundary |
| --- | --- |
| HOOT compliancy | 19 |
| Header flags | 1 |
| Custom signals | Scalar and array families represented by `SignalType` |
| Device catalog | TalonFX, firmware major 26 |
| Transport | Classic CAN and CAN FD |
| Tail handling | Strict validation, lenient recovery, and canonical repair |
| Output | Sparse Polars DataFrame and Parquet |

## Version selection

The semantic catalog is enabled only after a device version record has been
observed. Devices with an unsupported firmware major, conflicting version
evidence, or unrecognized record layout remain visible in the schema report but
are not assigned potentially incorrect semantics.

## Column contract

The first column is `timestamp`, stored as signed microseconds. Catalog signals
use deterministic names of the form:

```text
device_<id>_<signal>
```

For example, device 1 motor voltage is `device_1_motor_voltage`. Custom logged
signals retain their embedded names. The schema rejects duplicate names and
the reserved custom name `timestamp`.

Rows are sparse: each unique timestamp appears once, and a signal that did not
update at that timestamp is null. No forward fill is performed.

## Validation levels

The repository uses two test levels:

1. Hermetic unit, property, and synthetic-fixture tests run on every build.
2. An ignored local test reads a user-authorized `.hoot` file supplied through
   `HOOT_TEST_INPUT` without committing that file or identifying information.

When an authorized `.hoot` and corresponding `.wpilog` pair is available,
maintainers may perform an ephemeral comparison outside the repository. Such
inputs, outputs, generated scripts, paths, hashes, and results are not release
artifacts.

## Known limits

- Compliancy values other than 19 are rejected.
- Firmware catalogs other than major version 26 are not included.
- Physical records without a selected semantic definition are reported rather
  than silently assigned a meaning.
- Class-7 subtypes outside the implemented data, name, and units layouts are
  reported as unsupported physical records.
- Exact handling of new device families or future record groups requires new,
  independently authored definitions and synthetic coverage.
