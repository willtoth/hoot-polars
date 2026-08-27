# Implemented HOOT format boundary

This document describes the byte layout implemented by `hoot-polars`. It is an
independent compatibility note, not an official specification. The reader
rejects unsupported versions rather than applying these rules broadly.

## File header

The compliancy-19 header is 80 bytes:

| Offset | Length | Meaning |
| ---: | ---: | --- |
| 0 | 64 | UTF-8 source or bus name, NUL padded |
| 64 | 6 | Reserved bytes, retained verbatim |
| 70 | 1 | Compliancy value; this implementation requires 19 |
| 71 | 1 | Format flags; this implementation requires 1 |
| 72 | 8 | Little-endian Unix start time in seconds |

## Entropy-coded body

Bytes after the header use a fixed prefix code with 257 symbols: every byte
value plus an end-of-stream symbol. Source bits are consumed least-significant
bit first. The longest code is 11 bits.

The decoder is streaming and checked. An invalid prefix, missing terminator, or
partial symbol produces a structured error in strict mode. Lenient mode returns
complete records and reports the exact discarded bit boundary.

## Physical records

The entropy-decoded record prefix is 10 bytes:

| Offset | Length | Meaning |
| ---: | ---: | --- |
| 0 | 4 | Little-endian record header |
| 4 | 5 | Little-endian timestamp in microseconds |
| 9 | 1 | DLC in the high nibble and flags in the low nibble |

The low 29 header bits are the arbitration identifier and the high three bits
are the record class. The public timestamp is the stored timestamp plus one
microsecond.

DLC values map to CAN/CAN-FD payload lengths as follows:

```text
0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64
```

Payload bytes are modular deltas. State is maintained independently for each
complete 32-bit record header. For every byte position:

```text
current = previous.wrapping_add(delta)
```

New state begins at zero. State storage is bounded to prevent adversarial input
from causing unbounded allocation.

## Custom signals

Record class 7 carries custom signal definitions and data. Definition records
provide the signal name and units; data records provide typed payloads. The
implemented logical families are:

- raw bytes;
- boolean;
- signed 64-bit integer;
- 32-bit and 64-bit floating point;
- UTF-8 string;
- arrays of each non-raw scalar family.

Fixed-width arrays reject trailing partial elements. String arrays use a
sequence of little-endian 32-bit lengths followed by UTF-8 bytes. Unknown type
codes and invalid UTF-8 are reported explicitly.

## Device catalog

Firmware-major-26 TalonFX definitions are selected through version records.
The catalog contains functional identifiers, bit locations, numeric scales,
units, and enum values required for decoding. It intentionally contains no
vendor-authored explanatory summaries.

Classic CAN status groups and the CAN FD bundle share definitions. Standalone
query records can reuse the most recent compatible status payload where the
wire representation requires it. Unrecognized physical records remain in the
schema report with their counts, offsets, deltas, and first reconstructed
payload.

Catalog columns use `device_<id>_<snake_case_signal>`. Custom signals retain
their embedded names.

## Tail handling and repair

Strict mode requires a complete final record and end marker. Lenient mode
retains all complete records and exposes the location of a partial tail.

`canonicalize_tail` and the `repair-tail` CLI command create a separate output:

1. decode and count every complete record;
2. discard only the incomplete final record or prefix;
3. append the canonical end marker;
4. decode the result strictly and verify the retained record count.

The original input is never modified.

## Resource and safety limits

- Every offset and payload length is checked before slicing.
- Timestamp conversion checks overflow.
- Payload-state and reorder-buffer growth are bounded.
- File conversion writes through a temporary file.
- Property tests exercise arbitrary short headers and entropy bodies.
