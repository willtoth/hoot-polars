//! Versioned Phoenix CAN semantic catalog.
//!
//! The Phoenix-26 TalonFX catalog is selected only after a version-frame
//! discovery pass. This prevents transmit/query traffic and old devices from
//! being mislabeled as decoded status streams. CAN FD's 64-byte timesync
//! frame concatenates classic status groups, so both transports share field
//! definitions.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{HootError, Result};
use crate::framing::RawFrame;
use crate::header::HootHeader;
use crate::model::{
    DecodedUpdate, FrameKey, HootSchema, PhoenixDeviceInfo, PhoenixTransport, SignalInfo,
    SignalSource, SignalSupport, SignalType, SignalValue,
};

const DEVICE_ID_MASK: u32 = 0x3f;
const FRAME_BASE_MASK: u32 = !DEVICE_ID_MASK;

const TALON_FD_BUNDLE_BASE: u32 = 0x0204_2b40;
const TALON_MOTOR_OUTPUT_BASE: u32 = 0x0204_2c40;
const TALON_SUPPLY_TEMP_BASE: u32 = 0x0204_2d40;
const TALON_ROTOR_BASE: u32 = 0x0204_2d80;
const TALON_MOTION_BASE: u32 = 0x0204_2dc0;
const TALON_PID_STATE_BASE: u32 = 0x0204_2e00;
const TALON_PID_REF_ERROR_BASE: u32 = 0x0204_2e40;
const TALON_PID_OUTPUT_BASE: u32 = 0x0204_2e80;
const TALON_PID_SLOPE_BASE: u32 = 0x0204_2ec0;
const TALON_MOTOR_CONSTANTS_BASE: u32 = 0x0204_3040;
const TALON_FAULTS_BASE: u32 = 0x0204_4740;
const TALON_VERSION_BASE: u32 = 0x0204_6bc0;

const TIMESTAMP_SYNTHETIC_BASE: u32 = 0xfe00_0000;
const RESET_COUNT_SYNTHETIC_BASE: u32 = 0xfe00_0001;
const SUPPORTED_FIRMWARE_MAJOR: u8 = 26;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FrameGroup {
    MotorOutput,
    SupplyTemp,
    Rotor,
    Motion,
    PidState,
    PidRefError,
    PidOutput,
    PidSlope,
    MotorConstants,
    Faults,
    Version,
    FdBundle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CatalogFrame {
    group: FrameGroup,
    device_id: u8,
    firmware_full: u32,
    is_pro_licensed: bool,
}

#[derive(Debug, Default)]
pub(crate) struct CatalogSelection {
    devices: Vec<PhoenixDeviceInfo>,
    frames: BTreeSet<FrameKey>,
}

#[derive(Debug, Default)]
pub(crate) struct CatalogDecoder {
    cached_standalone: BTreeMap<(u8, FrameGroup), u64>,
}

#[derive(Debug, Clone, Copy)]
struct VersionObservation {
    firmware_full: u32,
    is_pro_licensed: bool,
}

/// Incremental evidence used to select the versioned Phoenix catalog after a
/// single physical-frame traversal.
#[derive(Debug, Default)]
pub(crate) struct CatalogDiscovery {
    versions: BTreeMap<(u8, u8), VersionObservation>,
    version_conflicts: BTreeSet<(u8, u8)>,
    version_variants: BTreeSet<(u8, u8)>,
    classic_devices: BTreeSet<u8>,
    fd_devices: BTreeSet<u8>,
    observed_status_frames: BTreeSet<FrameKey>,
}

impl CatalogDiscovery {
    pub(crate) fn observe(&mut self, frame: &RawFrame) {
        let base = frame.arbitration_id & FRAME_BASE_MASK;
        let device_id = (frame.arbitration_id & DEVICE_ID_MASK) as u8;
        if base == TALON_VERSION_BASE
            && matches!(frame.record_class, 1 | 3)
            && frame.payload.len() == 6
        {
            self.version_variants
                .insert((device_id, frame.record_class));
            let firmware_full =
                u32::from_le_bytes(frame.payload[..4].try_into().expect("length checked"));
            if firmware_full != 0 {
                let key = (device_id, frame.record_class);
                let observation = VersionObservation {
                    firmware_full,
                    is_pro_licensed: frame.payload[5] & 0x80 != 0,
                };
                if let Some(previous) = self.versions.get_mut(&key) {
                    if previous.firmware_full.to_le_bytes()[3]
                        != observation.firmware_full.to_le_bytes()[3]
                    {
                        self.version_conflicts.insert(key);
                        if observation.firmware_full < previous.firmware_full {
                            *previous = observation;
                        }
                    } else {
                        if observation.firmware_full > previous.firmware_full {
                            previous.firmware_full = observation.firmware_full;
                        }
                        previous.is_pro_licensed |= observation.is_pro_licensed;
                    }
                } else {
                    self.versions.insert(key, observation);
                }
            }
        }
        if matches!(frame.record_class, 1 | 3)
            && frame.payload.len() == 8
            && is_standalone_status_base(base)
        {
            self.observed_status_frames.insert(FrameKey {
                arbitration_id: frame.arbitration_id,
                record_class: frame.record_class,
                payload_len: frame.payload.len(),
            });
        }
        if frame.record_class == 1 && frame.payload.len() == 8 && is_timesync_group_base(base) {
            self.classic_devices.insert(device_id);
        }
        if frame.record_class == 3 && frame.payload.len() == 64 && base == TALON_FD_BUNDLE_BASE {
            self.fd_devices.insert(device_id);
        }
    }

    pub(crate) fn finish(self) -> CatalogSelection {
        let all_devices = self
            .classic_devices
            .union(&self.fd_devices)
            .copied()
            .collect::<BTreeSet<_>>();
        let mut selection = CatalogSelection::default();
        for device_id in all_devices {
            let (transport, record_class, version) = if self.fd_devices.contains(&device_id) {
                match self.versions.get(&(device_id, 3)) {
                    Some(version) => (PhoenixTransport::CanFd, 3, *version),
                    None => continue,
                }
            } else {
                match self.versions.get(&(device_id, 1)) {
                    Some(version) => (PhoenixTransport::Can2, 1, *version),
                    None => continue,
                }
            };
            let bytes = version.firmware_full.to_le_bytes();
            let version_conflict = self.version_conflicts.contains(&(device_id, record_class));
            let supported = bytes[3] == SUPPORTED_FIRMWARE_MAJOR && !version_conflict;
            selection.devices.push(PhoenixDeviceInfo {
                device_type: "TalonFX".to_owned(),
                device_id,
                firmware_major: bytes[3],
                firmware_minor: bytes[2],
                firmware_bugfix: bytes[1],
                firmware_build: bytes[0],
                firmware_full: version.firmware_full,
                is_pro_licensed: version.is_pro_licensed,
                transport,
                version_conflict,
                catalog_supported: supported,
            });
            if !supported {
                continue;
            }

            let id = u32::from(device_id);
            selection.frames.extend(
                self.observed_status_frames
                    .iter()
                    .copied()
                    .filter(|key| key.arbitration_id & DEVICE_ID_MASK == id),
            );
            if transport == PhoenixTransport::CanFd {
                selection.frames.insert(FrameKey {
                    arbitration_id: TALON_FD_BUNDLE_BASE | id,
                    record_class,
                    payload_len: 64,
                });
            }
            selection.frames.insert(FrameKey {
                arbitration_id: TALON_VERSION_BASE | id,
                record_class,
                payload_len: 6,
            });
            if transport == PhoenixTransport::CanFd
                && self.version_variants.contains(&(device_id, 1))
            {
                selection.frames.insert(FrameKey {
                    arbitration_id: TALON_VERSION_BASE | id,
                    record_class: 1,
                    payload_len: 6,
                });
            }
        }
        selection
    }
}

#[derive(Debug, Clone, Copy)]
enum Encoding {
    Signed {
        shift: u8,
        width: u8,
        scale: f64,
        bias: f64,
    },
    Unsigned {
        shift: u8,
        width: u8,
        scale: f64,
        bias: f64,
    },
    Float32 {
        shift: u8,
        stored_width: u8,
    },
    Text(TextEncoding),
}

#[derive(Debug, Clone, Copy)]
enum TextEncoding {
    ForwardLimit,
    ReverseLimit,
    AppliedRotorPolarity,
    BridgeOutput,
    ControlMode,
    RobotEnable,
    DeviceEnable,
    ConnectedMotor,
    MotorOutputStatus,
}

#[derive(Debug, Clone, Copy)]
struct SignalDef {
    spn: u32,
    leaf: &'static str,
    units: &'static str,
    encoding: Encoding,
}

const MOTOR_OUTPUT: &[SignalDef] = &[
    double_def(1772, "MotorVoltage", "V", signed(2, 13, 0.01)),
    text_def(1773, "ForwardLimit", TextEncoding::ForwardLimit),
    text_def(1774, "ReverseLimit", TextEncoding::ReverseLimit),
    text_def(
        1775,
        "AppliedRotorPolarity",
        TextEncoding::AppliedRotorPolarity,
    ),
    double_def(
        1776,
        "DutyCycle",
        "fractional",
        signed(32, 12, 1.0 / 1024.0),
    ),
    double_def(1778, "TorqueCurrent", "A", signed(48, 16, 0.01)),
    text_def(1963, "BridgeOutput", TextEncoding::BridgeOutput),
];

const SUPPLY_TEMP: &[SignalDef] = &[
    double_def(1779, "StatorCurrent", "A", signed(0, 15, 0.02)),
    double_def(1780, "SupplyCurrent", "A", signed(15, 15, 0.02)),
    double_def(
        1781,
        "SupplyVoltage",
        "V",
        unsigned_with_bias(30, 10, 0.025, 4.0),
    ),
    double_def(1782, "DeviceTemp", "℃", unsigned(40, 8, 1.0)),
    double_def(1783, "ProcessorTemp", "℃", unsigned(48, 8, 1.0)),
    double_def(2091, "AncillaryDeviceTemp", "℃", unsigned(56, 8, 1.0)),
];

const ROTOR: &[SignalDef] = &[
    double_def(
        1785,
        "RotorVelocity",
        "rotations per second",
        signed(2, 19, 1.0 / 512.0),
    ),
    double_def(
        1786,
        "RotorPosition",
        "rotations",
        signed(21, 27, 1.0 / 4096.0),
    ),
];

const MOTION: &[SignalDef] = &[
    double_def(
        1789,
        "Velocity",
        "rotations per second",
        signed(2, 19, 1.0 / 512.0),
    ),
    double_def(1790, "Position", "rotations", signed(21, 27, 1.0 / 4096.0)),
    double_def(
        1791,
        "Acceleration",
        "rotations per second²",
        signed(48, 14, 0.25),
    ),
];

const PID_STATE: &[SignalDef] = &[
    double_def(
        1793,
        "PIDDutyCycle_IntegratedAccum",
        "fractional",
        signed(0, 18, 1.0 / 1024.0),
    ),
    double_def(
        1794,
        "PIDMotorVoltage_IntegratedAccum",
        "V",
        signed(0, 18, 0.01),
    ),
    double_def(
        1795,
        "PIDTorqueCurrent_IntegratedAccum",
        "A",
        signed(0, 18, 0.1),
    ),
    double_def(
        1796,
        "PIDDutyCycle_FeedForward",
        "fractional",
        signed(18, 12, 1.0 / 1024.0),
    ),
    double_def(
        1797,
        "PIDMotorVoltage_FeedForward",
        "V",
        signed(18, 12, 0.02),
    ),
    double_def(
        1798,
        "PIDTorqueCurrent_FeedForward",
        "A",
        signed(18, 12, 0.2),
    ),
    text_def(1799, "ControlMode", TextEncoding::ControlMode),
    double_def(1805, "MotionMagicAtTarget", "", unsigned(59, 1, 1.0)),
    double_def(1806, "MotionMagicIsRunning", "", unsigned(60, 1, 1.0)),
    text_def(1807, "RobotEnable", TextEncoding::RobotEnable),
    text_def(1808, "DeviceEnable", TextEncoding::DeviceEnable),
];

const PID_REF_ERROR: &[SignalDef] = &[
    double_def(1810, "PIDPosition_Reference", "rotations", float32(0, 32)),
    double_def(
        1811,
        "PIDVelocity_Reference",
        "rotations per second",
        float32(0, 32),
    ),
    double_def(
        1812,
        "PIDPosition_ClosedLoopError",
        "rotations",
        float32(32, 31),
    ),
    double_def(
        1813,
        "PIDVelocity_ClosedLoopError",
        "rotations per second",
        float32(32, 31),
    ),
];

const PID_OUTPUT: &[SignalDef] = &[
    double_def(
        1817,
        "PIDDutyCycle_ProportionalOutput",
        "fractional",
        signed(8, 18, 1.0 / 1024.0),
    ),
    double_def(
        1818,
        "PIDMotorVoltage_ProportionalOutput",
        "V",
        signed(8, 18, 0.01),
    ),
    double_def(
        1819,
        "PIDTorqueCurrent_ProportionalOutput",
        "A",
        signed(8, 18, 0.1),
    ),
    double_def(
        1820,
        "PIDDutyCycle_DerivativeOutput",
        "fractional",
        signed(26, 18, 1.0 / 1024.0),
    ),
    double_def(
        1821,
        "PIDMotorVoltage_DerivativeOutput",
        "V",
        signed(26, 18, 0.01),
    ),
    double_def(
        1822,
        "PIDTorqueCurrent_DerivativeOutput",
        "A",
        signed(26, 18, 0.1),
    ),
    double_def(
        1823,
        "PIDDutyCycle_Output",
        "fractional",
        signed(44, 18, 1.0 / 1024.0),
    ),
    double_def(1824, "PIDMotorVoltage_Output", "V", signed(44, 18, 0.01)),
    double_def(1825, "PIDTorqueCurrent_Output", "A", signed(44, 18, 0.1)),
    double_def(1826, "ClosedLoopSlot", "", unsigned(62, 2, 1.0)),
    text_def(2117, "ConnectedMotor", TextEncoding::ConnectedMotor),
];

const PID_SLOPE: &[SignalDef] = &[
    double_def(
        1827,
        "PIDPosition_ReferenceSlope",
        "rotations per second",
        signed(0, 16, 1.0 / 64.0),
    ),
    double_def(
        1828,
        "PIDVelocity_ReferenceSlope",
        "rotations per second²",
        signed(0, 16, 1.0 / 64.0),
    ),
    text_def(1830, "MotorOutputStatus", TextEncoding::MotorOutputStatus),
];

const MOTOR_CONSTANTS: &[SignalDef] = &[
    double_def(1874, "MotorKT", "Nm/A", unsigned(2, 8, 0.0001)),
    double_def(1875, "MotorKV", "RPM/V", unsigned(10, 11, 1.0)),
    double_def(1876, "MotorStallCurrent", "A", unsigned(21, 10, 1.0)),
];

const FAULTS: &[SignalDef] = &[
    double_def(844, "FaultField", "", unsigned(0, 32, 1.0)),
    double_def(845, "StickyFaultField", "", unsigned(32, 32, 1.0)),
    fault_def(0x2711, "Fault_Hardware", 0),
    fault_def(0x2712, "StickyFault_Hardware", 32),
    fault_def(0x2714, "Fault_ProcTemp", 1),
    fault_def(0x2715, "StickyFault_ProcTemp", 33),
    fault_def(0x2717, "Fault_DeviceTemp", 2),
    fault_def(0x2718, "StickyFault_DeviceTemp", 34),
    fault_def(0x271a, "Fault_Undervoltage", 3),
    fault_def(0x271b, "StickyFault_Undervoltage", 35),
    fault_def(0x271d, "Fault_BootDuringEnable", 4),
    fault_def(0x271e, "StickyFault_BootDuringEnable", 36),
    fault_def(0x2720, "Fault_UnlicensedFeatureInUse", 5),
    fault_def(0x2721, "StickyFault_UnlicensedFeatureInUse", 37),
    fault_def(0x2741, "Fault_BridgeBrownout", 23),
    fault_def(0x2742, "StickyFault_BridgeBrownout", 55),
    fault_def(0x2744, "Fault_RemoteSensorReset", 22),
    fault_def(0x2745, "StickyFault_RemoteSensorReset", 54),
    fault_def(0x2747, "Fault_MissingDifferentialFX", 21),
    fault_def(0x2748, "StickyFault_MissingDifferentialFX", 53),
    fault_def(0x274a, "Fault_RemoteSensorPosOverflow", 20),
    fault_def(0x274b, "StickyFault_RemoteSensorPosOverflow", 52),
    fault_def(0x274d, "Fault_OverSupplyV", 19),
    fault_def(0x274e, "StickyFault_OverSupplyV", 51),
    fault_def(0x2750, "Fault_UnstableSupplyV", 18),
    fault_def(0x2751, "StickyFault_UnstableSupplyV", 50),
    fault_def(0x2753, "Fault_ReverseHardLimit", 17),
    fault_def(0x2754, "StickyFault_ReverseHardLimit", 49),
    fault_def(0x2756, "Fault_ForwardHardLimit", 16),
    fault_def(0x2757, "StickyFault_ForwardHardLimit", 48),
    fault_def(0x2759, "Fault_ReverseSoftLimit", 15),
    fault_def(0x275a, "StickyFault_ReverseSoftLimit", 47),
    fault_def(0x275c, "Fault_ForwardSoftLimit", 14),
    fault_def(0x275d, "StickyFault_ForwardSoftLimit", 46),
    fault_def(0x275f, "Fault_MissingSoftLimitRemote", 13),
    fault_def(0x2760, "StickyFault_MissingSoftLimitRemote", 45),
    fault_def(0x2762, "Fault_MissingHardLimitRemote", 12),
    fault_def(0x2763, "StickyFault_MissingHardLimitRemote", 44),
    fault_def(0x2765, "Fault_RemoteSensorDataInvalid", 11),
    fault_def(0x2766, "StickyFault_RemoteSensorDataInvalid", 43),
    fault_def(0x2768, "Fault_FusedSensorOutOfSync", 10),
    fault_def(0x2769, "StickyFault_FusedSensorOutOfSync", 42),
    fault_def(0x276b, "Fault_StatorCurrLimit", 9),
    fault_def(0x276c, "StickyFault_StatorCurrLimit", 41),
    fault_def(0x276e, "Fault_SupplyCurrLimit", 8),
    fault_def(0x276f, "StickyFault_SupplyCurrLimit", 40),
    fault_def(0x2771, "Fault_UsingFusedCANcoderWhileUnlicensed", 7),
    fault_def(0x2772, "StickyFault_UsingFusedCANcoderWhileUnlicensed", 39),
    fault_def(0x2774, "Fault_StaticBrakeDisabled", 6),
    fault_def(0x2775, "StickyFault_StaticBrakeDisabled", 38),
    fault_def(0x27a1, "Fault_RotorFault1", 25),
    fault_def(0x27a2, "StickyFault_RotorFault1", 57),
    fault_def(0x27a4, "Fault_RotorFault2", 26),
    fault_def(0x27a5, "StickyFault_RotorFault2", 58),
];

const VERSION: &[SignalDef] = &[
    double_def(734, "VersionMajor", "", unsigned(24, 8, 1.0)),
    double_def(735, "VersionMinor", "", unsigned(16, 8, 1.0)),
    double_def(736, "VersionBugfix", "", unsigned(8, 8, 1.0)),
    double_def(737, "VersionBuild", "", unsigned(0, 8, 1.0)),
    double_def(738, "Version", "", unsigned(0, 32, 1.0)),
    double_def(2052, "IsProLicensed", "", unsigned(47, 1, 1.0)),
];

const fn signed(shift: u8, width: u8, scale: f64) -> Encoding {
    Encoding::Signed {
        shift,
        width,
        scale,
        bias: 0.0,
    }
}

const fn unsigned(shift: u8, width: u8, scale: f64) -> Encoding {
    unsigned_with_bias(shift, width, scale, 0.0)
}

const fn unsigned_with_bias(shift: u8, width: u8, scale: f64, bias: f64) -> Encoding {
    Encoding::Unsigned {
        shift,
        width,
        scale,
        bias,
    }
}

const fn float32(shift: u8, stored_width: u8) -> Encoding {
    Encoding::Float32 {
        shift,
        stored_width,
    }
}

const fn double_def(
    spn: u32,
    leaf: &'static str,
    units: &'static str,
    encoding: Encoding,
) -> SignalDef {
    SignalDef {
        spn,
        leaf,
        units,
        encoding,
    }
}

const fn fault_def(spn: u32, leaf: &'static str, shift: u8) -> SignalDef {
    double_def(spn, leaf, "", unsigned(shift, 1, 1.0))
}

const fn text_def(spn: u32, leaf: &'static str, encoding: TextEncoding) -> SignalDef {
    SignalDef {
        spn,
        leaf,
        units: "",
        encoding: Encoding::Text(encoding),
    }
}

#[cfg(test)]
pub(crate) fn discover<I>(frames: I) -> Result<CatalogSelection>
where
    I: IntoIterator<Item = Result<RawFrame>>,
{
    let mut discovery = CatalogDiscovery::default();
    for frame in frames {
        let frame = frame?;
        discovery.observe(&frame);
    }
    Ok(discovery.finish())
}

fn is_timesync_group_base(base: u32) -> bool {
    matches!(
        base,
        TALON_MOTOR_OUTPUT_BASE
            | TALON_SUPPLY_TEMP_BASE
            | TALON_ROTOR_BASE
            | TALON_MOTION_BASE
            | TALON_PID_STATE_BASE
            | TALON_PID_REF_ERROR_BASE
            | TALON_PID_OUTPUT_BASE
            | TALON_PID_SLOPE_BASE
    )
}

fn is_standalone_status_base(base: u32) -> bool {
    is_timesync_group_base(base) || matches!(base, TALON_MOTOR_CONSTANTS_BASE | TALON_FAULTS_BASE)
}

pub(crate) fn apply_selection(schema: &mut HootSchema, selection: CatalogSelection) {
    for device in selection.devices {
        schema.insert_device(device);
    }
    for frame in selection.frames {
        schema.enable_frame(frame);
    }
}

pub(crate) fn classify(frame: &RawFrame, schema: &HootSchema) -> Option<CatalogFrame> {
    let key = FrameKey {
        arbitration_id: frame.arbitration_id,
        record_class: frame.record_class,
        payload_len: frame.payload.len(),
    };
    classify_key(key, schema)
}

pub(crate) fn classify_key(key: FrameKey, schema: &HootSchema) -> Option<CatalogFrame> {
    if !schema.frame_enabled(key) {
        return None;
    }
    let device_id = (key.arbitration_id & DEVICE_ID_MASK) as u8;
    let group = match key.arbitration_id & FRAME_BASE_MASK {
        TALON_FD_BUNDLE_BASE => FrameGroup::FdBundle,
        TALON_MOTOR_OUTPUT_BASE => FrameGroup::MotorOutput,
        TALON_SUPPLY_TEMP_BASE => FrameGroup::SupplyTemp,
        TALON_ROTOR_BASE => FrameGroup::Rotor,
        TALON_MOTION_BASE => FrameGroup::Motion,
        TALON_PID_STATE_BASE => FrameGroup::PidState,
        TALON_PID_REF_ERROR_BASE => FrameGroup::PidRefError,
        TALON_PID_OUTPUT_BASE => FrameGroup::PidOutput,
        TALON_PID_SLOPE_BASE => FrameGroup::PidSlope,
        TALON_MOTOR_CONSTANTS_BASE => FrameGroup::MotorConstants,
        TALON_FAULTS_BASE => FrameGroup::Faults,
        TALON_VERSION_BASE => FrameGroup::Version,
        _ => return None,
    };
    let device = schema.device(device_id)?;
    Some(CatalogFrame {
        group,
        device_id,
        firmware_full: device.firmware_full,
        is_pro_licensed: device.is_pro_licensed,
    })
}

pub(crate) fn add_schema(
    header: &HootHeader,
    definition_decoded_offset: u64,
    kind: CatalogFrame,
    schema: &mut HootSchema,
) {
    add_device_bookkeeping(header, definition_decoded_offset, kind.device_id, schema);
    for definitions in definitions(kind.group) {
        for definition in *definitions {
            insert_if_absent(
                schema,
                signal_info(
                    header,
                    definition_decoded_offset,
                    kind.device_id,
                    definition,
                ),
            );
        }
    }
}

impl CatalogDecoder {
    pub(crate) fn decode_frame_into(
        &mut self,
        frame: &RawFrame,
        kind: CatalogFrame,
        updates: &mut std::collections::VecDeque<DecodedUpdate>,
    ) -> Result<()> {
        let expected = match kind.group {
            FrameGroup::Version => 6,
            FrameGroup::FdBundle => 64,
            _ => 8,
        };
        if frame.payload.len() != expected {
            return Err(HootError::InvalidCanPayload {
                decoded_offset: frame.decoded_offset,
                arbitration_id: frame.arbitration_id,
                expected,
                actual: frame.payload.len(),
            });
        }

        let groups: &[(FrameGroup, usize)] = match kind.group {
            FrameGroup::FdBundle => &[
                (FrameGroup::MotorOutput, 0),
                (FrameGroup::SupplyTemp, 8),
                (FrameGroup::Rotor, 16),
                (FrameGroup::Motion, 24),
                (FrameGroup::PidState, 32),
                (FrameGroup::PidRefError, 40),
                (FrameGroup::PidOutput, 48),
                (FrameGroup::PidSlope, 56),
            ],
            group => &[(group, 0)],
        };
        for (group, offset) in groups {
            let available = frame.payload.len() - *offset;
            let width = available.min(8);
            let mut bytes = [0_u8; 8];
            bytes[..width].copy_from_slice(&frame.payload[*offset..*offset + width]);
            let mut packed = u64::from_le_bytes(bytes);
            if *offset == 0 && matches!(group, FrameGroup::MotorConstants | FrameGroup::Faults) {
                let key = (kind.device_id, *group);
                if frame.record_class == 3 {
                    self.cached_standalone.insert(key, packed);
                } else if frame.record_class == 1
                    && packed == 0
                    && let Some(cached) = self.cached_standalone.get(&key)
                {
                    packed = *cached;
                }
            }
            if *group == FrameGroup::Version && packed & u64::from(u32::MAX) == 0 {
                packed = u64::from(kind.firmware_full)
                    | if kind.is_pro_licensed { 1_u64 << 47 } else { 0 };
            }
            for definitions in definitions(*group) {
                for definition in *definitions {
                    updates.push_back(update(
                        frame,
                        phoenix_raw_id(definition.spn, kind.device_id),
                        decode_value(definition.encoding, packed),
                    ));
                }
            }
        }
        updates.push_back(update(
            frame,
            timestamp_raw_id(kind.device_id),
            SignalValue::Float64(frame.timestamp_us as f64 / 1_000_000.0),
        ));
        Ok(())
    }
}

pub(crate) fn reset_update(frame: &RawFrame, device_id: u8) -> DecodedUpdate {
    update(frame, reset_count_raw_id(device_id), SignalValue::Int64(0))
}

impl CatalogFrame {
    pub(crate) fn device_id(self) -> u8 {
        self.device_id
    }
}

fn definitions(group: FrameGroup) -> &'static [&'static [SignalDef]] {
    match group {
        FrameGroup::MotorOutput => &[MOTOR_OUTPUT],
        FrameGroup::SupplyTemp => &[SUPPLY_TEMP],
        FrameGroup::Rotor => &[ROTOR],
        FrameGroup::Motion => &[MOTION],
        FrameGroup::PidState => &[PID_STATE],
        FrameGroup::PidRefError => &[PID_REF_ERROR],
        FrameGroup::PidOutput => &[PID_OUTPUT],
        FrameGroup::PidSlope => &[PID_SLOPE],
        FrameGroup::MotorConstants => &[MOTOR_CONSTANTS],
        FrameGroup::Faults => &[FAULTS],
        FrameGroup::Version => &[VERSION],
        FrameGroup::FdBundle => &[
            MOTOR_OUTPUT,
            SUPPLY_TEMP,
            ROTOR,
            MOTION,
            PID_STATE,
            PID_REF_ERROR,
            PID_OUTPUT,
            PID_SLOPE,
        ],
    }
}

fn signal_info(
    header: &HootHeader,
    definition_decoded_offset: u64,
    device_id: u8,
    definition: &SignalDef,
) -> SignalInfo {
    let signal_type = if matches!(definition.encoding, Encoding::Text(_)) {
        SignalType::String
    } else {
        SignalType::Float64
    };
    SignalInfo {
        raw_id: phoenix_raw_id(definition.spn, device_id),
        name: signal_name(device_id, definition.leaf),
        signal_type,
        original_type: signal_type.original_type(),
        units: definition.units.to_owned(),
        metadata: "{}".to_owned(),
        source: SignalSource::PhoenixCan,
        support: SignalSupport::Full,
        bus: header.source.clone(),
        device: Some(format!("TalonFX-{device_id}")),
        definition_decoded_offset,
    }
}

fn decode_value(encoding: Encoding, packed: u64) -> SignalValue {
    match encoding {
        Encoding::Signed {
            shift,
            width,
            scale,
            bias,
        } => SignalValue::Float64(
            sign_extend(extract(packed, shift, width), u32::from(width)) as f64 * scale + bias,
        ),
        Encoding::Unsigned {
            shift,
            width,
            scale,
            bias,
        } => SignalValue::Float64(extract(packed, shift, width) as f64 * scale + bias),
        Encoding::Float32 {
            shift,
            stored_width,
        } => {
            let bits = extract(packed, shift, stored_width) << (32 - stored_width);
            SignalValue::Float64(f64::from(f32::from_bits(bits as u32)))
        }
        Encoding::Text(encoding) => SignalValue::String(decode_text(encoding, packed).to_owned()),
    }
}

fn extract(value: u64, shift: u8, width: u8) -> u64 {
    let mask = if width == 64 {
        u64::MAX
    } else {
        (1_u64 << width) - 1
    };
    (value >> shift) & mask
}

fn bridge_output(value: u8) -> &'static str {
    match value {
        0 => "BridgeReq_Coast",
        1 => "BridgeReq_Brake",
        6 => "BridgeReq_Trapez",
        7 => "BridgeReq_FOCTorque",
        8 => "BridgeReq_MusicTone",
        9 => "BridgeReq_FOCEasy",
        12 => "BridgeReq_FaultBrake",
        13 => "BridgeReq_FaultCoast",
        14 => "BridgeReq_ActiveBrake",
        15 => "BridgeReq_VariableBrake",
        _ => "BridgeReq_Coast",
    }
}

fn decode_text(encoding: TextEncoding, packed: u64) -> &'static str {
    match encoding {
        // Limit inputs are active-low on the status wire, while the public
        // enum assigns Open=1 and ClosedToGround=0.
        TextEncoding::ForwardLimit => limit_value(extract(packed, 0, 1) == 0),
        TextEncoding::ReverseLimit => limit_value(extract(packed, 1, 1) == 0),
        TextEncoding::AppliedRotorPolarity => rotor_polarity(extract(packed, 31, 1) as u8),
        TextEncoding::BridgeOutput => bridge_output(extract(packed, 44, 4) as u8),
        TextEncoding::ControlMode => control_mode(extract(packed, 30, 6) as u8),
        TextEncoding::RobotEnable => enabled_value(extract(packed, 61, 1) != 0),
        TextEncoding::DeviceEnable => enabled_value(extract(packed, 62, 1) != 0),
        TextEncoding::ConnectedMotor => connected_motor(extract(packed, 2, 4) as u8),
        TextEncoding::MotorOutputStatus => motor_output_status(extract(packed, 17, 3) as u8),
    }
}

fn limit_value(open: bool) -> &'static str {
    if open { "Open" } else { "ClosedToGround" }
}

fn rotor_polarity(value: u8) -> &'static str {
    match value {
        1 => "PositiveIsClockwise",
        _ => "PositiveIsCounterClockwise",
    }
}

fn enabled_value(enabled: bool) -> &'static str {
    if enabled { "Enabled" } else { "Disabled" }
}

fn control_mode(value: u8) -> &'static str {
    const VALUES: &[&str] = &[
        "DisabledOutput",
        "NeutralOut",
        "StaticBrake",
        "DutyCycleOut",
        "PositionDutyCycle",
        "VelocityDutyCycle",
        "MotionMagicDutyCycle",
        "DutyCycleFOC",
        "PositionDutyCycleFOC",
        "VelocityDutyCycleFOC",
        "MotionMagicDutyCycleFOC",
        "VoltageOut",
        "PositionVoltage",
        "VelocityVoltage",
        "MotionMagicVoltage",
        "VoltageFOC",
        "PositionVoltageFOC",
        "VelocityVoltageFOC",
        "MotionMagicVoltageFOC",
        "TorqueCurrentFOC",
        "PositionTorqueCurrentFOC",
        "VelocityTorqueCurrentFOC",
        "MotionMagicTorqueCurrentFOC",
        "Follower",
        "Reserved",
        "CoastOut",
        "UnauthorizedDevice",
        "MusicTone",
        "MotionMagicVelocityDutyCycle",
        "MotionMagicVelocityDutyCycleFOC",
        "MotionMagicVelocityVoltage",
        "MotionMagicVelocityVoltageFOC",
        "MotionMagicVelocityTorqueCurrentFOC",
        "MotionMagicExpoDutyCycle",
        "MotionMagicExpoDutyCycleFOC",
        "MotionMagicExpoVoltage",
        "MotionMagicExpoVoltageFOC",
        "MotionMagicExpoTorqueCurrentFOC",
    ];
    VALUES.get(usize::from(value)).copied().unwrap_or(VALUES[0])
}

fn connected_motor(value: u8) -> &'static str {
    const VALUES: &[&str] = &[
        "Unknown",
        "Falcon500_Integrated",
        "KrakenX60_Integrated",
        "KrakenX44_Integrated",
        "Minion_JST",
        "Brushed_AB",
        "Brushed_AC",
        "Brushed_BC",
        "NEO_JST",
        "NEO550_JST",
        "VORTEX_JST",
        "CustomBrushless",
    ];
    VALUES.get(usize::from(value)).copied().unwrap_or(VALUES[0])
}

fn motor_output_status(value: u8) -> &'static str {
    const VALUES: &[&str] = &[
        "Unknown",
        "Off",
        "StaticBraking",
        "Motoring",
        "DiscordantMotoring",
        "RegenBraking",
    ];
    VALUES.get(usize::from(value)).copied().unwrap_or(VALUES[0])
}

fn add_device_bookkeeping(
    header: &HootHeader,
    definition_decoded_offset: u64,
    device_id: u8,
    schema: &mut HootSchema,
) {
    let common =
        |raw_id, leaf: &str, signal_type, original_type: &str, units: &str, support| SignalInfo {
            raw_id,
            name: signal_name(device_id, leaf),
            signal_type,
            original_type: original_type.to_owned(),
            units: units.to_owned(),
            metadata: "{}".to_owned(),
            source: SignalSource::PhoenixCan,
            support,
            bus: header.source.clone(),
            device: Some(format!("TalonFX-{device_id}")),
            definition_decoded_offset,
        };
    insert_if_absent(
        schema,
        common(
            timestamp_raw_id(device_id),
            "Timestamp",
            SignalType::Float64,
            "double",
            "seconds",
            SignalSupport::Full,
        ),
    );
    insert_if_absent(
        schema,
        common(
            reset_count_raw_id(device_id),
            "ResetCount",
            SignalType::Int64,
            "int64",
            "",
            SignalSupport::Full,
        ),
    );
}

fn insert_if_absent(schema: &mut HootSchema, signal: SignalInfo) {
    if schema.get(signal.raw_id).is_none() {
        schema.insert(signal);
    }
}

fn update(frame: &RawFrame, raw_id: u32, value: SignalValue) -> DecodedUpdate {
    DecodedUpdate {
        timestamp_us: frame.timestamp_us,
        raw_id,
        value,
        decoded_offset: frame.decoded_offset,
        compressed_byte_offset: frame.compressed_byte_offset,
    }
}

fn phoenix_raw_id(spn: u32, device_id: u8) -> u32 {
    (spn << 16) | (u32::from(device_id) << 8)
}

fn timestamp_raw_id(device_id: u8) -> u32 {
    TIMESTAMP_SYNTHETIC_BASE | (u32::from(device_id) << 8)
}

fn reset_count_raw_id(device_id: u8) -> u32 {
    RESET_COUNT_SYNTHETIC_BASE | (u32::from(device_id) << 8)
}

fn signal_name(device_id: u8, leaf: &str) -> String {
    format!("device_{device_id}_{}", simple_leaf_name(leaf))
}

fn simple_leaf_name(leaf: &str) -> String {
    let characters = leaf.chars().collect::<Vec<_>>();
    let mut name = String::with_capacity(leaf.len() + 8);

    for (index, character) in characters.iter().copied().enumerate() {
        if !character.is_ascii_alphanumeric() {
            if !name.is_empty() && !name.ends_with('_') {
                name.push('_');
            }
            continue;
        }

        if character.is_ascii_uppercase() {
            let previous = index.checked_sub(1).and_then(|index| characters.get(index));
            let next = characters.get(index + 1);
            let starts_word = previous.is_some_and(|previous| {
                previous.is_ascii_lowercase()
                    || previous.is_ascii_digit()
                    || (previous.is_ascii_uppercase()
                        && next.is_some_and(|next| next.is_ascii_lowercase()))
            });
            if starts_word && !name.ends_with('_') {
                name.push('_');
            }
            name.push(character.to_ascii_lowercase());
        } else {
            name.push(character);
        }
    }

    name.trim_end_matches('_').to_owned()
}

fn sign_extend(value: u64, width: u32) -> i64 {
    ((value << (64 - width)) as i64) >> (64 - width)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(definitions: &[SignalDef], leaf: &str, payload: &str) -> SignalValue {
        let bytes: [u8; 8] = hex::decode(payload).unwrap().try_into().unwrap();
        let definition = definitions.iter().find(|item| item.leaf == leaf).unwrap();
        decode_value(definition.encoding, u64::from_le_bytes(bytes))
    }

    fn packed_value(definitions: &[SignalDef], leaf: &str, packed: u64) -> SignalValue {
        let definition = definitions.iter().find(|item| item.leaf == leaf).unwrap();
        decode_value(definition.encoding, packed)
    }

    fn signed_bits(value: i64, width: u8) -> u64 {
        (value as u64) & ((1_u64 << width) - 1)
    }

    #[test]
    fn catalog_names_are_simple_and_deterministic() {
        assert_eq!(signal_name(1, "MotorVoltage"), "device_1_motor_voltage");
        assert_eq!(signal_name(12, "PIDRefSlope"), "device_12_pid_ref_slope");
        assert_eq!(
            signal_name(2, "StickyFault_BridgeBrownout"),
            "device_2_sticky_fault_bridge_brownout"
        );
    }

    #[test]
    fn classic_layout_samples_decode_as_expected() {
        assert_eq!(
            value(MOTOR_OUTPUT, "MotorVoltage", "080580ef1c71b10d"),
            SignalValue::Float64(3.22)
        );
        assert_eq!(
            value(MOTOR_OUTPUT, "DutyCycle", "080580ef1c71b10d"),
            SignalValue::Float64(0.27734375)
        );
        assert_eq!(
            value(MOTOR_OUTPUT, "TorqueCurrent", "080580ef1c71b10d"),
            SignalValue::Float64(3505.0 * 0.01)
        );
        assert_eq!(
            value(MOTOR_OUTPUT, "BridgeOutput", "080580ef1c71b10d"),
            SignalValue::String("BridgeReq_FOCTorque".to_owned())
        );

        let supply = "120ae4014c191f1c";
        assert_eq!(
            value(SUPPLY_TEMP, "StatorCurrent", supply),
            SignalValue::Float64(51.56)
        );
        assert_eq!(
            value(SUPPLY_TEMP, "SupplyCurrent", supply),
            SignalValue::Float64(19.36)
        );
        assert_eq!(
            value(SUPPLY_TEMP, "SupplyVoltage", supply),
            SignalValue::Float64(304.0 * 0.025 + 4.0)
        );
        assert_eq!(
            value(SUPPLY_TEMP, "DeviceTemp", supply),
            SignalValue::Float64(25.0)
        );
        assert_eq!(
            value(SUPPLY_TEMP, "ProcessorTemp", supply),
            SignalValue::Float64(31.0)
        );
        assert_eq!(
            value(SUPPLY_TEMP, "AncillaryDeviceTemp", supply),
            SignalValue::Float64(28.0)
        );

        let motion = "240080d4ffffff3f";
        assert_eq!(
            value(MOTION, "Velocity", motion),
            SignalValue::Float64(0.017578125)
        );
        assert_eq!(
            value(MOTION, "Acceleration", motion),
            SignalValue::Float64(-0.25)
        );
    }

    #[test]
    fn version_payload_is_device_discovery_evidence() {
        let mut packed = [0_u8; 8];
        packed[..6].copy_from_slice(&hex::decode("0000021a1380").unwrap());
        let packed = u64::from_le_bytes(packed);
        let read = |leaf| {
            let definition = VERSION.iter().find(|item| item.leaf == leaf).unwrap();
            decode_value(definition.encoding, packed)
        };
        assert_eq!(read("VersionMajor"), SignalValue::Float64(26.0));
        assert_eq!(read("VersionMinor"), SignalValue::Float64(2.0));
        assert_eq!(read("Version"), SignalValue::Float64(436_338_688.0));
        assert_eq!(read("IsProLicensed"), SignalValue::Float64(1.0));
    }

    #[test]
    fn closed_loop_and_fault_layouts_decode_as_expected() {
        let pid_state = signed_bits(-10, 18)
            | (signed_bits(-3, 12) << 18)
            | (37_u64 << 30)
            | (1_u64 << 59)
            | (1_u64 << 61)
            | (1_u64 << 62);
        assert_eq!(
            packed_value(PID_STATE, "PIDDutyCycle_IntegratedAccum", pid_state),
            SignalValue::Float64(-10.0 / 1024.0)
        );
        assert_eq!(
            packed_value(PID_STATE, "PIDMotorVoltage_FeedForward", pid_state),
            SignalValue::Float64(-0.06)
        );
        assert_eq!(
            packed_value(PID_STATE, "ControlMode", pid_state),
            SignalValue::String("MotionMagicExpoTorqueCurrentFOC".to_owned())
        );
        assert_eq!(
            packed_value(PID_STATE, "MotionMagicAtTarget", pid_state),
            SignalValue::Float64(1.0)
        );
        assert_eq!(
            packed_value(PID_STATE, "MotionMagicIsRunning", pid_state),
            SignalValue::Float64(0.0)
        );
        assert_eq!(
            packed_value(PID_STATE, "RobotEnable", pid_state),
            SignalValue::String("Enabled".to_owned())
        );

        let reference = u64::from(1.5_f32.to_bits());
        let error = u64::from((-2.25_f32).to_bits() >> 1) << 32;
        assert_eq!(
            packed_value(PID_REF_ERROR, "PIDPosition_Reference", reference | error),
            SignalValue::Float64(1.5)
        );
        assert_eq!(
            packed_value(
                PID_REF_ERROR,
                "PIDPosition_ClosedLoopError",
                reference | error
            ),
            SignalValue::Float64(-2.25)
        );

        let pid_output = (3_u64 << 2)
            | (10_u64 << 8)
            | (signed_bits(-5, 18) << 26)
            | (7_u64 << 44)
            | (2_u64 << 62);
        assert_eq!(
            packed_value(PID_OUTPUT, "ConnectedMotor", pid_output),
            SignalValue::String("KrakenX44_Integrated".to_owned())
        );
        assert_eq!(
            packed_value(PID_OUTPUT, "PIDDutyCycle_DerivativeOutput", pid_output),
            SignalValue::Float64(-5.0 / 1024.0)
        );
        assert_eq!(
            packed_value(PID_OUTPUT, "ClosedLoopSlot", pid_output),
            SignalValue::Float64(2.0)
        );

        let slope = signed_bits(-64, 16) | (5_u64 << 17);
        assert_eq!(
            packed_value(PID_SLOPE, "PIDPosition_ReferenceSlope", slope),
            SignalValue::Float64(-1.0)
        );
        assert_eq!(
            packed_value(PID_SLOPE, "MotorOutputStatus", slope),
            SignalValue::String("RegenBraking".to_owned())
        );

        let faults = 0x0280_0300_u64 << 32;
        for leaf in [
            "StickyFault_BridgeBrownout",
            "StickyFault_StatorCurrLimit",
            "StickyFault_SupplyCurrLimit",
            "StickyFault_RotorFault1",
        ] {
            assert_eq!(
                packed_value(FAULTS, leaf, faults),
                SignalValue::Float64(1.0),
                "{leaf}"
            );
        }
        assert_eq!(
            packed_value(FAULTS, "StickyFault_RotorFault2", faults),
            SignalValue::Float64(0.0)
        );
        assert_eq!(
            packed_value(FAULTS, "StickyFault_RotorFault2", 1_u64 << 58),
            SignalValue::Float64(1.0)
        );
    }

    fn frame(arbitration_id: u32, record_class: u8, payload: &str) -> RawFrame {
        let payload = hex::decode(payload).unwrap();
        RawFrame {
            decoded_offset: 0,
            compressed_byte_offset: 80,
            compressed_bit: 0,
            header: arbitration_id | (u32::from(record_class) << 29),
            arbitration_id,
            record_class,
            encoded_timestamp_us: 0,
            timestamp_us: 1,
            dlc: 0,
            dlc_flags: 0,
            payload_delta: payload.clone(),
            payload,
        }
    }

    #[test]
    fn discovery_rejects_old_fd_device_and_selects_fd_plus_fallback() {
        let frames = vec![
            Ok(frame(TALON_VERSION_BASE, 3, "780063170200")),
            Ok(frame(TALON_VERSION_BASE, 3, "0000021a1380")),
            Ok(frame(TALON_FD_BUNDLE_BASE, 3, &"00".repeat(64))),
            Ok(frame(TALON_VERSION_BASE | 9, 3, "0000021a1380")),
            Ok(frame(TALON_VERSION_BASE | 9, 1, "000000000000")),
            Ok(frame(TALON_FD_BUNDLE_BASE | 9, 3, &"00".repeat(64))),
            Ok(frame(TALON_MOTION_BASE | 9, 1, "0000000000000000")),
        ];
        let selection = discover(frames).unwrap();
        let mut schema = HootSchema::new();
        apply_selection(&mut schema, selection);

        let old = schema.device(0).unwrap();
        assert_eq!(old.firmware_major, 23);
        assert!(old.version_conflict);
        assert!(!old.catalog_supported);
        assert!(classify(&frame(TALON_FD_BUNDLE_BASE, 3, &"00".repeat(64)), &schema).is_none());

        let current = schema.device(9).unwrap();
        assert_eq!(current.transport, PhoenixTransport::CanFd);
        assert!(current.catalog_supported);
        assert!(
            classify(
                &frame(TALON_FD_BUNDLE_BASE | 9, 3, &"00".repeat(64)),
                &schema
            )
            .is_some()
        );
        assert!(
            classify(
                &frame(TALON_MOTION_BASE | 9, 1, "0000000000000000"),
                &schema
            )
            .is_some()
        );
        assert!(classify(&frame(TALON_VERSION_BASE | 9, 1, "000000000000"), &schema).is_some());
    }

    #[test]
    fn fd_standalone_query_reuses_latest_response() {
        let kind = CatalogFrame {
            group: FrameGroup::Faults,
            device_id: 9,
            firmware_full: 0x1a02_0000,
            is_pro_licensed: true,
        };
        let mut decoder = CatalogDecoder::default();
        let mut updates = std::collections::VecDeque::new();
        decoder
            .decode_frame_into(
                &frame(TALON_FAULTS_BASE | 9, 3, "0000000000038002"),
                kind,
                &mut updates,
            )
            .unwrap();
        updates.clear();
        decoder
            .decode_frame_into(
                &frame(TALON_FAULTS_BASE | 9, 1, "0000000000000000"),
                kind,
                &mut updates,
            )
            .unwrap();
        let read = |leaf: &str| {
            let raw_id = definitions(FrameGroup::Faults)
                .iter()
                .flat_map(|definitions| definitions.iter())
                .find(|definition| definition.leaf == leaf)
                .map(|definition| phoenix_raw_id(definition.spn, 9))
                .unwrap();
            &updates
                .iter()
                .find(|update| update.raw_id == raw_id)
                .unwrap()
                .value
        };
        assert_eq!(
            read("StickyFaultField"),
            &SignalValue::Float64(0x0280_0300 as f64)
        );
        assert_eq!(
            read("StickyFault_BridgeBrownout"),
            &SignalValue::Float64(1.0)
        );
    }
}
