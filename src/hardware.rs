//! Hardware health: SSD wear via smartctl (bundled in MacTriage.app), built-in
//! keyboard / trackpad presence and controller status, the lid angle sensor,
//! and low-battery Bluetooth input devices.

use crate::lidangle::LidAngle;
use crate::report::{Evidence, Finding, Severity, Skipped, Vital};
use crate::util::{apple_diagnostics_step, run, run_with_timeout};
use std::path::{Path, PathBuf};
use std::time::Duration;

// ── SSD wear ────────────────────────────────────────────────────────────────

/// `smartctl -j -a` output reduced to the fields triage needs. The drive's
/// serial number is never read.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct SsdHealth {
    pub exit_status: u8,
    pub model: String,
    pub passed: Option<bool>,
    pub nvme: Option<NvmeHealth>,
}

/// NVMe SMART / Health Information log (log page 02h).
#[derive(Debug, Default, Clone, PartialEq)]
pub struct NvmeHealth {
    pub critical_warning: u8,
    pub percentage_used: u32,
    pub available_spare: u32,
    pub available_spare_threshold: u32,
    pub media_errors: u64,
    pub unsafe_shutdowns: u64,
    pub power_on_hours: u64,
    pub temperature_c: Option<i64>,
}

/// Result of the SSD check for the caller to fold into the Disk vital.
#[derive(Default)]
pub struct SsdOutcome {
    pub finding: Option<Finding>,
    /// Appended to the Disk vital, e.g. " · wear 0% · spare 100%".
    pub vital_suffix: String,
    pub flag: Option<Severity>,
    pub skipped: Option<Skipped>,
    pub percentage_used: Option<u32>,
}

/// Where to find smartctl. Never searches PATH: an env override (for tests and
/// known-failure controls), then the copy bundled next to this binary inside
/// MacTriage.app, then Homebrew's two prefixes.
pub fn smartctl_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("MACTRIAGE_SMARTCTL") {
        // Returned even when missing, so a control run can prove the Skipped path.
        return Some(PathBuf::from(p));
    }
    let bundled = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("smartctl")));
    [
        bundled,
        Some(PathBuf::from("/opt/homebrew/bin/smartctl")),
        Some(PathBuf::from("/usr/local/bin/smartctl")),
    ]
    .into_iter()
    .flatten()
    .find(|p| p.is_file())
}

/// Parse `smartctl -j -a <disk>`. Exit-status bits per smartctl(8) EXIT STATUS:
/// bit 0 = command line did not parse, bit 1 = device open failed (no data),
/// bit 2 = some SMART command failed (routine on Apple NVMe — not a fault),
/// bit 3 = SMART status "DISK FAILING".
pub fn parse_smartctl_json(out: &str) -> Result<SsdHealth, String> {
    let v: serde_json::Value =
        serde_json::from_str(out).map_err(|e| format!("unreadable smartctl output ({e})"))?;
    let exit_status = v
        .pointer("/smartctl/exit_status")
        .and_then(|x| x.as_u64())
        .unwrap_or(0) as u8;
    if exit_status & 0b11 != 0 {
        let msg = v
            .pointer("/smartctl/messages/0/string")
            .and_then(|s| s.as_str())
            .unwrap_or("device could not be opened");
        return Err(format!("smartctl exit status {exit_status}: {msg}"));
    }
    let nvme = v.get("nvme_smart_health_information_log").map(|h| {
        let u = |k: &str| h.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
        NvmeHealth {
            critical_warning: u("critical_warning") as u8,
            percentage_used: u("percentage_used") as u32,
            available_spare: u("available_spare") as u32,
            available_spare_threshold: u("available_spare_threshold") as u32,
            media_errors: u("media_errors"),
            unsafe_shutdowns: u("unsafe_shutdowns"),
            power_on_hours: u("power_on_hours"),
            temperature_c: h.get("temperature").and_then(|x| x.as_i64()),
        }
    });
    Ok(SsdHealth {
        exit_status,
        model: v
            .get("model_name")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string(),
        passed: v.pointer("/smart_status/passed").and_then(|p| p.as_bool()),
        nvme,
    })
}

/// Critical Warning bit meanings, NVMe Base Spec SMART / Health log byte 0
/// (as printed by smartmontools nvmeprint.cpp `print_critical_warning`).
const CRITICAL_WARNING_BITS: &[(u8, &str)] = &[
    (0x01, "available spare has fallen below threshold"),
    (0x04, "NVM subsystem reliability has been degraded"),
    (0x08, "media has been placed in read-only mode"),
    (0x10, "volatile memory backup device has failed"),
    (
        0x20,
        "persistent memory region has become read-only or unreliable",
    ),
];
const TEMPERATURE_WARNING: u8 = 0x02;

/// Turn parsed SMART data into at most one `snap.ssd_wear` finding.
pub fn assess_ssd(h: &SsdHealth, disk: &str, tool: &Path) -> SsdOutcome {
    let mut high: Vec<String> = Vec::new();
    let mut medium: Vec<String> = Vec::new();
    let mut out = SsdOutcome::default();

    if let Some(n) = &h.nvme {
        out.percentage_used = Some(n.percentage_used);
        out.vital_suffix = format!(
            " · wear {}% · spare {}%",
            n.percentage_used, n.available_spare
        );
        for (bit, what) in CRITICAL_WARNING_BITS {
            if n.critical_warning & bit != 0 {
                high.push(format!("the drive reports that its {what}"));
            }
        }
        let unknown = n.critical_warning & !0x3f;
        if unknown != 0 {
            high.push(format!(
                "unknown critical warning bits 0x{unknown:02x} are set"
            ));
        }
        if n.critical_warning & 0x01 == 0
            && n.available_spare_threshold > 0
            && n.available_spare < n.available_spare_threshold
        {
            high.push(format!(
                "spare blocks are at {}%, below the drive's {}% threshold",
                n.available_spare, n.available_spare_threshold
            ));
        }
        if n.media_errors > 0 {
            high.push(format!(
                "{} unrecovered media/data-integrity error(s) recorded",
                n.media_errors
            ));
        }
        if n.percentage_used >= 100 {
            high.push(format!(
                "{}% of rated write endurance used (past the manufacturer's rating)",
                n.percentage_used
            ));
        } else if n.percentage_used >= 80 {
            medium.push(format!(
                "{}% of rated write endurance used",
                n.percentage_used
            ));
        }
        if n.critical_warning & TEMPERATURE_WARNING != 0 {
            medium.push("the drive is outside its temperature threshold right now".into());
        }
    } else if let Some(passed) = h.passed {
        out.vital_suffix = format!(" · smartctl {}", if passed { "passed" } else { "FAILED" });
    }
    // For NVMe, smartctl sets bit 3 / passed=false exactly when a critical
    // warning bit is set, and those bits are already explained above (a
    // temperature-only warning stays Medium). The generic verdict is only the
    // cause for ATA/SATA drives.
    if h.nvme.is_none() && (h.exit_status & 0b1000 != 0 || h.passed == Some(false)) {
        high.push("SMART overall-health check returned DISK FAILING".into());
    }

    let severity = if !high.is_empty() {
        Severity::High
    } else if !medium.is_empty() {
        Severity::Medium
    } else {
        return out;
    };
    out.flag = Some(severity);
    let problems: Vec<String> = high.into_iter().chain(medium).collect();
    let mut f = Finding::new(
        "snap.ssd_wear",
        severity,
        "disk",
        &format!("SSD health: {}", problems[0]),
    );
    f.detail = format!(
        "smartctl read the boot drive's health log ({}): {}. An SSD in this state can fail or \
         turn read-only without warning; macOS's own SMART status may still say Verified.",
        if h.model.is_empty() { disk } else { &h.model },
        problems.join("; ")
    );
    f.next_step = Some(if severity == Severity::High {
        format!(
            "Back up now and verify the backup. {}. Plan storage or logic-board service \
             (Apple silicon storage is soldered).",
            apple_diagnostics_step()
        )
    } else {
        "Keep backups current and recheck monthly; plan replacement as it approaches 100%.".into()
    });
    f.evidence.push(Evidence {
        source: tool.display().to_string(),
        excerpt: evidence_excerpt(h),
    });
    out.finding = Some(f);
    out
}

fn evidence_excerpt(h: &SsdHealth) -> String {
    match &h.nvme {
        Some(n) => {
            format!(
            "percentage_used={} available_spare={}/{} media_errors={} critical_warning=0x{:02x} \
             unsafe_shutdowns={} power_on_hours={} temperature={} exit_status={}",
            n.percentage_used,
            n.available_spare,
            n.available_spare_threshold,
            n.media_errors,
            n.critical_warning,
            n.unsafe_shutdowns,
            n.power_on_hours,
            n.temperature_c.map(|t| format!("{t}C")).unwrap_or_else(|| "?".into()),
            h.exit_status
        )
        }
        None => format!("passed={:?} exit_status={}", h.passed, h.exit_status),
    }
}

/// Run smartctl against `disk` (e.g. "disk0") and assess the result.
pub fn ssd_check(disk: &str) -> SsdOutcome {
    let skip = |reason: String| SsdOutcome {
        skipped: Some(Skipped {
            what: "SSD wear (smartctl)".into(),
            reason,
        }),
        ..Default::default()
    };
    let Some(tool) = smartctl_path() else {
        return skip("smartctl not bundled or installed (brew install smartmontools)".into());
    };
    if !tool.is_file() {
        return skip(format!("smartctl not found at {}", tool.display()));
    }
    let (out, timed_out) = run_with_timeout(
        &tool.to_string_lossy(),
        &["-j", "-a", disk],
        Duration::from_secs(15),
    );
    if timed_out {
        return skip("smartctl timed out after 15s".into());
    }
    if out.trim().is_empty() {
        return skip(format!("{} produced no output", tool.display()));
    }
    match parse_smartctl_json(&out) {
        Ok(h) => assess_ssd(&h, disk, &tool),
        Err(reason) => skip(reason),
    }
}

// ── keyboard / trackpad ──────────────────────────────────────────────────────

/// Input hardware macOS can see in the I/O registry.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct InputDevices {
    pub builtin_keyboard: bool,
    pub builtin_trackpad: bool,
    /// Bluetooth / wireless keyboards, mice and trackpads that report a battery.
    pub peripherals: Vec<(String, u8)>,
    /// Built-in keyboard/trackpad controller status flags: ("Critical Errors",
    /// "Critical Errors Accumulator"). None when the registry has no such entry.
    pub controller_errors: Option<(u64, u64)>,
    pub lid_angle: LidAngle,
}

/// Bluetooth input devices at or below this charge get flagged.
const LOW_PERIPHERAL_BATTERY: u8 = 10;

/// With the lid switch reporting open, a hinge sensor below this angle is
/// reading wrong: nobody uses a Mac with the lid this far down.
const LID_ANGLE_SHUT_DEGREES: u16 = 20;

const BUILTIN_INPUT_PRODUCT: &str = "Apple Internal Keyboard / Trackpad";

fn ioreg_dicts(xml: &str) -> Vec<plist::Dictionary> {
    if xml.trim().is_empty() {
        return Vec::new();
    }
    match plist::Value::from_reader_xml(xml.as_bytes()) {
        Ok(plist::Value::Array(items)) => items
            .into_iter()
            .filter_map(|v| v.into_dictionary())
            .collect(),
        _ => Vec::new(),
    }
}

fn built_in(d: &plist::Dictionary) -> bool {
    d.get("Built-In")
        .and_then(|v| v.as_boolean())
        .unwrap_or(false)
}

fn int(d: &plist::Dictionary, key: &str) -> Option<u64> {
    d.get(key).and_then(|v| v.as_unsigned_integer())
}

/// Parse three `ioreg -r -a` dumps: the AppleHIDKeyboardEventDriverV2 class,
/// the AppleMultitouchTrackpadHIDEventDriver class, and every entry carrying a
/// `BatteryPercent` key. Only keyboards, mice and trackpads count as
/// peripherals, so headphones that report a battery are ignored.
pub fn parse_input_devices(keyboards: &str, trackpads: &str, batteries: &str) -> InputDevices {
    let mut dev = InputDevices {
        builtin_keyboard: ioreg_dicts(keyboards).iter().any(built_in),
        builtin_trackpad: ioreg_dicts(trackpads).iter().any(built_in),
        ..Default::default()
    };
    for d in ioreg_dicts(batteries) {
        if built_in(&d) {
            continue;
        }
        let Some(pct) = int(&d, "BatteryPercent") else {
            continue;
        };
        let product = d
            .get("Product")
            .and_then(|v| v.as_string())
            .unwrap_or("")
            .to_string();
        let lower = product.to_lowercase();
        // HID Generic Desktop page (1): usage 2 = mouse, 6 = keyboard.
        let hid_input = int(&d, "PrimaryUsagePage") == Some(1)
            && matches!(int(&d, "PrimaryUsage"), Some(2) | Some(6));
        let named_input = ["keyboard", "mouse", "trackpad"]
            .iter()
            .any(|w| lower.contains(w));
        if (hid_input || named_input) && !dev.peripherals.iter().any(|(p, _)| *p == product) {
            let name = if product.is_empty() {
                "input device".into()
            } else {
                product
            };
            dev.peripherals.push((name, pct.min(100) as u8));
        }
    }
    dev
}

/// Parse `ioreg -r -a -c AppleMultitouchDevice` for the built-in controller's
/// status flags. The built-in entry carries no "Built-In" key, so it is matched
/// by product name; an external Magic Trackpad is ignored.
pub fn parse_controller_errors(multitouch: &str) -> Option<(u64, u64)> {
    ioreg_dicts(multitouch)
        .iter()
        .filter(|d| {
            built_in(d)
                || d.get("Product").and_then(|v| v.as_string()) == Some(BUILTIN_INPUT_PRODUCT)
        })
        .filter_map(|d| {
            let now = int(d, "Critical Errors");
            let total = int(d, "Critical Errors Accumulator");
            (now.is_some() || total.is_some()).then(|| (now.unwrap_or(0), total.unwrap_or(0)))
        })
        .reduce(|a, b| (a.0 | b.0, a.1 | b.1))
}

/// Findings and the "Input" vital for the parsed devices. `laptop` = a battery
/// is installed, so a built-in keyboard and trackpad must exist. With the lid
/// closed (clamshell) the built-in devices are not judged. The registry classes
/// were verified on Apple silicon only, so a missing device is High there and
/// Medium on Intel.
pub fn assess_input(
    dev: &InputDevices,
    laptop: bool,
    lid_closed: bool,
    apple_silicon: bool,
) -> (Vec<Finding>, Vital) {
    let mut findings = Vec::new();
    let mut parts: Vec<String> = Vec::new();
    let mut flag: Option<Severity> = None;
    let mark = |ok: bool| if ok { "✓" } else { "✗ missing" };

    if laptop && lid_closed {
        parts.push("lid closed — built-in keyboard/trackpad not checked".into());
    } else if laptop {
        parts.push(format!("built-in keyboard {}", mark(dev.builtin_keyboard)));
        parts.push(format!("trackpad {}", mark(dev.builtin_trackpad)));
        let missing: Vec<&str> = [
            (!dev.builtin_keyboard).then_some("keyboard"),
            (!dev.builtin_trackpad).then_some("trackpad"),
        ]
        .into_iter()
        .flatten()
        .collect();
        if !missing.is_empty() {
            let sev = if apple_silicon {
                Severity::High
            } else {
                Severity::Medium
            };
            flag = Some(sev);
            let what = missing.join(" and ");
            let mut f = Finding::new(
                "snap.input_devices",
                sev,
                "hardware",
                &format!("Built-in {what} not detected by macOS"),
            );
            f.detail = format!(
                "This Mac has a battery, so it should have a built-in keyboard and trackpad, but \
                 the I/O registry lists no built-in {what} driver. The usual causes are a failed \
                 keyboard/trackpad assembly or its cable, liquid damage, or an input-controller \
                 firmware fault."
            );
            f.next_step = Some(format!(
                "With the lid open, test with an external keyboard and mouse. Shut down fully for \
                 30 seconds and start up again. If the {what} is still missing: {}.",
                apple_diagnostics_step()
            ));
            f.evidence.push(Evidence {
                source:
                    "ioreg AppleHIDKeyboardEventDriverV2 / AppleMultitouchTrackpadHIDEventDriver"
                        .into(),
                excerpt: format!(
                    "built-in keyboard={} built-in trackpad={}",
                    dev.builtin_keyboard, dev.builtin_trackpad
                ),
            });
            findings.push(f);
        }
        if let Some((now, total)) = dev.controller_errors {
            let status = now | total;
            if status == 0 {
                parts.push("controller ✓".into());
            } else {
                parts.push(format!("controller errors {status:#x}"));
                flag = flag.max(Some(Severity::Medium));
                let mut f = Finding::new(
                    "snap.input_controller",
                    Severity::Medium,
                    "hardware",
                    &format!(
                        "Built-in keyboard/trackpad controller reports critical errors \
                         (status {status:#x})"
                    ),
                );
                f.detail = "The controller that runs the built-in keyboard and trackpad reports \
                            a nonzero critical-error status; a healthy Mac reads 0x0. This fits \
                            a keyboard and trackpad that stop responding, or respond only \
                            sometimes, while a USB or Bluetooth keyboard still works. The usual \
                            causes are a loose or damaged keyboard/trackpad cable (check this \
                            first after any repair inside the case), liquid damage, or a failed \
                            keyboard/trackpad assembly."
                    .into();
                f.next_step = Some(format!(
                    "Confirm with an external keyboard and mouse. Shut down fully for 30 seconds \
                     and start up again. If the status is still nonzero: {}. If the Mac was \
                     opened for a repair recently, have the repairer reseat the keyboard/trackpad \
                     cable.",
                    apple_diagnostics_step()
                ));
                f.evidence.push(Evidence {
                    source: "ioreg AppleMultitouchDevice (built-in)".into(),
                    excerpt: format!(
                        "Critical Errors={now} ({now:#x}) Critical Errors Accumulator={total} \
                         ({total:#x})"
                    ),
                });
                findings.push(f);
            }
        }
        match &dev.lid_angle {
            LidAngle::NoSensor => {}
            LidAngle::Unreadable(why) => parts.push(format!("lid angle unreadable ({why})")),
            LidAngle::Degrees(degrees) => {
                parts.push(format!("lid angle {degrees}°"));
                if *degrees < LID_ANGLE_SHUT_DEGREES {
                    flag = flag.max(Some(Severity::Medium));
                    let mut f = Finding::new(
                        "snap.lid_angle",
                        Severity::Medium,
                        "hardware",
                        &format!(
                            "Lid angle sensor reads {degrees}° while the lid switch reports open"
                        ),
                    );
                    f.detail = "The hinge sensor and the lid switch disagree: the lid is open, \
                                but the sensor reports it almost shut. A wrong angle can make the \
                                Mac act as if the lid were closed or closing. Likely causes are \
                                a faulty or misplaced sensor, or a replacement sensor that was \
                                not configured after the repair."
                        .into();
                    f.next_step = Some(
                        "Open the lid fully and run the check again. If the reading stays low or \
                         does not follow the lid, have the repairer check the lid angle sensor \
                         and run the system configuration step for the replaced part."
                            .into(),
                    );
                    f.evidence.push(Evidence {
                        source: "IOHID lid angle sensor (usage page 0x20, usage 0x8A); ioreg \
                                 AppleClamshellState"
                            .into(),
                        excerpt: format!("angle={degrees}° AppleClamshellState=No"),
                    });
                    findings.push(f);
                }
            }
        }
    } else if !dev.builtin_keyboard && !dev.builtin_trackpad {
        parts.push("no built-in keyboard/trackpad (desktop Mac)".into());
    }

    for (name, pct) in &dev.peripherals {
        parts.push(format!("{name} {pct}%"));
    }
    let low: Vec<String> = dev
        .peripherals
        .iter()
        .filter(|(_, pct)| *pct <= LOW_PERIPHERAL_BATTERY)
        .map(|(name, pct)| format!("{name} {pct}%"))
        .collect();
    if !low.is_empty() {
        flag = flag.or(Some(Severity::Low));
        let mut f = Finding::new(
            "snap.input_devices",
            Severity::Low,
            "hardware",
            &format!("Low battery: {}", low.join(", ")),
        );
        f.detail = "A nearly flat Bluetooth keyboard, mouse or trackpad lags, drops keystrokes \
                    and disconnects, which is easy to mistake for a failing device."
            .into();
        f.next_step = Some(
            "Charge it (or replace its batteries), then retest before suspecting the hardware."
                .into(),
        );
        findings.push(f);
    }

    let value = if parts.is_empty() {
        "no input devices reported".into()
    } else {
        parts.join(" · ")
    };
    (
        findings,
        Vital {
            label: "Input".into(),
            value,
            flag,
        },
    )
}

/// Query the registry and assess input hardware on this Mac. Err when ioreg
/// itself can't run: an unreadable registry must not read as "desktop Mac".
pub fn input_check() -> Result<(Vec<Finding>, Vital), String> {
    // `run` is None only when ioreg fails; a class with no instances is Some("").
    let q = |args: &[&str]| run("ioreg", args).ok_or_else(|| "ioreg could not run".to_string());
    let battery = q(&["-r", "-c", "AppleSmartBattery", "-a"])?;
    let laptop = crate::power::parse_smart_battery(&battery)
        .map(|b| b.installed)
        .unwrap_or(false);
    let mut dev = parse_input_devices(
        &q(&["-r", "-a", "-c", "AppleHIDKeyboardEventDriverV2"])?,
        &q(&["-r", "-a", "-c", "AppleMultitouchTrackpadHIDEventDriver"])?,
        &q(&["-r", "-a", "-k", "BatteryPercent"])?,
    );
    dev.controller_errors =
        parse_controller_errors(&q(&["-r", "-a", "-c", "AppleMultitouchDevice"])?);
    let lid_closed = q(&["-r", "-k", "AppleClamshellState", "-d", "1"])?
        .lines()
        .any(|l| l.contains("\"AppleClamshellState\" = Yes"));
    if laptop && !lid_closed {
        dev.lid_angle = crate::lidangle::read(Duration::from_secs(3));
    }
    Ok(assess_input(
        &dev,
        laptop,
        lid_closed,
        crate::util::is_apple_silicon(),
    ))
}
