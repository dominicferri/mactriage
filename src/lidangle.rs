//! Lid angle from the hinge sensor on Apple silicon laptops. The sensor is an
//! Apple HID device (vendor 0x05AC, product 0x8104) on the Sensor usage page
//! (0x20), usage 0x8A. Feature report 1 holds the angle in whole degrees as a
//! little-endian u16 in bytes 1-2; a closed lid reads 0.

use std::ffi::{c_void, CString};
use std::os::raw::{c_char, c_int};
use std::sync::mpsc;
use std::time::Duration;

#[derive(Debug, Default, Clone, PartialEq)]
pub enum LidAngle {
    /// No lid angle sensor (desktop Mac, Intel or older laptop), or not read.
    #[default]
    NoSensor,
    Degrees(u16),
    /// The sensor exists but did not return a usable reading.
    Unreadable(String),
}

type CFTypeRef = *const c_void;
type CFIndex = isize;
type IOReturn = c_int;

#[repr(C)]
struct CFDictionaryKeyCallBacks {
    _version: CFIndex,
    _callbacks: [*const c_void; 5],
}

#[repr(C)]
struct CFDictionaryValueCallBacks {
    _version: CFIndex,
    _callbacks: [*const c_void; 4],
}

const CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
const CF_NUMBER_SINT32: CFIndex = 3;
const HID_REPORT_TYPE_FEATURE: u32 = 2;

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    static kCFTypeDictionaryKeyCallBacks: CFDictionaryKeyCallBacks;
    static kCFTypeDictionaryValueCallBacks: CFDictionaryValueCallBacks;
    fn CFStringCreateWithCString(alloc: CFTypeRef, s: *const c_char, enc: u32) -> CFTypeRef;
    fn CFNumberCreate(alloc: CFTypeRef, kind: CFIndex, value: *const c_void) -> CFTypeRef;
    fn CFDictionaryCreate(
        alloc: CFTypeRef,
        keys: *const CFTypeRef,
        values: *const CFTypeRef,
        count: CFIndex,
        key_callbacks: *const CFDictionaryKeyCallBacks,
        value_callbacks: *const CFDictionaryValueCallBacks,
    ) -> CFTypeRef;
    fn CFSetGetCount(set: CFTypeRef) -> CFIndex;
    fn CFSetGetValues(set: CFTypeRef, values: *mut CFTypeRef);
    fn CFRelease(cf: CFTypeRef);
}

#[link(name = "IOKit", kind = "framework")]
extern "C" {
    fn IOHIDManagerCreate(alloc: CFTypeRef, options: u32) -> CFTypeRef;
    fn IOHIDManagerSetDeviceMatching(manager: CFTypeRef, matching: CFTypeRef);
    fn IOHIDManagerOpen(manager: CFTypeRef, options: u32) -> IOReturn;
    fn IOHIDManagerClose(manager: CFTypeRef, options: u32) -> IOReturn;
    fn IOHIDManagerCopyDevices(manager: CFTypeRef) -> CFTypeRef;
    fn IOHIDDeviceOpen(device: CFTypeRef, options: u32) -> IOReturn;
    fn IOHIDDeviceClose(device: CFTypeRef, options: u32) -> IOReturn;
    fn IOHIDDeviceGetReport(
        device: CFTypeRef,
        report_type: u32,
        report_id: CFIndex,
        report: *mut u8,
        length: *mut CFIndex,
    ) -> IOReturn;
}

/// Decode feature report 1. None when the report is too short or the value
/// cannot be an angle.
pub fn decode_report(report: &[u8]) -> Option<u16> {
    if report.len() < 3 {
        return None;
    }
    let degrees = u16::from_le_bytes([report[1], report[2]]);
    (degrees <= 360).then_some(degrees)
}

/// Read the lid angle. The IOKit calls run on a worker thread so a sensor
/// that never answers costs at most `timeout`.
pub fn read(timeout: Duration) -> LidAngle {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(read_blocking());
    });
    rx.recv_timeout(timeout).unwrap_or_else(|_| {
        LidAngle::Unreadable(format!("no answer within {} s", timeout.as_secs()))
    })
}

fn read_blocking() -> LidAngle {
    let matching: [(&str, i32); 4] = [
        ("VendorID", 0x05AC),
        ("ProductID", 0x8104),
        ("PrimaryUsagePage", 0x20),
        ("PrimaryUsage", 0x8A),
    ];
    // SAFETY: every CF object created here is released before returning, and
    // the device references from CFSetGetValues are used only while the set
    // that owns them is alive.
    unsafe {
        let mut owned: Vec<CFTypeRef> = Vec::new();
        let mut keys = Vec::new();
        let mut values = Vec::new();
        for (key, value) in matching {
            let key = CString::new(key).expect("static key has no NUL");
            let k =
                CFStringCreateWithCString(std::ptr::null(), key.as_ptr(), CF_STRING_ENCODING_UTF8);
            let v = CFNumberCreate(
                std::ptr::null(),
                CF_NUMBER_SINT32,
                &value as *const i32 as *const c_void,
            );
            keys.push(k);
            values.push(v);
            owned.extend([k, v]);
        }
        let dict = CFDictionaryCreate(
            std::ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            keys.len() as CFIndex,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks,
        );
        owned.push(dict);
        let manager = IOHIDManagerCreate(std::ptr::null(), 0);
        IOHIDManagerSetDeviceMatching(manager, dict);
        let opened = IOHIDManagerOpen(manager, 0);
        let set = IOHIDManagerCopyDevices(manager);
        let result = if set.is_null() || CFSetGetCount(set) == 0 {
            LidAngle::NoSensor
        } else {
            let mut devices = vec![std::ptr::null(); CFSetGetCount(set) as usize];
            CFSetGetValues(set, devices.as_mut_ptr());
            let mut last = LidAngle::Unreadable(format!("HID manager open returned {opened:#x}"));
            for device in devices {
                let ret = IOHIDDeviceOpen(device, 0);
                if ret != 0 {
                    last = LidAngle::Unreadable(format!("device open returned {ret:#x}"));
                    continue;
                }
                let mut report = [0u8; 8];
                let mut length = report.len() as CFIndex;
                let ret = IOHIDDeviceGetReport(
                    device,
                    HID_REPORT_TYPE_FEATURE,
                    1,
                    report.as_mut_ptr(),
                    &mut length,
                );
                IOHIDDeviceClose(device, 0);
                let length = (length.max(0) as usize).min(report.len());
                last = match (ret, decode_report(&report[..length])) {
                    (0, Some(degrees)) => LidAngle::Degrees(degrees),
                    (0, None) => LidAngle::Unreadable(format!(
                        "unexpected report {:02x?}",
                        &report[..length]
                    )),
                    (ret, _) => LidAngle::Unreadable(format!("get report returned {ret:#x}")),
                };
                if matches!(last, LidAngle::Degrees(_)) {
                    break;
                }
            }
            last
        };
        if !set.is_null() {
            CFRelease(set);
        }
        IOHIDManagerClose(manager, 0);
        CFRelease(manager);
        for cf in owned {
            CFRelease(cf);
        }
        result
    }
}
