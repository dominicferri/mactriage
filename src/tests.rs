use crate::report::{Finding, OverallCondition, Severity};
use crate::util;

#[test]
fn parse_window_units() {
    assert_eq!(util::parse_window("30m").unwrap().as_secs(), 1800);
    assert_eq!(util::parse_window("6h").unwrap().as_secs(), 21600);
    assert_eq!(util::parse_window("3d").unwrap().as_secs(), 259200);
    assert_eq!(util::parse_window("2w").unwrap().as_secs(), 1209600);
    assert!(util::parse_window("abc").is_none());
    assert!(util::parse_window("").is_none());
}

#[test]
fn parse_report_times() {
    // Modern .ips header stamp with zone
    let t = crate::files::parse_report_time("2026-07-16 13:27:14.00 -0400").unwrap();
    assert_eq!(t.timestamp(), 1784222834);
    // Hang report stamp with millis
    assert!(crate::files::parse_report_time("2026-07-11 21:10:41.454 -0400").is_some());
    // No zone (interpreted as local) still parses
    assert!(crate::files::parse_report_time("2026-07-16 13:27:14").is_some());
    assert!(crate::files::parse_report_time("garbage").is_none());
}

#[test]
fn severity_exit_codes() {
    assert_eq!(Severity::Info.exit_code(), 0);
    assert_eq!(Severity::Low.exit_code(), 10);
    assert_eq!(Severity::Medium.exit_code(), 20);
    assert_eq!(Severity::High.exit_code(), 30);
    assert_eq!(Severity::Critical.exit_code(), 40);
    assert!(Severity::Critical > Severity::High);
}

#[test]
fn overall_condition_reports_how_serious_the_findings_are() {
    let mut report = crate::report::Report {
        schema_version: crate::report::SCHEMA_VERSION,
        tool: crate::report::TOOL_NAME.into(),
        tool_version: crate::report::TOOL_VERSION.into(),
        generated_at: chrono::Utc::now(),
        scan_window: "test".into(),
        window_since: None,
        window_until: None,
        complete: true,
        host: crate::host::host_info(false),
        vitals: vec![],
        findings: vec![],
        skipped: vec![],
        notes: vec![],
        recovery: None,
        stats: Default::default(),
        log_events: vec![],
    };

    assert_eq!(report.overall_condition(), OverallCondition::Healthy);
    report.complete = false;
    assert_eq!(report.overall_condition(), OverallCondition::Unknown);
    let terminal = crate::render::render(&report, &crate::render::Style::new(true), 0, false);
    assert!(terminal.contains("Overall condition  UNKNOWN"));
    let html = crate::html::render(&report);
    assert!(html.contains("Overall condition: UNKNOWN"));
    report
        .findings
        .push(Finding::new("low", Severity::Low, "test", "low"));
    assert_eq!(report.overall_condition(), OverallCondition::Minor);
    report
        .findings
        .push(Finding::new("medium", Severity::Medium, "test", "medium"));
    assert_eq!(report.overall_condition(), OverallCondition::Degraded);
    report
        .findings
        .push(Finding::new("high", Severity::High, "test", "high"));
    assert_eq!(report.overall_condition(), OverallCondition::Serious);
    report.findings.push(Finding::new(
        "critical",
        Severity::Critical,
        "test",
        "critical",
    ));
    report
        .findings
        .push(Finding::new("info", Severity::Info, "test", "info"));
    assert_eq!(report.overall_condition(), OverallCondition::Critical);
    assert_eq!(report.actionable_count(), 4);
}

#[test]
fn ips_crash_scan_from_fixture() {
    use std::collections::HashSet;
    let dir = std::env::temp_dir().join("mactriage-test-fixture");
    let _ = std::fs::create_dir_all(&dir);
    let ips = concat!(
        r#"{"app_name":"testproc","timestamp":"2026-07-16 13:27:14.00 -0400","bug_type":"309","name":"testproc"}"#,
        "\n",
        r#"{"procName":"testproc","exception":{"type":"EXC_BAD_ACCESS","signal":"SIGSEGV"},"termination":{"indicator":"segfault"}}"#
    );
    std::fs::write(dir.join("testproc-2026-07-16-132714.ips"), ips).unwrap();

    let cats: HashSet<crate::report::Category> =
        crate::report::Category::ALL.iter().copied().collect();
    let since = chrono::Utc::now() - chrono::Duration::days(1);
    let res = crate::files::scan(std::slice::from_ref(&dir), since, chrono::Utc::now(), &cats);
    let crash = res
        .findings
        .iter()
        .find(|f| f.rule_id == "file.crash")
        .expect("crash finding");
    assert_eq!(crash.process.as_deref(), Some("testproc"));
    assert!(crash.summary.contains("EXC_BAD_ACCESS"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn panic_ips_extracts_kexts() {
    use std::collections::HashSet;
    let dir = std::env::temp_dir().join("mactriage-test-panic");
    let _ = std::fs::create_dir_all(&dir);
    let body = serde_json::json!({
        "panicString": "panic(cpu 4): Kernel trap at 0xffff\nKernel Extensions in backtrace:\n   com.vendor.baddriver(1.2.3)[UUID]@0xfff\n   com.apple.iokit.IOUSBHostFamily(1.0)[UUID]@0xffe\nlast started kext"
    });
    let ips = format!(
        "{}\n{}",
        r#"{"bug_type":"210","timestamp":"2026-07-16 08:00:00.00 -0400","name":"kernel"}"#, body
    );
    std::fs::write(dir.join("Kernel-2026-07-16-080000.panic.ips"), ips).unwrap();

    let cats: HashSet<crate::report::Category> =
        crate::report::Category::ALL.iter().copied().collect();
    let since = chrono::Utc::now() - chrono::Duration::days(1);
    let res = crate::files::scan(std::slice::from_ref(&dir), since, chrono::Utc::now(), &cats);
    let panic = res
        .findings
        .iter()
        .find(|f| f.rule_id == "file.kernel_panic")
        .expect("panic finding");
    assert_eq!(panic.severity, Severity::Critical);
    assert!(res.panic_kexts.iter().any(|k| k == "com.vendor.baddriver"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn correlator_merges_repeats_and_escalates_loops() {
    use chrono::TimeZone;
    let mk = |rule: &str, process: &str, hour: u32, min: u32| {
        let mut f = Finding::new(
            rule,
            Severity::Medium,
            "crash",
            &format!("{process} crashed"),
        );
        f.process = Some(process.into());
        f.timestamp = Some(
            chrono::Utc
                .with_ymd_and_hms(2026, 7, 16, hour, min, 0)
                .unwrap(),
        );
        f
    };
    let findings = vec![
        // Three crashes inside a ~40-min window → a real crash loop (High).
        mk("file.crash", "looper", 1, 0),
        mk("file.crash", "looper", 1, 20),
        mk("file.crash", "looper", 1, 40),
        // Repeated resource-abuse of one process merges with a count.
        mk("file.cpu_resource", "hog", 1, 0),
        mk("file.cpu_resource", "hog", 2, 0),
    ];
    let out = crate::correlate::run(findings, &[], &[], &[]);
    let loop_f = out
        .iter()
        .find(|f| f.rule_id == "correlate.crash_loop")
        .expect("crash loop");
    assert_eq!(loop_f.severity, Severity::High);
    assert_eq!(loop_f.count, 3);
    let hog = out
        .iter()
        .find(|f| f.rule_id == "file.cpu_resource")
        .expect("merged cpu finding");
    assert_eq!(hog.count, 2);
    assert!(hog.first_seen.is_some());
}

#[test]
fn panic_kext_cross_reference() {
    let out = crate::correlate::run(
        vec![],
        &[
            "com.vendor.baddriver".into(),
            "com.apple.driverkit.thing".into(),
        ],
        &["com.vendor.baddriver".into()],
        &[],
    );
    let hit = out
        .iter()
        .find(|f| f.rule_id == "correlate.panic_kext")
        .expect("panic kext cross-ref");
    assert!(hit.summary.contains("com.vendor.baddriver"));
    // Apple kexts in the backtrace never trigger it
    assert!(!hit.summary.contains("com.apple."));
}

#[test]
fn min_severity_report_exit() {
    let mut report = crate::report::Report {
        schema_version: crate::report::SCHEMA_VERSION,
        tool: crate::report::TOOL_NAME.into(),
        tool_version: crate::report::TOOL_VERSION.into(),
        generated_at: chrono::Utc::now(),
        scan_window: "test".into(),
        window_since: None,
        window_until: None,
        complete: true,
        host: crate::host::host_info(false),
        vitals: vec![],
        findings: vec![
            Finding::new("a", Severity::Low, "x", "low thing"),
            Finding::new("b", Severity::High, "x", "high thing"),
        ],
        skipped: vec![],
        notes: vec![],
        recovery: None,
        stats: Default::default(),
        log_events: vec![],
    };
    assert_eq!(report.exit_code(), 30);
    report.findings.retain(|f| f.severity >= Severity::Critical);
    assert_eq!(report.exit_code(), 0);
}

#[test]
fn wrap_respects_width() {
    let text = "one two three four five six seven eight nine ten eleven twelve";
    let wrapped = util::wrap(text, 20, "  ");
    for line in wrapped.lines() {
        assert!(line.len() <= 22, "line too long: {line}");
    }
}

// Regression: legacy plain-text `.panic` files have no JSON header, and the
// header reader used to swallow them so they were never parsed.
#[test]
fn plaintext_panic_is_parsed() {
    use std::collections::HashSet;
    let dir = std::env::temp_dir().join("mactriage-test-plainpanic");
    let _ = std::fs::create_dir_all(&dir);
    let text = "panic(cpu 2): Kernel trap\n\
                Kernel Extensions in backtrace:\n\
                   com.vendor.plainkext(9.9)[UUID]@0xfff\n\
                last started kext at ...";
    std::fs::write(dir.join("Kernel_2026-07-16-120000.panic"), text).unwrap();

    let cats: HashSet<crate::report::Category> =
        crate::report::Category::ALL.iter().copied().collect();
    let since = chrono::Utc::now() - chrono::Duration::days(1);
    let res = crate::files::scan(std::slice::from_ref(&dir), since, chrono::Utc::now(), &cats);
    let panic = res
        .findings
        .iter()
        .find(|f| f.rule_id == "file.kernel_panic")
        .expect("plain-text panic parsed");
    assert_eq!(panic.severity, Severity::Critical);
    assert!(res.panic_kexts.iter().any(|k| k == "com.vendor.plainkext"));
    assert_eq!(
        res.files_unparsed, 0,
        "plain .panic should not count as unparsed"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// Category routing: `--only crashes` must scan crashes but not panics.
#[test]
fn category_filter_scopes_reports() {
    use std::collections::HashSet;
    let dir = std::env::temp_dir().join("mactriage-test-catfilter");
    let _ = std::fs::create_dir_all(&dir);
    let crash = concat!(
        r#"{"app_name":"appx","timestamp":"2026-07-16 13:00:00.00 -0400","bug_type":"309","name":"appx"}"#,
        "\n",
        r#"{"procName":"appx","exception":{"type":"EXC_CRASH"}}"#
    );
    std::fs::write(dir.join("appx-2026-07-16-130000.ips"), crash).unwrap();
    let panic = concat!(
        r#"{"bug_type":"210","timestamp":"2026-07-16 13:00:00.00 -0400","name":"kernel"}"#,
        "\n",
        r#"{"panicString":"panic(cpu 0): trap"}"#
    );
    std::fs::write(dir.join("Kernel-2026-07-16-130000.panic.ips"), panic).unwrap();

    let only_crashes: HashSet<crate::report::Category> =
        [crate::report::Category::Crashes].into_iter().collect();
    let since = chrono::Utc::now() - chrono::Duration::days(1);
    let res = crate::files::scan(
        std::slice::from_ref(&dir),
        since,
        chrono::Utc::now(),
        &only_crashes,
    );
    assert!(res.findings.iter().any(|f| f.rule_id == "file.crash"));
    assert!(
        !res.findings
            .iter()
            .any(|f| f.rule_id == "file.kernel_panic"),
        "panic must be filtered out under --only crashes"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// The shutdown-cause code table, per SMC firmware STOP_CAUSE constants:
// normal codes (1/5/7)→None, thermal emergency(-95)→Critical, watchdog
// (-61/-62)→Critical, -64 is officially "unknown" (High, not Critical),
// -60 is a drained battery (Medium), unknown→Medium.
#[test]
fn shutdown_code_classification() {
    use crate::logscan::shutdown_severity;
    assert!(shutdown_severity(5).is_none());
    assert!(shutdown_severity(1).is_none());
    assert!(shutdown_severity(7).is_none());
    assert_eq!(shutdown_severity(-95).unwrap().0, Severity::Critical);
    assert_eq!(shutdown_severity(-61).unwrap().0, Severity::Critical);
    assert_eq!(shutdown_severity(-64).unwrap().0, Severity::High);
    assert!(shutdown_severity(-64).unwrap().1.contains("unknown"));
    assert_eq!(shutdown_severity(-60).unwrap().0, Severity::Medium);
    assert!(shutdown_severity(-60).unwrap().1.contains("battery"));
    assert_eq!(shutdown_severity(-3).unwrap().0, Severity::High);
    assert!(shutdown_severity(-3).unwrap().1.contains("thermal"));
    assert_eq!(shutdown_severity(0).unwrap().0, Severity::Medium);
    assert_eq!(shutdown_severity(3).unwrap().0, Severity::High);
    assert_eq!(shutdown_severity(-9999).unwrap().0, Severity::Medium);
}

// A tight burst of crashes is a High crash loop; the same count spread across
// the window is only Medium.
#[test]
fn crash_loop_requires_a_burst() {
    use chrono::TimeZone;
    let mk = |process: &str, h: u32, m: u32| {
        let mut f = Finding::new(
            "file.crash",
            Severity::Medium,
            "crash",
            &format!("{process} crashed"),
        );
        f.process = Some(process.into());
        f.timestamp = Some(chrono::Utc.with_ymd_and_hms(2026, 7, 16, h, m, 0).unwrap());
        f
    };
    // Three crashes within 30 minutes → loop.
    let burst = vec![mk("tight", 10, 0), mk("tight", 10, 10), mk("tight", 10, 25)];
    let out = crate::correlate::run(burst, &[], &[], &[]);
    assert_eq!(
        out.iter()
            .find(|f| f.process.as_deref() == Some("tight"))
            .unwrap()
            .rule_id,
        "correlate.crash_loop"
    );

    // Three crashes days apart → not a loop, merged to a Medium file.crash.
    let spread = vec![mk("spread", 1, 0), mk("spread", 12, 0), mk("spread", 23, 0)];
    let out = crate::correlate::run(spread, &[], &[], &[]);
    let f = out
        .iter()
        .find(|f| f.process.as_deref() == Some("spread"))
        .unwrap();
    assert_eq!(f.rule_id, "file.crash");
    assert_eq!(f.severity, Severity::Medium);
    assert_eq!(f.count, 3);
}

// The rule catalog must have unique IDs and cover the load-bearing rules.
#[test]
fn rule_catalog_is_consistent() {
    use std::collections::HashSet;
    let ids: Vec<&str> = crate::rules::RULES.iter().map(|r| r.id).collect();
    let unique: HashSet<&&str> = ids.iter().collect();
    assert_eq!(ids.len(), unique.len(), "duplicate rule id in catalog");
    for must in [
        "file.kernel_panic",
        "log.software_update",
        "snap.smart",
        "snap.top_mem",
        "correlate.crash_loop",
    ] {
        assert!(ids.contains(&must), "catalog missing {must}");
    }
}

#[test]
fn software_update_failure_matching_is_specific() {
    use crate::logscan::software_update_failure;
    assert!(software_update_failure(
        "softwareupdated",
        "Previous software update asset is no longer prepared (error 7408)"
    ));
    assert!(software_update_failure(
        "com.apple.MobileSoftwareUpdate.UpdateBrainService",
        "Personalization failed with SUErrorDomain"
    ));
    assert!(!software_update_failure(
        "softwareupdated",
        "Update completed successfully"
    ));
    assert!(!software_update_failure(
        "unrelated-app",
        "installation failed"
    ));
}

#[test]
fn io_error_matching_rejects_core_data_metadata_and_successful_checks() {
    let rule = crate::logscan::LOG_RULES
        .iter()
        .find(|rule| rule.id == "log.io_errors")
        .expect("log.io_errors rule");

    for process in ["peopled", "sharingd"] {
        assert!(!(rule.matches)(
            process,
            "CoreData: error:   Filesystem type name: \t\tapfs"
        ));
    }
    assert!(!(rule.matches)(
        "diskutil",
        "Performing fsck_apfs -n -l -x /dev/rdisk3s1"
    ));
    assert!(!(rule.matches)(
        "fsck_apfs",
        "The volume /dev/rdisk3s1 appears to be OK"
    ));

    assert!((rule.matches)(
        "kernel",
        "[ESD-S1C] I/O error! Opcode 0x28, Service response 0x01, Task status 0x04"
    ));
    assert!((rule.matches)("fsck_apfs", "error: object map is invalid"));
    assert!((rule.matches)(
        "kernel",
        "apfs: container corruption detected"
    ));

    // 2026-09-09 run: 64 sandbox denials escalated to a High disk finding.
    assert!(!(rule.matches)(
        "kernel",
        "IOUC AppleAPFSUserClient failed MACF in process pid 45665, mdworker_shared"
    ));
    // Volume lock-state churn (also present in the 2026-09-08 client report).
    assert!(!(rule.matches)(
        "kernel",
        "apfs_keybag_unload_class_keys:3332: failed to unload volume class keys, error = e00002f0"
    ));
    assert!(!(rule.matches)(
        "kernel",
        "apfs_keybag_unlock_record_tag:3546: failed to unwrap volume key, err = 0xe00002e2 (tag = 2)"
    ));
    // Automount retrying a locked secondary volume is a mount outcome, not I/O.
    assert!(!(rule.matches)(
        "kernel",
        "apfs_vfsop_mount:3052: apfs_vfsop_mount failed, err: 1"
    ));
    assert!(!(rule.matches)(
        "kernel",
        "apfs_vfsop_mount:2842: disk7 apfs_mount failed, err: 1"
    ));
    assert!(!(rule.matches)(
        "kernel",
        "apfs_mount:30612: disk7s1 Failed to unwrap metadata crypto state: 1"
    ));
    // "invalidating" is routine cleanup, not "invalid" state (substring trap).
    assert!(!(rule.matches)(
        "kernel",
        "apfs_vnop_remove:4868: disk3s5 invalidating reserved ranges after deletion of ino 9172859"
    ));
    assert!((rule.matches)("fsck_apfs", "error: object map is invalid"));
    // A volume dropping mid-write is the classic dying-disk symptom — keep it.
    assert!((rule.matches)(
        "kernel",
        "apfs_vfsop_unmount:3541: disk6s1 failed to finish all transactions before unmount! (err 6)"
    ));
    // Spotlight store page-ins are index corruption, not a disk finding.
    assert!(!(rule.matches)(
        "kernel",
        "apfs_pagein:15352: disk3s5 ino 8993820/9048430 pl_offset 0 f_offset 16384 size 16384 file size 6244 error 22 (mds_stores)"
    ));
    assert!((rule.matches)(
        "kernel",
        "apfs_pagein:15352: disk3s5 ino 12/34 pl_offset 0 f_offset 16384 size 16384 file size 6244 error 22"
    ));

    let spotlight = crate::logscan::LOG_RULES
        .iter()
        .find(|r| r.id == "log.spotlight")
        .expect("log.spotlight rule");
    assert!(!(spotlight.matches)(
        "mds",
        "[0xaef9a0c80] Re-initialization successful; calling out to event handler with XPC_ERROR_CONNECTION_INTERRUPTED"
    ));
    // Positive control: a substantive index error still matches. (Until
    // 0.11.5 this used the ENOENT "stat succeeded, getattrlist returned error
    // 2" race, which is now filtered as temp-file churn.)
    assert!((spotlight.matches)(
        "mds_stores",
        "_CISyncContextSync:1504: indexPrepareForSyncBulk error:-1"
    ));

    // backupd probing snapshot support is not a backup failure.
    let backupd = crate::logscan::LOG_RULES
        .iter()
        .find(|r| r.id == "log.backupd")
        .expect("log.backupd rule");
    assert!(!(backupd.matches)(
        "backupd",
        "Failed to get unit 39160 from store <private>"
    ));
    assert!(!(backupd.matches)(
        "backupd",
        "[0xe00000a9ce97c00] Re-initialization successful; calling out to event handler with XPC_ERROR_CONNECTION_INTERRUPTED"
    ));
    assert!(!(backupd.matches)(
        "backupd",
        "fs_snapshot_list failed: Operation not supported"
    ));
    assert!((backupd.matches)(
        "backupd",
        "Snapshot deletion failed for disk '/', error: Error Domain=NSPOSIXErrorDomain Code=30"
    ));
}

#[test]
fn recovery_assessment_renders_in_terminal_html_and_json() {
    let mut report = crate::report::Report {
        schema_version: crate::report::SCHEMA_VERSION,
        tool: crate::report::TOOL_NAME.into(),
        tool_version: crate::report::TOOL_VERSION.into(),
        generated_at: chrono::Utc::now(),
        scan_window: "test".into(),
        window_since: None,
        window_until: None,
        complete: true,
        host: crate::report::HostInfo {
            model: "MacTest1,1".into(),
            chip: "Apple M2".into(),
            memory_gb: 16,
            macos_version: "13.7.8".into(),
            macos_build: "22H730".into(),
            arch: "arm64".into(),
            uptime: "1h".into(),
            root: true,
            model_name: String::new(),
            storage: String::new(),
        },
        vitals: vec![],
        findings: vec![Finding::new(
            "log.software_update",
            Severity::Medium,
            "updates",
            "Software Update failure",
        )],
        skipped: vec![],
        notes: vec![],
        recovery: None,
        stats: Default::default(),
        log_events: vec![],
    };
    report.recovery = Some(crate::recovery::assess(&report, true));

    let terminal = crate::render::render(&report, &crate::render::Style::new(true), 0, false);
    assert!(terminal.contains("Overall condition  DEGRADED"));
    assert!(terminal.contains("Meaningful problems were found"));
    assert!(terminal.contains("Recovery decision"));
    assert!(terminal.contains("REINSTALL macOS IN PLACE"));
    assert!(terminal.contains("NOT YET JUSTIFIED"));

    let html = crate::html::render(&report);
    assert!(html.contains("Overall condition"));
    assert!(html.contains("DEGRADED"));
    assert!(html.contains("Meaningful problems were found"));
    assert!(html.contains("Recovery decision"));
    assert!(html.contains("NOT YET JUSTIFIED"));

    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(
        json["recovery"]["clean_install"],
        serde_json::Value::String("not_yet_justified".into())
    );
}

// The JSON report carries every matched log line for deep review, but the key
// is omitted entirely when the log pass produced no hits (or did not run).
#[test]
fn log_events_serialize_only_when_present() {
    let mut report = crate::report::Report {
        schema_version: crate::report::SCHEMA_VERSION,
        tool: crate::report::TOOL_NAME.into(),
        tool_version: crate::report::TOOL_VERSION.into(),
        generated_at: chrono::Utc::now(),
        scan_window: "test".into(),
        window_since: None,
        window_until: None,
        complete: true,
        host: crate::host::host_info(false),
        vitals: vec![],
        findings: vec![],
        skipped: vec![],
        notes: vec![],
        recovery: None,
        stats: Default::default(),
        log_events: vec![],
    };

    let json = serde_json::to_value(&report).unwrap();
    assert!(
        json.get("log_events").is_none(),
        "empty log_events must be omitted from the JSON report"
    );

    report.log_events.push(crate::report::LogEvent {
        timestamp: Some(chrono::Utc::now()),
        rule_id: "log.io_errors".into(),
        process: "kernel".into(),
        message: "apfs: container corruption detected".into(),
    });
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["log_events"][0]["rule_id"], "log.io_errors");
    assert_eq!(json["log_events"][0]["process"], "kernel");

    // Old reports without the key still deserialize.
    let mut old = serde_json::to_value(&report).unwrap();
    old.as_object_mut().unwrap().remove("log_events");
    let decoded: crate::report::Report = serde_json::from_value(old).unwrap();
    assert!(decoded.log_events.is_empty());
}

// Real lines from the 2026-09-08 field report that were counted as findings
// but are queries, configuration, polling, or updater bookkeeping — plus the
// genuine failure signatures each rule exists to catch.
#[test]
fn field_noise_lines_do_not_match_wifi_watchdog_thermal_usb() {
    let rule = |id: &str| {
        crate::logscan::LOG_RULES
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("missing rule {id}"))
    };

    let wifi = rule("log.wifi");
    assert!(!(wifi.matches)(
        "airportd",
        "[corewifi] END REQ [GET LINK DOWN STATUS] took 0.000144792s (pid=754 proc=WiFiAgent"
    ));
    // 2026-09-09 run: WiFiUsageSession telemetry dumps embed LinkDown counters.
    assert!(!(wifi.matches)(
        "airportd",
        "-[WiFiUsageSession _generateState] Device\n{\n    BTBand = \"2.4\";\n    Link Down = 1;\n}"
    ));
    assert!((wifi.matches)(
        "airportd",
        "deauth received from AP, reason 7"
    ));
    assert!((wifi.matches)(
        "airportd",
        "link down on en0 (reason: beacon loss)"
    ));

    // 2026-09-09 run: 2400 idle-exit reclaims counted as memory-pressure kills.
    let jetsam = rule("log.jetsam");
    assert!(!(jetsam.matches)(
        "kernel",
        "memorystatus: killing (idle) com.apple.MobileSoftwareUpdate.C [72818] due to idle-exit (9)"
    ));
    assert!(!(jetsam.matches)(
        "kernel",
        "memorystatus: killing_idle_process pid 4801 [cfprefsd] (idle-exit 0 310s rf:low type:daemon)"
    ));
    assert!((jetsam.matches)(
        "kernel",
        "memorystatus: killing_top_process pid 812 [Goodnotes] due to vm-pageshortage"
    ));
    assert!((jetsam.matches)(
        "kernel",
        "memorystatus: low swap: killing largest compressed process"
    ));

    let watchdog = rule("log.watchdog");
    assert!(!(watchdog.matches)(
        "launchd",
        "setting launch watchdog timeout to 10 secs from overlay"
    ));
    assert!((watchdog.matches)(
        "watchdogd",
        "service is unresponsive for 30 seconds"
    ));
    assert!((watchdog.matches)(
        "kernel",
        "watchdog timeout: no checkins from watchdogd"
    ));

    let thermal = rule("log.thermal");
    assert!(!(thermal.matches)(
        "CommCenter",
        "#I Polling for the states of screen, locks, reachability status, ringer state, battery \
         saver mode, thermal pressure level & in metro status"
    ));
    assert!((thermal.matches)("kernel", "CPU_Speed_Limit = 60"));
    assert!((thermal.matches)(
        "thermalmonitord",
        "thermal pressure state: 3 (heavy)"
    ));

    let usb = rule("log.usb_tb");
    assert!(!(usb.matches)(
        "accessoryupdaterd",
        "Step completed step:Find device:com.apple.MobileAsset.MobileAccessoryUpdate.\
         ThunderboltTypeSwitchOS successful:NO next-step:End silentUpdate=0 error:(null)"
    ));
    assert!((usb.matches)(
        "kernel",
        "USB port over-current condition detected on port 2"
    ));
    assert!((usb.matches)(
        "kernel",
        "Thunderbolt link error on port 1, retraining"
    ));
}

// Jetsam per-process-limit means ONE process crossed its own cap (medium, keyed
// by the victim); vm-pageshortage means the SYSTEM ran out of memory (high).
#[test]
fn jetsam_reason_separates_victim_cap_from_system_pressure() {
    use std::collections::HashSet;
    let dir = std::env::temp_dir().join("mactriage-test-jetsam");
    let _ = std::fs::create_dir_all(&dir);
    let cats: HashSet<crate::report::Category> =
        crate::report::Category::ALL.iter().copied().collect();

    let mk = |file: &str, reason: &str| {
        let body = serde_json::json!({
            "largestProcess": "Goodnotes",
            "processes": [{"name": "knowledgeconstructiond", "reason": reason}]
        });
        let ips = format!(
            "{}\n{}",
            r#"{"bug_type":"298","timestamp":"2026-09-08 00:12:05.00 -0400","name":"JetsamEvent"}"#,
            body
        );
        std::fs::write(dir.join(file), ips).unwrap();
    };

    mk("JetsamEvent-2026-09-08-001205.ips", "per-process-limit");
    let since = chrono::Utc::now() - chrono::Duration::days(365 * 10);
    let res = crate::files::scan(std::slice::from_ref(&dir), since, chrono::Utc::now(), &cats);
    let f = res
        .findings
        .iter()
        .find(|f| f.rule_id == "file.jetsam")
        .expect("jetsam finding");
    assert_eq!(
        f.severity,
        Severity::Medium,
        "per-process cap is not system pressure"
    );
    assert_eq!(
        f.process.as_deref(),
        Some("knowledgeconstructiond"),
        "keyed by victim"
    );
    assert!(f.summary.contains("knowledgeconstructiond"));
    assert!(!f.detail.contains("ran out of memory headroom"));
    assert!(
        !f.evidence[0].excerpt.is_empty(),
        "evidence must be quotable"
    );

    mk("JetsamEvent-2026-09-08-001205.ips", "vm-pageshortage");
    let res = crate::files::scan(std::slice::from_ref(&dir), since, chrono::Utc::now(), &cats);
    let f = res
        .findings
        .iter()
        .find(|f| f.rule_id == "file.jetsam")
        .expect("jetsam finding");
    assert_eq!(
        f.severity,
        Severity::High,
        "system pressure is the serious case"
    );
    assert_eq!(f.process.as_deref(), Some("knowledgeconstructiond"));

    // xnu-verified classes: highwater is hybrid (soft cap during pressure →
    // system), idle-exit/long-idle-exit are housekeeping (Low).
    mk("JetsamEvent-2026-09-08-001205.ips", "highwater");
    let res = crate::files::scan(std::slice::from_ref(&dir), since, chrono::Utc::now(), &cats);
    let f = res
        .findings
        .iter()
        .find(|f| f.rule_id == "file.jetsam")
        .expect("jetsam finding");
    assert_eq!(
        f.severity,
        Severity::High,
        "highwater only kills under system pressure"
    );

    mk("JetsamEvent-2026-09-08-001205.ips", "long-idle-exit");
    let res = crate::files::scan(std::slice::from_ref(&dir), since, chrono::Utc::now(), &cats);
    let f = res
        .findings
        .iter()
        .find(|f| f.rule_id == "file.jetsam")
        .expect("jetsam finding");
    assert_eq!(f.severity, Severity::Low, "idle reaping is housekeeping");
    let _ = std::fs::remove_dir_all(&dir);
}

// Log findings clustered entirely inside the first ~2 minutes after boot are
// startup sequencing: tagged and downgraded one level, never below the floor,
// and fatal findings are untouched.
#[test]
fn boot_window_findings_are_tagged_and_downgraded() {
    use chrono::TimeZone;
    let boot = chrono::Utc
        .with_ymd_and_hms(2026, 9, 8, 19, 15, 30)
        .unwrap();
    let at = |s: i64| Some(boot + chrono::Duration::seconds(s));

    let mut boot_noise = Finding::new("log.kext", Severity::Medium, "services", "kext failures");
    boot_noise.first_seen = at(5);
    boot_noise.timestamp = at(30);
    let mut runtime = Finding::new("log.io_errors", Severity::High, "i/o", "io errors");
    runtime.first_seen = at(10);
    runtime.timestamp = at(4000); // continues long after boot
    let mut fatal = Finding::new("log.shutdown_cause", Severity::Critical, "power", "panic");
    fatal.timestamp = at(20);
    let mut file_based = Finding::new("file.crash", Severity::Medium, "crash", "crash");
    file_based.timestamp = at(20);

    let mut findings = vec![boot_noise, runtime, fatal, file_based];
    crate::scan::apply_boot_phase(&mut findings, boot);

    assert_eq!(
        findings[0].severity,
        Severity::Low,
        "boot-window log finding downgraded"
    );
    assert!(findings[0].detail.contains("of boot"));
    assert_eq!(
        findings[1].severity,
        Severity::High,
        "runtime finding untouched"
    );
    assert_eq!(
        findings[2].severity,
        Severity::Critical,
        "fatal never downgraded"
    );
    assert_eq!(
        findings[3].severity,
        Severity::Medium,
        "file findings untouched"
    );
}

// Four medium-grade Spotlight-stack findings are one story with one fix; the
// correlator must join them and rank the story above its members.
#[test]
fn spotlight_stack_findings_join_into_one_story() {
    let mut cpu = Finding::new(
        "file.cpu_resource",
        Severity::Medium,
        "resource_abuse",
        "spotlightknowledged exceeded its CPU usage limit",
    );
    cpu.process = Some("spotlightknowledged".into());
    cpu.count = 8;
    let mut mds = Finding::new(
        "log.spotlight",
        Severity::Medium,
        "spotlight",
        "Spotlight indexer errors (227 events)",
    );
    mds.count = 227;
    let mut jetsam = Finding::new(
        "file.jetsam",
        Severity::Medium,
        "memory",
        "knowledgeconstructiond exceeded its own memory limit",
    );
    jetsam.process = Some("knowledgeconstructiond".into());

    let out = crate::correlate::run(vec![cpu, mds, jetsam], &[], &[], &[]);
    let story = out
        .iter()
        .find(|f| f.rule_id == "correlate.spotlight_stack")
        .expect("spotlight stack story");
    assert_eq!(story.severity, Severity::High);
    assert!(story
        .next_step
        .as_deref()
        .unwrap_or("")
        .contains("mdutil -E /"));
    for member in out.iter().filter(|f| {
        matches!(
            f.rule_id.as_str(),
            "file.cpu_resource" | "log.spotlight" | "file.jetsam"
        )
    }) {
        assert_eq!(
            member.severity,
            Severity::Info,
            "{} must fold out of the actionable list",
            member.rule_id
        );
    }

    // A lone signal class must NOT fabricate the story.
    let mut lone = Finding::new(
        "log.spotlight",
        Severity::Medium,
        "spotlight",
        "Spotlight indexer errors",
    );
    lone.count = 60;
    let out = crate::correlate::run(vec![lone], &[], &[], &[]);
    assert!(!out.iter().any(|f| f.rule_id == "correlate.spotlight_stack"));
}

// Apple OSAnalytics bug_type coverage: modern cpu_resource is 202 (143 is a
// legacy alias), ResetCount is 115, SystemWatchdogCrash is 409, and BridgeOS
// panics arrive as 210 with caused_by.
#[test]
fn bug_type_routing_matches_apple_osanalytics_config() {
    use std::collections::HashSet;
    let dir = std::env::temp_dir().join("mactriage-test-bugtypes");
    let _ = std::fs::create_dir_all(&dir);
    let cats: HashSet<crate::report::Category> =
        crate::report::Category::ALL.iter().copied().collect();
    let since = chrono::Utc::now() - chrono::Duration::days(1);

    let write = |file: &str, bug: &str, body: &str| {
        let header = format!(
            "{{\"bug_type\":\"{bug}\",\"timestamp\":\"2026-09-09 08:00:00.00 -0400\",\"name\":\"x\"}}"
        );
        std::fs::write(dir.join(file), format!("{header}\n{body}")).unwrap();
    };

    // 202 = modern cpu_resource (header carries app_name, like real reports)
    std::fs::write(
        dir.join("spotlightknowledged_2026-09-09.ips"),
        concat!(
            "{\"app_name\":\"spotlightknowledged\",\"bug_type\":\"202\",\"timestamp\":\"2026-09-09 08:00:00.00 -0400\",\"name\":\"spotlightknowledged\"}\n",
            "Event:            cpu usage\nCPU:              90 seconds cpu time over 95 seconds (95% cpu average), exceeding limit of 50%"
        ),
    )
    .unwrap();
    // 115 = ResetCount
    write(
        "ResetCount-2026-09-09.ips",
        "115",
        "Boot failure count: 4\nBoot faults: swd",
    );
    // 409 = SystemWatchdogCrash
    write("loginwindow-2026-09-09.ips", "409", "{}");
    // 210 with caused_by = BridgeOS panic
    write(
        "Kernel-2026-09-09.panic.ips",
        "210",
        r#"{"caused_by":"bridgeos","panicString":"panic(cpu 0): bridgeos timeout"}"#,
    );

    let res = crate::files::scan(std::slice::from_ref(&dir), since, chrono::Utc::now(), &cats);
    let has = |id: &str| res.findings.iter().any(|f| f.rule_id == id);

    let cpu = res
        .findings
        .iter()
        .find(|f| f.rule_id == "file.cpu_resource")
        .expect("202 must route to cpu_resource");
    assert_eq!(cpu.process.as_deref(), Some("spotlightknowledged"));

    let rc = res
        .findings
        .iter()
        .find(|f| f.rule_id == "file.reset_count")
        .expect("115 must route to reset_count");
    assert_eq!(rc.severity, Severity::High, "4 boot failures is High");
    assert_eq!(rc.count, 4);

    assert!(
        has("file.system_watchdog"),
        "409 must route to system_watchdog"
    );

    let panic = res
        .findings
        .iter()
        .find(|f| f.rule_id == "file.kernel_panic")
        .expect("210 panic");
    assert!(
        panic.summary.contains("bridgeos"),
        "caused_by must surface for recovery gating"
    );

    // Sleep Wake Failure .diag has no JSON header — matched by filename.
    std::fs::write(
        dir.join("Sleep Wake Failure_2026-09-09-080000.diag"),
        "Date/Time: 2026-09-09 08:00:00 -0400\nCommand: Sleep Wake Failure\n",
    )
    .unwrap();
    let res = crate::files::scan(std::slice::from_ref(&dir), since, chrono::Utc::now(), &cats);
    assert!(
        res.findings
            .iter()
            .any(|f| f.rule_id == "file.sleep_wake_failure"),
        "Sleep Wake Failure .diag must be detected by filename"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// A finding with no timestamp must not poison a merged finding's first_seen.
#[test]
fn merge_keeps_first_seen_despite_timeless_member() {
    use chrono::TimeZone;
    let mut timed = Finding::new("file.jetsam", Severity::High, "memory", "jetsam");
    timed.process = Some("hogproc".into());
    timed.timestamp = Some(chrono::Utc.with_ymd_and_hms(2026, 7, 16, 8, 0, 0).unwrap());
    let mut timeless = Finding::new("file.jetsam", Severity::High, "memory", "jetsam");
    timeless.process = Some("hogproc".into());
    timeless.timestamp = None;

    let out = crate::correlate::run(vec![timed, timeless], &[], &[], &[]);
    let merged = out.iter().find(|f| f.rule_id == "file.jetsam").unwrap();
    assert_eq!(merged.count, 2);
    assert!(merged.first_seen.is_some(), "None member erased first_seen");
}

// ── security.rs parsers ─────────────────────────────────────────────────────

#[test]
fn wifi_security_classification() {
    use crate::security::{
        classify_wifi_security as c, parse_wifi_security as p, WifiSecurity as W,
    };
    // Real macOS 27 `ipconfig getsummary en0` excerpt (corporate 802.1X).
    let enterprise = "  BSSID : <redacted>\n  SSID : <redacted>\n  Security : FT_8021X\n";
    assert_eq!(p(enterprise), W::Secure("FT_8021X".into()));
    // Negative controls: the check must fire on open and weak networks.
    assert_eq!(p("  SSID : Cafe\n  Security : NONE\n"), W::Open);
    assert_eq!(c("WEP"), W::Weak("WEP".into()));
    assert_eq!(c("WPA_PSK"), W::Weak("WPA_PSK".into()));
    assert_eq!(
        c("WPA2_WPA_Mixed_PSK"),
        W::Weak("WPA2_WPA_Mixed_PSK".into())
    );
    assert_eq!(c("OWE"), W::EnhancedOpen("OWE".into()));
    assert_eq!(c("WPA2_PSK"), W::Secure("WPA2_PSK".into()));
    assert_eq!(c("WPA3_SAE"), W::Secure("WPA3_SAE".into()));
    // Unknown is never "secure".
    assert_eq!(p("  SSID : x\n"), W::Unknown);
    assert_eq!(c("SOMETHING_NEW"), W::Unknown);
    assert_eq!(p("  State : Inactive\n"), W::NotConnected);
}

#[test]
fn remote_access_services() {
    let out = "disabled services = {\n\t\t\"com.apple.AEServer\" => disabled\n\t\t\"com.apple.screensharing\" => enabled\n\t\t\"com.openssh.sshd\" => enabled\n\t}\n";
    let e = crate::security::parse_enabled_services(out);
    assert_eq!(e, vec!["com.apple.screensharing", "com.openssh.sshd"]);
    let ns = "tcp4  0 0  *.22   *.*  LISTEN\ntcp6 0 0 *.5900 *.* LISTEN\ntcp4 0 0 127.0.0.1.9222 *.* LISTEN\ntcp4 0 0 10.0.0.2.5000 1.2.3.4.443 ESTABLISHED\n";
    assert_eq!(crate::security::parse_listen_ports(ns), vec![22, 5900]);
}

#[test]
fn exposed_listeners_parsing() {
    use crate::security::{apple_platform_signed, parse_lsof_listeners, signer_label};
    // lsof -F pcn: IPv4 + IPv6 sockets on the same port collapse; loopback and
    // [::1] are not exposed; a pid-less row is ignored.
    let out = "p781\ncControlCenter\nf9\nn*:7000\nf10\nn*:7000\nf11\nn*:5000\n\
               p1072\nclocaldev\nf15\nn127.0.0.1:48000\np1091\ncssh\nf3\nn[::1]:9877\n";
    let l = parse_lsof_listeners(out);
    assert_eq!(l.len(), 4);
    assert!(
        l[0].exposed && l[0].pid == 781 && l[0].port == 7000 && l[0].command == "ControlCenter"
    );
    assert!(l[1].exposed && l[1].port == 5000);
    assert!(!l[2].exposed && l[2].command == "localdev" && l[2].port == 48000);
    assert!(!l[3].exposed && l[3].port == 9877);
    assert!(parse_lsof_listeners("n*:80\n").is_empty()); // no pid
    assert!(parse_lsof_listeners("").is_empty());

    let apple = "Executable=/System/Library/CoreServices/ControlCenter.app/Contents/MacOS/ControlCenter\n\
                 Authority=macOS Software Signing\nAuthority=Apple Code Signing Certification Authority\n\
                 Authority=Apple Root CA\n";
    assert!(apple_platform_signed(apple));
    assert_eq!(signer_label(apple), "Apple");
    assert!(apple_platform_signed("Authority=Software Signing\n"));
    let dev = "Authority=Developer ID Application: Example Vendor Inc (EXAMPLE456)\n\
               Authority=Developer ID Certification Authority\nAuthority=Apple Root CA\n";
    assert!(!apple_platform_signed(dev));
    assert_eq!(
        signer_label(dev),
        "Developer ID: Example Vendor Inc (EXAMPLE456)"
    );
    let store = "Authority=Apple Mac OS Application Signing\nAuthority=Apple Worldwide Developer Relations Certification Authority\n";
    assert!(!apple_platform_signed(store));
    assert_eq!(signer_label(store), "Mac App Store");
    assert_eq!(
        signer_label("Signature=adhoc\nTeamIdentifier=not set\n"),
        "ad-hoc signed (no identity)"
    );
    assert_eq!(
        signer_label("/opt/x: code object is not signed at all\n"),
        "unsigned"
    );
}

#[test]
fn known_resolvers_and_sensitive_hosts() {
    use crate::security::{known_public_resolver, sensitive_host};
    assert_eq!(
        known_public_resolver("75.75.75.75"),
        Some("Comcast/Xfinity")
    );
    assert_eq!(
        known_public_resolver("2001:558:FEED::1"),
        Some("Comcast/Xfinity")
    );
    assert_eq!(known_public_resolver("1.1.1.1"), Some("Cloudflare"));
    assert_eq!(known_public_resolver("9.9.9.9"), Some("Quad9"));
    assert_eq!(known_public_resolver("185.220.101.4"), None); // not a provider
    assert_eq!(known_public_resolver("8.8.8.9"), None); // near-miss is not Google

    assert_eq!(
        sensitive_host("swscan.apple.com"),
        Some("Apple update/security")
    );
    assert_eq!(
        sensitive_host("ocsp.apple.com"),
        Some("Apple update/security")
    );
    assert_eq!(sensitive_host("apple.com"), Some("Apple update/security"));
    assert_eq!(sensitive_host("notapple.com"), None); // label boundary
    assert_eq!(
        sensitive_host("registry.npmjs.org"),
        Some("package registry")
    );
    assert_eq!(sensitive_host("login.microsoftonline.com"), Some("sign-in"));
    assert_eq!(sensitive_host("sso.example.edu"), Some("sign-in"));
    assert_eq!(sensitive_host("warp.dev"), None);
    assert_eq!(sensitive_host("prox.home.arpa"), None);
}

#[test]
fn jamf_ca_and_pem() {
    use crate::security::{jamf_ca_expected, pem_to_der, profile_cert_ders};
    assert!(jamf_ca_expected(
        "Example University JSS Built-in Certificate Authority",
        true
    ));
    assert!(!jamf_ca_expected(
        "Example University JSS Built-in Certificate Authority",
        false
    ));
    assert!(!jamf_ca_expected("Jamf Root CA", true)); // substring is not enough
    assert!(!jamf_ca_expected("JSS Inspection Root", true));
    assert!(!jamf_ca_expected("Example Vendor CA", true));

    // "hello" → aGVsbG8= ; "hi" → aGk=
    let pem = "-----BEGIN CERTIFICATE-----\naGVs\nbG8=\n-----END CERTIFICATE-----\n";
    assert_eq!(pem_to_der(pem).unwrap(), b"hello");
    assert_eq!(
        pem_to_der("-----BEGIN X-----\naGk=\n-----END X-----").unwrap(),
        b"hi"
    );
    assert!(pem_to_der("no block here").is_none());
    assert!(pem_to_der("-----BEGIN X-----\n!!!!\n-----END X-----").is_none());
    assert!(pem_to_der("-----BEGIN X-----\n-----END X-----").is_none());

    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>_computerlevel</key><array><dict>
  <key>ProfileDisplayName</key><string>MDM Profile</string>
  <key>ProfileItems</key><array>
    <dict><key>PayloadType</key><string>com.apple.security.root</string>
          <key>PayloadContent</key><data>aGVsbG8=</data></dict>
    <dict><key>PayloadType</key><string>com.apple.mdm</string>
          <key>PayloadContent</key><data>aGk=</data></dict>
  </array></dict></array></dict></plist>"#;
    let ders = profile_cert_ders(xml);
    assert_eq!(ders, vec![b"hello".to_vec()]); // only the certificate payload
    assert!(profile_cert_ders("").is_empty());
}

#[test]
fn interpreter_scripts() {
    use crate::security::interpreter_script as s;
    let v = |a: &[&str]| a.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    assert_eq!(
        s(&v(&["/bin/sh", "/Library/Scripts/run.sh"])),
        Some("/Library/Scripts/run.sh".into())
    );
    assert_eq!(
        s(&v(&[
            "/bin/bash",
            "-l",
            "/opt/vendor/daemon.sh",
            "--daemon"
        ])),
        Some("/opt/vendor/daemon.sh".into())
    );
    assert_eq!(
        s(&v(&["/usr/bin/python3", "/opt/tool/main.py"])),
        Some("/opt/tool/main.py".into())
    );
    assert_eq!(
        s(&v(&["/usr/bin/env", "python3", "/opt/tool/main.py"])),
        Some("/opt/tool/main.py".into())
    );
    assert_eq!(
        s(&v(&["/usr/bin/env", "FOO=1", "bash", "/opt/t.sh"])),
        Some("/opt/t.sh".into())
    );
    assert_eq!(
        s(&v(&["/usr/bin/osascript", "/Library/x.scpt"])),
        Some("/Library/x.scpt".into())
    );
    // `env /abs/prog` runs that program, so it is the file to check.
    assert_eq!(
        s(&v(&["/usr/bin/env", "/opt/bin/tool"])),
        Some("/opt/bin/tool".into())
    );
    assert_eq!(
        s(&v(&["/usr/bin/env", "-u", "HOME", "/opt/bin/tool", "-v"])),
        Some("/opt/bin/tool".into())
    );
    // Options that take a value must not be mistaken for the script.
    assert_eq!(
        s(&v(&["/usr/bin/python3", "-W", "ignore", "/opt/t/main.py"])),
        Some("/opt/t/main.py".into())
    );
    assert_eq!(
        s(&v(&["/bin/bash", "-o", "pipefail", "/opt/t/run.sh"])),
        Some("/opt/t/run.sh".into())
    );
    assert_eq!(
        s(&v(&["/usr/bin/perl", "-I", "/opt/lib", "/opt/t/run.pl"])),
        Some("/opt/t/run.pl".into())
    );
    assert_eq!(
        s(&v(&[
            "/usr/bin/osascript",
            "-l",
            "JavaScript",
            "/opt/t/run.js"
        ])),
        Some("/opt/t/run.js".into())
    );
    assert_eq!(
        s(&v(&[
            "/usr/bin/env",
            "python3",
            "-W",
            "x",
            "/opt/t/main.py"
        ])),
        Some("/opt/t/main.py".into())
    );
    // Not scripts: a real binary, inline code, a relative path, a module.
    assert_eq!(s(&v(&["/usr/local/jamf/bin/jamf", "launchDaemon"])), None);
    assert_eq!(s(&v(&["/bin/sh", "-c", "echo hi"])), None);
    assert_eq!(s(&v(&["/bin/sh", "run.sh"])), None);
    assert_eq!(s(&v(&["/usr/bin/python3", "-m", "http.server"])), None);
    assert_eq!(s(&v(&["/usr/bin/env", "relative-tool"])), None);
    assert_eq!(s(&[]), None);
}

#[test]
fn hosts_overrides() {
    let hosts = "##\n127.0.0.1 localhost\n255.255.255.255 broadcasthost\n::1 localhost\n\
                 127.0.0.1 warp.dev\n127.0.0.1 warp.dev\n104.16.5.34 registry.npmjs.org # pin\n";
    let o = crate::security::parse_hosts_overrides(hosts);
    assert_eq!(
        o,
        vec![
            ("127.0.0.1".to_string(), "warp.dev".to_string()),
            ("104.16.5.34".to_string(), "registry.npmjs.org".to_string()),
        ]
    );
    // Stock file → nothing.
    assert!(
        crate::security::parse_hosts_overrides("127.0.0.1 localhost\n::1 localhost\n").is_empty()
    );
}

#[test]
fn dns_and_private_ranges() {
    let dns = "resolver #1\n  nameserver[0] : 100.100.100.100\n  nameserver[1] : 8.8.8.8\nresolver #2\n  nameserver[0] : 10.0.0.1\n";
    assert_eq!(
        crate::security::parse_default_nameservers(dns),
        vec!["100.100.100.100", "8.8.8.8"]
    );
    assert!(crate::security::is_private_ip("100.100.100.100")); // Tailscale CGNAT
    assert!(crate::security::is_private_ip("fd7a:115c:a1e0::53"));
    assert!(crate::security::is_private_ip("10.0.0.53"));
    assert!(!crate::security::is_private_ip("203.0.113.10"));
    assert!(!crate::security::is_private_ip("8.8.8.8"));
}

#[test]
fn dns_known_unknown_split_normalises_ipv6() {
    use crate::security::{known_public_resolver as k, split_public_resolvers};
    // Expanded or upper-case IPv6 is the same address as the listed one.
    assert_eq!(k("2606:4700:4700:0:0:0:0:1111"), Some("Cloudflare"));
    assert_eq!(k("2001:4860:4860:0000:0000:0000:0000:8888"), Some("Google"));
    assert_eq!(k("2620:FE::FE"), Some("Quad9"));
    assert_eq!(k("not-an-ip"), None);
    let ns: Vec<String> = [
        "192.168.1.1",
        "2606:4700:4700:0:0:0:0:1001",
        "203.0.113.10",
        "9.9.9.9",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let (known, unknown) = split_public_resolvers(&ns);
    assert_eq!(known, vec!["2606:4700:4700:0:0:0:0:1001", "9.9.9.9"]);
    assert_eq!(unknown, vec!["203.0.113.10"]); // must fire; private 192.168 is dropped
}

#[test]
fn hosts_block_apple_split() {
    use crate::security::apple_block_severity as a;
    // Update, revocation and notarization hosts are High.
    for h in [
        "swscan.apple.com",
        "ocsp.apple.com",
        "OCSP2.apple.com",
        "gdmf.apple.com",
        "updates.cdn-apple.com",
        "x.cdn-apple.com",
        "api.apple-cloudkit.com",
        "swdist.apple.com",
    ] {
        assert_eq!(a(h), Some(Severity::High), "{h}");
    }
    // Other Apple names (telemetry included) are Medium.
    assert_eq!(a("xp.apple.com"), Some(Severity::Medium));
    assert_eq!(a("metrics.apple.com"), Some(Severity::Medium));
    assert_eq!(a("apple.com"), Some(Severity::Medium));
    // Not Apple: label boundary, other vendors.
    assert_eq!(a("notapple.com"), None);
    assert_eq!(a("ocsp.apple.com.evil.example"), None);
    assert_eq!(a("ads.example.com"), None);
}

#[test]
fn trusted_cert_classification_without_profile_certificates() {
    use crate::security::{
        classify_admin_cert as c, parse_keychain_certs, parse_trust_output, AdminTrust as T,
    };
    let jamf = "Example University JSS Built-in Certificate Authority";
    let one = vec![b"hello".to_vec()];
    let two = vec![b"hello".to_vec(), b"hi".to_vec()];
    // No profile certificates to compare: a Jamf-named CA is Low (unverified), never Info.
    assert_eq!(c(jamf, true, &one, &[]), T::JamfUnverified);
    assert_eq!(c(jamf, true, &[], &[]), T::JamfUnverified);
    // Every same-name keychain certificate must be one a profile delivered.
    assert_eq!(c(jamf, true, &one, &one), T::JamfVerified);
    assert_eq!(c(jamf, true, &two, &one), T::JamfUnverified);
    // Not the Jamf CA by name, or no Jamf framework: needs an owner.
    assert_eq!(c("Example Vendor CA", true, &one, &one), T::Other);
    assert_eq!(c(jamf, false, &one, &one), T::Other);

    // `find-certificate -a -Z -p`: every block, with its SHA-256.
    let out = "SHA-256 hash: AAAA\nSHA-1 hash: BB\n-----BEGIN CERTIFICATE-----\naGVs\nbG8=\n\
               -----END CERTIFICATE-----\nSHA-256 hash: CCCC\nSHA-1 hash: DD\n\
               -----BEGIN CERTIFICATE-----\naGk=\n-----END CERTIFICATE-----\n";
    assert_eq!(
        parse_keychain_certs(out),
        vec![
            ("AAAA".to_string(), b"hello".to_vec()),
            ("CCCC".to_string(), b"hi".to_vec())
        ]
    );
    assert!(parse_keychain_certs("").is_empty());

    // dump-trust-settings: "none" only when the tool says so; failure is unknown.
    assert_eq!(
        parse_trust_output("SecTrustSettingsCopyCertificates: No Trust Settings were found.\n"),
        Some(vec![])
    );
    assert_eq!(
        parse_trust_output("Number of trusted certs = 1\nCert 0: X\n"),
        Some(vec!["X".to_string()])
    );
    assert_eq!(parse_trust_output(""), None);
    assert_eq!(parse_trust_output("security: permission denied"), None);
}

#[test]
fn listener_exposure_merge_and_sharing_ports() {
    use crate::security::{parse_lsof_listeners as p, reportable_ports};
    // A LAN address is exposed, not just `*`.
    let lan = p("p500\ncdevserver\nf4\nn192.168.1.20:8080\nf5\nn[fe80::1%en0]:8081\n");
    assert!(lan.iter().all(|l| l.exposed), "{lan:?}");
    // Loopback then wildcard on the same (pid, port) merge into one exposed row.
    let merged = p("p600\ncsrv\nf4\nn127.0.0.1:9000\nf5\nn*:9000\nf6\nn[::ffff:127.0.0.1]:9001\n");
    assert_eq!(merged.len(), 2);
    assert!(merged[0].exposed && merged[0].port == 9000);
    assert!(!merged[1].exposed); // v4-mapped loopback
                                 // Lines that start with a multi-byte character used to panic the parser.
    let odd = p("é\np1\ncx✓\n✓*:80\nn*:81\n");
    assert_eq!(odd.len(), 1);
    assert!(odd[0].command == "x✓" && odd[0].port == 81 && odd[0].exposed);
    // Sharing ports: left to sec.remote_access only for launchd or Apple binaries.
    assert_eq!(reportable_ports(4242, false, &[22, 8080]), vec![22, 8080]);
    assert_eq!(reportable_ports(4242, true, &[22, 5900, 7000]), vec![7000]);
    assert_eq!(reportable_ports(1, false, &[445, 3283]), Vec::<u16>::new());
}

#[test]
fn screen_lock_parsing() {
    use crate::security::parse_screen_lock as p;
    assert_eq!(
        p("2026-09-24 sysadminctl[1:2] screenLock delay is immediate"),
        Ok(Some(0))
    );
    assert_eq!(p("screenLock delay is 3600 seconds"), Ok(Some(3600)));
    assert_eq!(p("screenLock is off"), Ok(None));
    assert_eq!(p("garbage"), Err(()));
}

#[test]
fn enrollment_parsing() {
    let e = crate::security::parse_enrollment(
        "Enrolled via DEP: No\nMDM enrollment: Yes (User Approved)\nMDM server: https://jamf.example.edu:8443/mdm/ServerURL\n",
    );
    assert_eq!(e.enrolled, Some(true));
    assert!(e.user_approved);
    assert_eq!(e.dep, Some(false));
    let e = crate::security::parse_enrollment("Enrolled via DEP: No\nMDM enrollment: Yes\n");
    assert!(!e.user_approved);
    assert_eq!(crate::security::parse_enrollment("").enrolled, None);
}

#[test]
fn profiles_trust_and_extensions() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>
        <key>_computerlevel</key><array><dict>
          <key>ProfileDisplayName</key><string>PPPC</string>
          <key>ProfileItems</key><array><dict><key>PayloadType</key><string>com.apple.TCC.configuration-profile-policy</string></dict></array>
        </dict></array></dict></plist>"#;
    let p = crate::security::parse_profiles_xml(xml);
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].scope, "_computerlevel");
    assert_eq!(
        p[0].payload_types,
        vec!["com.apple.TCC.configuration-profile-policy"]
    );
    assert!(crate::security::parse_profiles_xml("not xml").is_empty());

    let trust = "Number of trusted certs = 2\nCert 0: Example University JSS Built-in Certificate Authority\n   Number of trust settings : 0\nCert 1: Example_Vendor_CA_SSL\n";
    assert_eq!(
        crate::security::parse_trust_settings(trust),
        vec![
            "Example University JSS Built-in Certificate Authority",
            "Example_Vendor_CA_SSL"
        ]
    );

    let sx = "--- com.apple.system_extension.driver_extension (x)\nenabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n\t*\tN3S\tcom.dymo (1)\tdymo\t[activated disabled]\n--- com.apple.system_extension.network_extension (x)\n*\t*\tW5364U7YZB\tio.tailscale.ipn (1.1)\tTailscale Network Extension\t[activated enabled]\n";
    assert_eq!(
        crate::security::parse_sysext_security(sx),
        vec!["Tailscale Network Extension (W5364U7YZB)"]
    );
}

// ── v0.10 security parsers (each with a must-fire negative control) ─────────

#[test]
fn boot_args_detection() {
    use crate::security::dangerous_boot_args as d;
    assert!(d("").is_empty());
    assert!(d("-v keepsyms=1 debug=0x100").is_empty()); // diagnostics ≠ AMFI off
    assert_eq!(
        d("-v amfi_get_out_of_my_way=1 cs_enforcement_disable=1"),
        vec!["amfi_get_out_of_my_way=1", "cs_enforcement_disable=1"]
    );
}

#[test]
fn privileged_path_modes() {
    let u = crate::security::unsafe_owner_mode;
    assert_eq!(u(0, 0, 0o100755), None);
    assert_eq!(u(0, 80, 0o040775), None); // /Applications: admin group-writable is fine
    assert!(u(0, 0, 0o100777).unwrap().contains("world-writable"));
    assert!(u(0, 20, 0o100775).unwrap().contains("group-writable"));
    assert!(u(501, 20, 0o100755).unwrap().contains("uid 501"));
}

#[test]
fn firewall_app_list() {
    let out = "Total number of apps = 3 \n1 : /Applications/A.app \n             (Allow incoming connections)\n2 : /Users/me/Downloads/b \n             (Block incoming connections)\n3 : /Users/me/tool \n             (Allow incoming connections)\n";
    assert_eq!(
        crate::security::parse_firewall_apps(out),
        vec![
            ("/Applications/A.app".to_string(), true),
            ("/Users/me/Downloads/b".to_string(), false),
            ("/Users/me/tool".to_string(), true),
        ]
    );
}

#[test]
fn sshd_config_semantics() {
    use crate::security::parse_sshd_config as p;
    // Stock macOS config: nothing set → OpenSSH defaults (passwords on).
    let stock =
        "UsePAM yes\nInclude /etc/ssh/sshd_config.d/*\nAuthorizedKeysFile .ssh/authorized_keys\n";
    let a = p(stock);
    assert!(a.password && a.kbd_interactive);
    assert_eq!(a.permit_root, "prohibit-password");
    // First value wins; Match blocks don't override globals.
    let hardened = "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPasswordAuthentication yes\nMatch User bob\n  PermitRootLogin yes\n";
    let h = p(hardened);
    assert!(!h.password && !h.kbd_interactive);
    assert_eq!(h.permit_root, "prohibit-password");
    // `sshd -T` output is lower-case key/value — same parser.
    assert_eq!(
        p("permitrootlogin yes\npasswordauthentication no\n").permit_root,
        "yes"
    );
}

#[test]
fn uid0_backdoor() {
    let out = "_amavisd 83\nroot 0\njdoe 501\ntoor 0\n";
    assert_eq!(crate::security::extra_uid0(out), vec!["toor"]);
    assert!(crate::security::extra_uid0("root 0\nme 501\n").is_empty());
}

#[test]
fn jamf_log_time() {
    use chrono::TimeZone;
    let now = chrono::Local
        .with_ymd_and_hms(2026, 9, 24, 9, 0, 0)
        .unwrap();
    let t = crate::security::parse_jamf_time(
        "Wed Sep 23 14:37:09 mac-01 jamf[31816]: Checking for policies triggered by \"recurring check-in\"",
        now,
    )
    .unwrap();
    assert_eq!((now - t).num_minutes(), 18 * 60 + 22);
    // A December line read in January belongs to last year.
    let jan = chrono::Local.with_ymd_and_hms(2027, 1, 2, 9, 0, 0).unwrap();
    let dec = crate::security::parse_jamf_time("Wed Dec 30 10:00:00 h jamf[1]: x", jan).unwrap();
    assert_eq!((jan - dec).num_days(), 2);
    assert!(crate::security::parse_jamf_time("garbage", now).is_none());
}

#[test]
fn profile_required_extensions() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>
      <key>_computerlevel</key><array><dict><key>ProfileItems</key><array>
        <dict><key>PayloadType</key><string>com.apple.system-extension-policy</string>
          <key>PayloadContent</key><dict><key>AllowedSystemExtensions</key><dict>
            <key>EXAMPLE123</key><array><string>com.example.webfilter</string></array>
          </dict></dict></dict>
        <dict><key>PayloadType</key><string>com.apple.webcontent-filter</string>
          <key>PayloadContent</key><dict><key>FilterDataProviderBundleIdentifier</key>
          <string>com.example.webfilter</string></dict></dict>
      </array></dict></array></dict></plist>"#;
    let ids = crate::security::profile_extension_ids(xml);
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].0, "com.example.webfilter");
    assert!(ids[0].2, "content-filter provider must be marked required");
    let list = "--- com.apple.system_extension.network_extension (x)\n*\t*\tW5364U7YZB\tio.tailscale.ipn.macsys.network-extension (1.102.4/101.102.4)\tTailscale\t[activated enabled]\n\t\tEXAMPLE123\tcom.example.other (1)\tE\t[terminated waiting to uninstall on reboot]\n";
    assert_eq!(
        crate::security::active_extension_ids(list),
        vec!["io.tailscale.ipn.macsys.network-extension"]
    );
}

#[test]
fn firewall_and_stealth_parsing() {
    use crate::security::{parse_firewall_state as fw, parse_stealth as st, FirewallState as F};
    // Exact macOS 27 socketfilterfw strings (format verified in the binary).
    assert_eq!(fw("Firewall is enabled. (State = 1)\n"), F::On);
    assert_eq!(fw("Firewall is enabled. (State = 2)\n"), F::On); // block-all
    assert_eq!(fw("Firewall is disabled. (State = 0)\n"), F::Off); // must fire
    assert_eq!(fw(""), F::Unknown); // unreadable is never "on"
    assert_eq!(fw("socketfilterfw: permission denied"), F::Unknown);
    assert_eq!(st("Firewall stealth mode is on\n"), Some(true));
    assert_eq!(st("Firewall stealth mode is off\n"), Some(false)); // must fire
    assert_eq!(st("Stealth mode disabled"), Some(false));
    assert_eq!(st(""), None);
}

// ── v0.11.0 hardware health ─────────────────────────────────────────────────

/// Trimmed from this Mac's `smartctl -j -a disk0` (MacBook Air M5, 2026-09-30);
/// exit status 4 is routine on Apple NVMe. The serial is a fake canary.
fn smartctl_fixture(exit: u8, used: u32, spare: u32, thresh: u32, media: u64, cw: u8) -> String {
    serde_json::json!({
        "smartctl": { "exit_status": exit },
        "model_name": "APPLE SSD AP0512Z",
        "serial_number": "CANARY-SERIAL-0001",
        "smart_status": { "passed": cw == 0, "nvme": { "value": cw } },
        "nvme_smart_health_information_log": {
            "critical_warning": cw,
            "temperature": 37,
            "available_spare": spare,
            "available_spare_threshold": thresh,
            "percentage_used": used,
            "power_on_hours": 206,
            "unsafe_shutdowns": 6,
            "media_errors": media,
            "num_err_log_entries": 0
        }
    })
    .to_string()
}

fn ssd(json: &str) -> crate::hardware::SsdOutcome {
    let h = crate::hardware::parse_smartctl_json(json).expect("parses");
    crate::hardware::assess_ssd(&h, "disk0", std::path::Path::new("/test/smartctl"))
}

#[test]
fn ssd_healthy_apple_nvme_is_clean() {
    let out = ssd(&smartctl_fixture(4, 0, 100, 99, 0, 0));
    assert!(
        out.finding.is_none(),
        "exit status 4 alone must not flag a healthy drive"
    );
    assert_eq!(out.flag, None);
    assert_eq!(out.vital_suffix, " · wear 0% · spare 100%");
    assert_eq!(out.percentage_used, Some(0));
}

#[test]
fn ssd_wear_thresholds() {
    assert!(ssd(&smartctl_fixture(0, 79, 100, 10, 0, 0))
        .finding
        .is_none());
    let worn = ssd(&smartctl_fixture(0, 85, 100, 10, 0, 0))
        .finding
        .expect("85% flags");
    assert_eq!(worn.severity, Severity::Medium);
    assert_eq!(worn.rule_id, "snap.ssd_wear");
    let spent = ssd(&smartctl_fixture(0, 100, 100, 10, 0, 0))
        .finding
        .expect("100% flags");
    assert_eq!(spent.severity, Severity::High);
}

#[test]
fn ssd_failure_conditions_are_high() {
    // Spare below threshold without the critical-warning bit.
    let spare = ssd(&smartctl_fixture(0, 10, 5, 10, 0, 0))
        .finding
        .expect("spare flags");
    assert_eq!(spare.severity, Severity::High);
    assert!(spare.detail.contains("below the drive's 10% threshold"));
    let media = ssd(&smartctl_fixture(0, 10, 100, 10, 1, 0))
        .finding
        .expect("media flags");
    assert_eq!(media.severity, Severity::High);
    // 0x04 = reliability degraded; smartctl also sets exit bit 3.
    let degraded = ssd(&smartctl_fixture(8, 10, 100, 10, 0, 0x04))
        .finding
        .expect("cw flags");
    assert_eq!(degraded.severity, Severity::High);
    assert!(degraded.detail.contains("reliability has been degraded"));
    assert!(
        !degraded.detail.contains("DISK FAILING"),
        "bit 3 must not duplicate the specific cause"
    );
    // 0x02 (temperature) alone is transient: Medium, not High.
    let hot = ssd(&smartctl_fixture(8, 10, 100, 10, 0, 0x02))
        .finding
        .expect("temp flags");
    assert_eq!(hot.severity, Severity::Medium);
}

#[test]
fn ssd_unusable_output_is_an_error_not_a_verdict() {
    let open_failed = r#"{"smartctl":{"exit_status":2,"messages":[{"string":"Smartctl open device: disk9 failed: No such device","severity":"error"}]}}"#;
    let err = crate::hardware::parse_smartctl_json(open_failed).unwrap_err();
    assert!(err.contains("No such device"));
    assert!(crate::hardware::parse_smartctl_json("not json").is_err());
}

#[test]
fn ssd_ata_drive_reports_pass_fail_only() {
    let ok = ssd(r#"{"smartctl":{"exit_status":0},"smart_status":{"passed":true}}"#);
    assert!(ok.finding.is_none());
    assert_eq!(ok.vital_suffix, " · smartctl passed");
    let bad = ssd(r#"{"smartctl":{"exit_status":8},"smart_status":{"passed":false}}"#)
        .finding
        .expect("failing ATA drive flags");
    assert_eq!(bad.severity, Severity::High);
    assert!(bad.summary.contains("DISK FAILING"));
}

#[test]
fn ssd_output_never_carries_the_serial() {
    let f = ssd(&smartctl_fixture(0, 100, 5, 10, 3, 0x05))
        .finding
        .expect("flags");
    let text = format!("{f:?}");
    assert!(
        !text.contains("CANARY-SERIAL"),
        "serial leaked into the finding"
    );
}

/// Shape of `ioreg -r -c AppleSmartBattery -a` on this Mac (values trimmed;
/// `Serial` is a fake canary that must never be surfaced).
fn battery_xml(
    external: bool,
    raw_external: bool,
    full: bool,
    amps: i64,
    cycles: u32,
    watts: Option<u32>,
) -> String {
    let b = |v: bool| if v { "<true/>" } else { "<false/>" };
    let adapter = watts
        .map(|w| {
            format!("<key>AdapterDetails</key><dict><key>Watts</key><integer>{w}</integer></dict>")
        })
        .unwrap_or_default();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><array><dict>
<key>BatteryInstalled</key><true/>
<key>Serial</key><string>CANARY-BATT-SERIAL</string>
<key>CycleCount</key><integer>{cycles}</integer>
<key>DesignCycleCount9C</key><integer>1000</integer>
<key>BatteryData</key><dict><key>DesignCapacity</key><integer>4629</integer><key>FullChargeCapacity</key><integer>4441</integer><key>FullyCharged</key><integer>0</integer></dict>
<key>ExternalConnected</key>{}
<key>AppleRawExternalConnected</key>{}
<key>IsCharging</key><false/>
<key>FullyCharged</key>{}
<key>InstantAmperage</key><integer>{amps}</integer>
{adapter}
</dict></array></plist>"#,
        b(external),
        b(raw_external),
        b(full)
    )
}

#[test]
fn battery_ioreg_parsing_and_rated_cycles() {
    use crate::power::{parse_smart_battery, past_rated_cycles};
    let b = parse_smart_battery(&battery_xml(false, false, false, -797, 21, None)).expect("parses");
    assert!(b.installed);
    assert_eq!(b.cycle_count, Some(21));
    assert_eq!(b.design_cycles, Some(1000));
    assert_eq!(b.design_mah, Some(4629));
    assert_eq!(b.full_charge_mah, Some(4441));
    assert_eq!(b.instant_amperage_ma, Some(-797));
    assert!(
        !b.fully_charged,
        "top-level FullyCharged is the bool, not BatteryData's integer"
    );
    assert!(
        !format!("{b:?}").contains("CANARY"),
        "battery serial must never be read"
    );
    assert_eq!(past_rated_cycles(Some(&b)), None);
    let old = parse_smart_battery(&battery_xml(false, false, false, 0, 1000, None)).unwrap();
    assert_eq!(past_rated_cycles(Some(&old)), Some((1000, 1000)));
    assert!(parse_smart_battery("").is_none());
    assert!(
        parse_smart_battery(r#"<?xml version="1.0"?><plist version="1.0"><array/></plist>"#)
            .is_none()
    );
}

#[test]
fn charger_rule_needs_two_draining_samples() {
    use crate::power::{assess_charger, parse_smart_battery};
    let draining =
        parse_smart_battery(&battery_xml(true, true, false, -900, 21, Some(30))).unwrap();
    let (f, v) = assess_charger(&draining, Some(&draining));
    let f = f.expect("connected + draining twice flags");
    assert_eq!(f.rule_id, "snap.charger");
    assert_eq!(f.severity, Severity::Medium);
    assert!(v.unwrap().value.contains("30 W"));
    // One sample only (second read unavailable) must not flag.
    assert!(assess_charger(&draining, None).0.is_none());
    // Plugged in and charging normally.
    let charging =
        parse_smart_battery(&battery_xml(true, true, false, 1500, 21, Some(100))).unwrap();
    assert!(assess_charger(&charging, None).0.is_none());
    // On battery: discharging is expected.
    let on_batt = parse_smart_battery(&battery_xml(false, false, false, -900, 21, None)).unwrap();
    let (f, v) = assess_charger(&on_batt, None);
    assert!(f.is_none());
    assert_eq!(v.unwrap().value, "on battery");
    // Stale ExternalConnected without the raw flag must not flag.
    let stale = parse_smart_battery(&battery_xml(true, false, false, -900, 21, Some(100))).unwrap();
    assert!(assess_charger(&stale, Some(&stale)).0.is_none());
    // Charge limit hold at 80%: connected, not charging, ~0 mA.
    let hold = parse_smart_battery(&battery_xml(true, true, false, -20, 21, Some(100))).unwrap();
    assert!(assess_charger(&hold, Some(&hold)).0.is_none());
}

/// Built-in keyboard / trackpad dicts as this Mac's ioreg prints them.
const KBD_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><array><dict>
<key>IOClass</key><string>AppleHIDKeyboardEventDriverV2</string>
<key>Product</key><string>Apple Internal Keyboard / Trackpad</string>
<key>Built-In</key><true/><key>Transport</key><string>FIFO</string>
<key>PrimaryUsagePage</key><integer>1</integer><key>PrimaryUsage</key><integer>6</integer>
</dict></array></plist>"#;
const TP_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><array><dict>
<key>IOClass</key><string>AppleMultitouchTrackpadHIDEventDriver</string>
<key>Product</key><string>Apple Internal Keyboard / Trackpad</string>
<key>Built-In</key><true/><key>Transport</key><string>FIFO</string>
<key>PrimaryUsagePage</key><integer>1</integer><key>PrimaryUsage</key><integer>2</integer>
</dict></array></plist>"#;
const EXT_TP_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><array><dict>
<key>IOClass</key><string>AppleMultitouchTrackpadHIDEventDriver</string>
<key>Product</key><string>Magic Trackpad</string>
<key>Built-In</key><false/><key>Transport</key><string>Bluetooth</string>
</dict></array></plist>"#;

#[test]
fn input_devices_present_on_this_mac() {
    use crate::hardware::{assess_input, parse_input_devices};
    let dev = parse_input_devices(KBD_XML, TP_XML, "");
    assert!(dev.builtin_keyboard && dev.builtin_trackpad);
    let (findings, vital) = assess_input(&dev, true, false, true);
    assert!(findings.is_empty());
    assert_eq!(vital.value, "built-in keyboard ✓ · trackpad ✓");
    assert_eq!(vital.flag, None);
}

#[test]
fn missing_builtin_trackpad_is_flagged() {
    use crate::hardware::{assess_input, parse_input_devices};
    // Only an external Magic Trackpad is present: it must not count as built-in.
    let dev = parse_input_devices(KBD_XML, EXT_TP_XML, "");
    assert!(dev.builtin_keyboard && !dev.builtin_trackpad);
    let (findings, vital) = assess_input(&dev, true, false, true);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "snap.input_devices");
    assert_eq!(findings[0].severity, Severity::High);
    assert!(findings[0].summary.contains("Built-in trackpad"));
    assert!(vital.value.contains("trackpad ✗ missing"));
    // Intel: class names unverified here, so Medium.
    let (intel, _) = assess_input(&dev, true, false, false);
    assert_eq!(intel[0].severity, Severity::Medium);
    // Lid closed: built-in devices are not judged.
    let (closed, vital) = assess_input(&dev, true, true, true);
    assert!(closed.is_empty());
    assert!(vital.value.contains("lid closed"));
    // Desktop Mac: no built-in devices expected.
    let none = parse_input_devices("", "", "");
    let (desk, vital) = assess_input(&none, false, false, true);
    assert!(desk.is_empty());
    assert!(vital.value.contains("desktop Mac"));
}

/// AppleMultitouchDevice entries: the built-in controller has no "Built-In"
/// key, so it is matched by product name.
fn multitouch_xml(product: &str, now: u64, total: u64) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><array><dict>
<key>IOClass</key><string>AppleMultitouchDevice</string>
<key>Product</key><string>{product}</string>
<key>Critical Errors</key><integer>{now}</integer>
<key>Critical Errors Accumulator</key><integer>{total}</integer>
<key>ResetCount</key><integer>0</integer>
</dict></array></plist>"#
    )
}

#[test]
fn input_controller_errors_are_flagged() {
    use crate::hardware::{assess_input, parse_controller_errors, parse_input_devices};
    let mut dev = parse_input_devices(KBD_XML, TP_XML, "");
    // Healthy controller (value read on a working MacBook).
    dev.controller_errors =
        parse_controller_errors(&multitouch_xml("Apple Internal Keyboard / Trackpad", 0, 0));
    assert_eq!(dev.controller_errors, Some((0, 0)));
    let (findings, vital) = assess_input(&dev, true, false, true);
    assert!(findings.is_empty());
    assert_eq!(
        vital.value,
        "built-in keyboard ✓ · trackpad ✓ · controller ✓"
    );
    assert_eq!(vital.flag, None);
    // Status 0x803, read on a MacBook whose built-in keyboard and trackpad
    // stopped responding while a USB keyboard worked.
    dev.controller_errors = parse_controller_errors(&multitouch_xml(
        "Apple Internal Keyboard / Trackpad",
        2051,
        2051,
    ));
    let (findings, vital) = assess_input(&dev, true, false, true);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "snap.input_controller");
    assert_eq!(findings[0].severity, Severity::Medium);
    assert!(findings[0].summary.contains("status 0x803"));
    assert!(findings[0].evidence[0]
        .excerpt
        .contains("Critical Errors=2051 (0x803)"));
    assert!(vital.value.contains("controller errors 0x803"));
    assert_eq!(vital.flag, Some(Severity::Medium));
    // An error only in the accumulator still counts.
    dev.controller_errors =
        parse_controller_errors(&multitouch_xml("Apple Internal Keyboard / Trackpad", 0, 16));
    assert!(assess_input(&dev, true, false, true)
        .1
        .value
        .contains("0x10"));
    // An external Magic Trackpad's status is not the built-in controller's.
    assert_eq!(
        parse_controller_errors(&multitouch_xml("Magic Trackpad", 2051, 2051)),
        None
    );
    assert_eq!(parse_controller_errors(""), None);
    // Lid closed: not judged.
    dev.controller_errors = Some((2051, 2051));
    assert!(assess_input(&dev, true, true, true).0.is_empty());
}

#[test]
fn lid_angle_disagreeing_with_lid_switch_is_flagged() {
    use crate::hardware::{assess_input, parse_input_devices};
    use crate::lidangle::{decode_report, LidAngle};
    // Feature report 1: report ID, then the angle as little-endian u16.
    assert_eq!(decode_report(&[0x01, 0x00, 0x00]), Some(0));
    assert_eq!(decode_report(&[0x01, 0x70, 0x00]), Some(112));
    assert_eq!(decode_report(&[0x01, 0x2c, 0x01]), Some(300));
    assert_eq!(decode_report(&[0x01, 0xff, 0xff]), None);
    assert_eq!(decode_report(&[0x01, 0x70]), None);

    let mut dev = parse_input_devices(KBD_XML, TP_XML, "");
    dev.lid_angle = LidAngle::Degrees(112);
    let (findings, vital) = assess_input(&dev, true, false, true);
    assert!(findings.is_empty());
    assert_eq!(
        vital.value,
        "built-in keyboard ✓ · trackpad ✓ · lid angle 112°"
    );

    dev.lid_angle = LidAngle::Degrees(3);
    let (findings, vital) = assess_input(&dev, true, false, true);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "snap.lid_angle");
    assert_eq!(findings[0].severity, Severity::Medium);
    assert!(findings[0].summary.contains("reads 3°"));
    assert_eq!(vital.flag, Some(Severity::Medium));

    // A sensor that does not answer is shown, not flagged.
    dev.lid_angle = LidAngle::Unreadable("get report returned 0xe00002d8".into());
    let (findings, vital) = assess_input(&dev, true, false, true);
    assert!(findings.is_empty());
    assert!(vital.value.contains("lid angle unreadable"));

    // Both problems at once keep both findings.
    dev.lid_angle = LidAngle::Degrees(0);
    dev.controller_errors = Some((0x803, 0x803));
    let (findings, _) = assess_input(&dev, true, false, true);
    let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert_eq!(ids, ["snap.input_controller", "snap.lid_angle"]);
}

#[test]
fn low_battery_bluetooth_input_devices() {
    use crate::hardware::{assess_input, parse_input_devices};
    let batteries = r#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><array>
<dict><key>Product</key><string>Magic Keyboard</string><key>BatteryPercent</key><integer>5</integer></dict>
<dict><key>Product</key><string>Magic Mouse</string><key>BatteryPercent</key><integer>64</integer></dict>
<dict><key>Product</key><string>AirPods Pro</string><key>BatteryPercent</key><integer>3</integer></dict>
<dict><key>Product</key><string>Keychron K2</string><key>PrimaryUsagePage</key><integer>1</integer><key>PrimaryUsage</key><integer>6</integer><key>BatteryPercent</key><integer>9</integer></dict>
</array></plist>"#;
    let dev = parse_input_devices(KBD_XML, TP_XML, batteries);
    let names: Vec<&str> = dev.peripherals.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        ["Magic Keyboard", "Magic Mouse", "Keychron K2"],
        "AirPods are not input devices"
    );
    let (findings, vital) = assess_input(&dev, true, false, true);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Low);
    assert!(findings[0].summary.contains("Magic Keyboard 5%"));
    assert!(findings[0].summary.contains("Keychron K2 9%"));
    assert!(!findings[0].summary.contains("Magic Mouse"));
    assert!(vital.value.contains("Magic Mouse 64%"));
}

#[test]
fn panic_classifier_blames_the_right_layer() {
    use crate::files::{classify_panic, BlameClass};
    let class = |s: &str, kexts: &[&str]| {
        let kexts: Vec<String> = kexts.iter().map(|k| k.to_string()).collect();
        classify_panic(s, None, &kexts).map(|b| b.class)
    };
    assert_eq!(
        class(
            "panic(cpu 0 caller 0xffffff8012): x86 CPU CATERR detected",
            &[]
        ),
        Some(BlameClass::HardwareSuspect)
    );
    assert_eq!(
        class(
            "panic(cpu 2 caller 0xffffff80): \"Machine Check at 0xffffff7f96c3c8fa, registers:\"",
            &[]
        ),
        Some(BlameClass::HardwareSuspect)
    );
    assert_eq!(
        class(
            "panic(cpu 1 caller 0xfffffe0016): SEP Panic: :sks /sks : 0x0001b3c5",
            &[]
        ),
        Some(BlameClass::Firmware)
    );
    assert_eq!(
        classify_panic("panic(cpu 0): Kernel trap", Some("bridgeos"), &[]).map(|b| b.class),
        Some(BlameClass::Firmware)
    );
    assert_eq!(
        class(
            "panic(cpu 4): Kernel trap at 0xffff",
            &["com.apple.iokit.IOUSBHostFamily", "com.vendor.baddriver"]
        ),
        Some(BlameClass::Software)
    );
    assert_eq!(
        class("panic(cpu 3 caller 0xfffffe00): userspace watchdog timeout: no successful checkins from com.apple.WindowServer", &[]),
        Some(BlameClass::Software)
    );
    // Negative controls: plain traps, Apple-only kexts, register-dump text alone.
    assert_eq!(
        class(
            "panic(cpu 4): Kernel trap at 0xffff",
            &["com.apple.iokit.IOUSBHostFamily"]
        ),
        None
    );
    assert_eq!(
        class("Machine-check capabilities 0x0000000000000c09", &[]),
        None
    );
}

#[test]
fn hardware_panic_is_tagged_end_to_end() {
    use std::collections::HashSet;
    let dir = std::env::temp_dir().join("mactriage-test-caterr");
    let _ = std::fs::create_dir_all(&dir);
    let body = serde_json::json!({ "panicString": "panic(cpu 0 caller 0xffffff8012): x86 CPU CATERR detected\n" });
    let ips = format!(
        "{}\n{}",
        r#"{"bug_type":"210","timestamp":"2026-07-16 08:00:00.00 -0400","name":"kernel"}"#, body
    );
    std::fs::write(dir.join("Kernel-2026-07-16-080000.panic.ips"), ips).unwrap();
    let cats: HashSet<crate::report::Category> =
        crate::report::Category::ALL.iter().copied().collect();
    let since = chrono::Utc::now() - chrono::Duration::days(1);
    let res = crate::files::scan(std::slice::from_ref(&dir), since, chrono::Utc::now(), &cats);
    let _ = std::fs::remove_dir_all(&dir);
    let panic = res
        .findings
        .iter()
        .find(|f| f.rule_id == "file.kernel_panic")
        .expect("panic finding");
    assert!(panic
        .detail
        .contains("Points to: Intel CPU / logic board (CATERR) (likely hardware)"));
    assert!(panic
        .evidence
        .iter()
        .any(|e| e.source == "panic classifier" && e.excerpt.starts_with("hardware-suspect")));
    assert!(panic
        .next_step
        .as_deref()
        .unwrap_or("")
        .contains("Apple Diagnostics"));
}

#[test]
fn disk_identity_parsing() {
    let info = "   Device / Media Name:       APPLE SSD AP0512Z\n   Protocol:                  Apple Fabric\n   Disk Size:                 500.3 GB (500277792768 Bytes) (exactly 977105064 512-Byte-Units)\n";
    assert_eq!(
        crate::host::parse_disk_identity(info),
        "APPLE SSD AP0512Z · 500.3 GB"
    );
    assert_eq!(crate::host::parse_disk_identity(""), "");
}

#[test]
fn hardware_category_and_rules_registered() {
    use clap::ValueEnum;
    assert_eq!(
        crate::report::Category::from_str("hardware", true),
        Ok(crate::report::Category::Hardware)
    );
    assert!(crate::report::Category::ALL.contains(&crate::report::Category::Hardware));
    let ids: Vec<&str> = crate::rules::RULES.iter().map(|r| r.id).collect();
    for must in [
        "snap.ssd_wear",
        "snap.charger",
        "snap.input_devices",
        "snap.input_controller",
        "snap.lid_angle",
    ] {
        assert!(ids.contains(&must), "catalog missing {must}");
    }
}

#[test]
fn pre_0_11_baseline_still_loads() {
    let old = r#"{"captured_at":"2026-09-01T12:00:00Z","macos_build":"26A428","loaded_kexts":[],"sysexts":[],"launch_items":[],"install_count":3,"last_install":null,"disk_pct_full":41,"snapshot_count":2,"sip_enabled":true,"gatekeeper_enabled":true,"filevault_on":true}"#;
    let b: crate::baseline::Baseline = serde_json::from_str(old).expect("old baseline loads");
    assert_eq!(b.ssd_percent_used, None);
    assert_eq!(b.battery_cycles, None);
    assert_eq!(b.battery_max_capacity_pct, None);
}

#[test]
fn pre_0_11_report_host_still_loads() {
    let host = r#"{"model":"Mac17,3","chip":"Apple M5","memory_gb":24,"macos_version":"27.0","macos_build":"26A428","arch":"aarch64","uptime":"1h","root":false}"#;
    let h: crate::report::HostInfo = serde_json::from_str(host).expect("old host loads");
    assert_eq!(h.machine(), "Mac17,3");
    assert_eq!(h.storage_suffix(), "");
}

// ── v0.11.1 false-positive fixes (2026-09-30 field run) ─────────────────────

fn write_309(
    dir: &std::path::Path,
    file: &str,
    proc_name: &str,
    exc: &str,
    indicator: &str,
    when: &str,
) {
    let header = format!(
        r#"{{"bug_type":"309","timestamp":"{when}.00 -0400","app_name":"{proc_name}","name":"{proc_name}"}}"#
    );
    let body = serde_json::json!({
        "procName": proc_name,
        "exception": { "type": exc },
        "termination": { "indicator": indicator }
    });
    std::fs::write(dir.join(file), format!("{header}\n{body}")).unwrap();
}

fn scan_dir(dir: &std::path::Path) -> Vec<Finding> {
    use std::collections::HashSet;
    let cats: HashSet<crate::report::Category> =
        crate::report::Category::ALL.iter().copied().collect();
    let since = chrono::Utc::now() - chrono::Duration::days(3650);
    let res = crate::files::scan(&[dir.to_path_buf()], since, chrono::Utc::now(), &cats);
    crate::correlate::run(res.findings, &[], &[], &[])
}

#[test]
fn exc_user_fault_reports_are_not_crashes() {
    let dir = std::env::temp_dir().join("mactriage-test-userfault");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Five fault snapshots inside 4 minutes — the shape that produced a false
    // "nsattributedstringagent is crash-looping" High.
    for (i, t) in ["14:14:18", "14:15:02", "14:16:49", "14:17:10", "14:17:42"]
        .iter()
        .enumerate()
    {
        write_309(
            &dir,
            &format!("ExcUserFault_nsattributedstringagent-2026-09-30-14170{i}.ips"),
            "nsattributedstringagent",
            "EXC_GUARD",
            "Application Triggered Fault",
            &format!("2026-09-30 {t}"),
        );
    }
    let findings = scan_dir(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!findings
        .iter()
        .any(|f| f.rule_id == "correlate.crash_loop" || f.rule_id == "file.crash"));
    let faults: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.rule_id == "file.user_fault")
        .collect();
    assert_eq!(faults.len(), 1, "fault snapshots merge into one row");
    assert_eq!(faults[0].severity, Severity::Info);
    assert_eq!(faults[0].count, 5);
    assert!(faults[0].summary.contains("kept running"));
}

#[test]
fn real_crash_burst_still_loops_and_faults_stay_out_of_it() {
    let dir = std::env::temp_dir().join("mactriage-test-realloop");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for (i, t) in ["10:00:00", "10:10:00", "10:20:00"].iter().enumerate() {
        write_309(
            &dir,
            &format!("Widget-2026-09-30-10{i}000.ips"),
            "Widget",
            "EXC_BAD_ACCESS",
            "Segmentation fault: 11",
            &format!("2026-09-30 {t}"),
        );
    }
    write_309(
        &dir,
        "ExcUserFault_Widget-2026-09-30-103000.ips",
        "Widget",
        "EXC_GUARD",
        "Application Triggered Fault",
        "2026-09-30 10:30:00",
    );
    let findings = scan_dir(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    let lp = findings
        .iter()
        .find(|f| f.rule_id == "correlate.crash_loop")
        .expect("3 crashes in 20 min is a loop");
    assert_eq!(lp.count, 3, "the fault snapshot is not a crash");
    assert!(lp.detail.contains("including a tight burst"));
    assert!(findings.iter().any(|f| f.rule_id == "file.user_fault"));
}

#[test]
fn evenly_spaced_crashes_are_recurring_not_a_loop() {
    // jamfRemoteAssistConnector: a segfault every 8 h, 6 of them over 2 days.
    let dir = std::env::temp_dir().join("mactriage-test-periodic");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let times = [
        "2026-09-28 01:37:15",
        "2026-09-28 09:36:05",
        "2026-09-28 17:36:42",
        "2026-09-29 01:37:15",
        "2026-09-29 09:37:43",
        "2026-09-29 17:38:32",
    ];
    for (i, t) in times.iter().enumerate() {
        write_309(
            &dir,
            &format!("jamfRemoteAssistConnector-{i}.ips"),
            "jamfRemoteAssistConnector",
            "EXC_BAD_ACCESS",
            "Segmentation fault: 11",
            t,
        );
    }
    let findings = scan_dir(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !findings.iter().any(|f| f.rule_id == "correlate.crash_loop"),
        "8-hourly crashes are not a loop"
    );
    let rec = findings
        .iter()
        .find(|f| f.rule_id == "file.crash")
        .expect("recurring crash finding");
    assert_eq!(rec.severity, Severity::Medium);
    assert_eq!(rec.count, 6);
    assert!(rec.summary.contains("not a tight loop"));

    // Positive control: 5 crashes inside 24 h (hours apart) is still a loop.
    let dir = std::env::temp_dir().join("mactriage-test-day-burst");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for (i, h) in ["02", "06", "10", "14", "18"].iter().enumerate() {
        write_309(
            &dir,
            &format!("Daemon-{i}.ips"),
            "Daemon",
            "EXC_BAD_ACCESS",
            "Segmentation fault: 11",
            &format!("2026-09-29 {h}:00:00"),
        );
    }
    let findings = scan_dir(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(findings.iter().any(|f| f.rule_id == "correlate.crash_loop"));
}

fn spotlight_member(rule: &str, process: Option<&str>, sev: Severity) -> Finding {
    let mut f = Finding::new(rule, sev, "x", &format!("{rule} {}", process.unwrap_or("")));
    f.process = process.map(String::from);
    f
}

#[test]
fn spotlight_stack_needs_memory_kills_or_an_error_flood() {
    let with_count = |mut f: Finding, n: u32| {
        f.count = n;
        f
    };
    // 2026-09-30 field shape: 23 substantive mds errors, spotlightknowledged
    // CPU reports ×14, one each from suggestd and media-indexer, plus an
    // unrelated recurring non-indexer process.
    let routine = vec![
        with_count(spotlight_member("log.spotlight", None, Severity::Low), 23),
        with_count(
            spotlight_member(
                "file.cpu_resource",
                Some("spotlightknowledged"),
                Severity::Medium,
            ),
            14,
        ),
        spotlight_member("file.cpu_resource", Some("suggestd"), Severity::Medium),
        spotlight_member("file.cpu_resource", Some("media-indexer"), Severity::Medium),
        with_count(
            spotlight_member(
                "file.cpu_resource",
                Some("signpost_reporter"),
                Severity::Medium,
            ),
            4,
        ),
    ];
    let out = crate::correlate::run(routine.clone(), &[], &[], &[]);
    assert!(
        !out.iter().any(|f| f.rule_id == "correlate.spotlight_stack"),
        "background indexing is not a story"
    );
    let skd = out
        .iter()
        .find(|f| f.process.as_deref() == Some("spotlightknowledged"))
        .unwrap();
    assert_eq!(
        skd.severity,
        Severity::Info,
        "Apple's scheduled indexing bursts are informational"
    );
    assert!(skd
        .next_step
        .as_deref()
        .unwrap()
        .starts_with("No action unless"));
    let other = out
        .iter()
        .find(|f| f.process.as_deref() == Some("signpost_reporter"))
        .unwrap();
    assert_eq!(
        other.severity,
        Severity::Medium,
        "non-indexer recurrence rule unaffected"
    );

    // An error flood (substantive errors > 50) is a Medium index story.
    let mut flood = routine.clone();
    flood[0].count = 60;
    let out = crate::correlate::run(flood, &[], &[], &[]);
    let stack = out
        .iter()
        .find(|f| f.rule_id == "correlate.spotlight_stack")
        .expect("flood forms a story");
    assert_eq!(stack.severity, Severity::Medium);
    assert!(stack
        .next_step
        .as_deref()
        .unwrap()
        .starts_with("Test search"));

    // Memory kills of an indexer: High with the rebuild advice.
    let mut thrashing = routine;
    thrashing.push(spotlight_member(
        "file.jetsam",
        Some("spotlightknowledged"),
        Severity::Medium,
    ));
    let out = crate::correlate::run(thrashing, &[], &[], &[]);
    let stack = out
        .iter()
        .find(|f| f.rule_id == "correlate.spotlight_stack")
        .unwrap();
    assert_eq!(stack.severity, Severity::High);
    assert!(stack.next_step.as_deref().unwrap().contains("mdutil -E"));
}

#[test]
fn spotlight_log_ignores_routine_mds_churn() {
    let rule = crate::logscan::LOG_RULES
        .iter()
        .find(|r| r.id == "log.spotlight")
        .unwrap();
    assert!(!(rule.matches)(
        "mds",
        "fetchQueryResultsForTaskID Got connection error"
    ));
    assert!(!(rule.matches)("mds", "_oidParentForOid:744: stat succeeded, getattrlist returned error  2 for 23124215 (<private> = <private>)"));
    // Positive controls: substantive index errors still count.
    assert!((rule.matches)(
        "mds_stores",
        "_ContentIndexSyncIndexBulk:2331: Sync sync error: 22"
    ));
    assert!((rule.matches)(
        "mds_stores",
        "_SIShutdownIndex:6012: <si:cs_default> - setDir 3 error 1 ((null))"
    ));
}

#[test]
fn gatekeeper_ignores_quic_flow_control_counters() {
    use crate::logscan::gatekeeper_denial;
    let quic = "quic_conn_log_summary [C12.1.1.1:2] [-6f2b4bb3ed] \n\tConnection attempts: 1, RETRY received: no, PTOs: 0\n\tDATA_BLOCKED frames sent/received: 0/0\n\tSTREAM_DATA_BLOCKED frames sent/received: 0/0";
    assert!(!gatekeeper_denial("syspolicyd", &quic.to_lowercase()));
    // Positive control: a real denial still matches.
    assert!(gatekeeper_denial(
        "syspolicyd",
        &"Prompt shown (7, 0), denied launch of /Applications/Foo.app".to_lowercase()
    ));
    assert!(!gatekeeper_denial("kernel", "denied"));
}

#[test]
fn keychain_severity_counts_only_real_auth_failures() {
    use crate::logscan::keychain_verdict;
    let locked = "Self Service+ Ag[20210]/1#5 LF=1 add Error Domain=NSOSStatusErrorDomain Code=-25308 \"ks_crypt: e00002e2 failed to 'od' item (class 6, bag: 0) Access to item attempted while keychain is locked.\"";
    let teams = "MSTeams[20447]/1#22 LF=0 copy_matching Error Domain=NSOSStatusErrorDomain Code=-34018 \"Client explicitly specifies access group UBF8T346G9.com.microsoft.workplacejoin.v2 but is only entitled for (\"";
    let mut field_run: Vec<&str> = vec![locked; 386];
    field_run.extend([teams, teams]);
    let (sev, detail, next) = keychain_verdict(&field_run);
    assert_eq!(
        sev,
        Severity::Low,
        "386 locked-bag + 2 entitlement errors is not a keychain problem"
    );
    assert!(detail.contains("2 missing-entitlement error(s) (-34018) from MSTeams"));
    assert!(detail.contains("386 access attempt(s) while the keychain was locked"));
    assert!(next.starts_with("No keychain repair needed"));
    assert!(!next.contains("out of sync"));
    // Positive control: a flood of wrong-password failures is still Medium.
    let auth = "securityd: SecKeychainUnlock failed: -25293 The user name or passphrase you entered is not correct";
    let (sev, _, next) = keychain_verdict(&vec![auth; 21]);
    assert_eq!(sev, Severity::Medium);
    assert!(next.contains("out of sync"));
}

// ── v0.11.3: thermal episodes, Time Machine deferrals (2026-09-30 sudo run) ──

/// The 13 messages the old thermal rule matched on this Mac in 6 h: one
/// elevation at 16:03:41 that several daemons echoed, its all-clear at
/// 16:06:38, camera-driver chatter, and a Podcasts level=0 poll.
fn thermal_field_run() -> Vec<(Option<chrono::DateTime<chrono::Utc>>, &'static str)> {
    use chrono::TimeZone;
    let t =
        |h: u32, m: u32, s: u32| Some(chrono::Utc.with_ymd_and_hms(2026, 9, 30, h, m, s).unwrap());
    vec![
        (t(17, 27, 57), "ICThermalMonitor: current thermal pressure level=0"),
        (t(20, 1, 0), "<<<< BWMultiStreamCameraSourceNode >>>> -[BWMultiStreamCameraSourceNode updateMLVNREnabledByThermalPressureOrPowerPressure]"),
        (t(20, 3, 41), "[Thermal] Thermal pressure rose to elevated level"),
        (t(20, 3, 41), "[Thermal] Thermal pressure rose to elevated level"),
        (t(20, 3, 41), "[Thermal] Thermal pressure state changed, is elevated: true"),
        (t(20, 3, 41), "[Thermal] Thermal pressure state changed, is elevated: true"),
        (t(20, 3, 41), "Limiting maximum active count due to thermal pressure"),
        (t(20, 3, 41), "Limiting maximum active count due to thermal pressure"),
        (t(20, 6, 38), "[Thermal] Thermal pressure dropped to nominal level"),
        (t(20, 6, 38), "[Thermal] Thermal pressure dropped to nominal level"),
        (t(20, 6, 38), "[Thermal] Thermal pressure state changed, is elevated: false"),
        (t(20, 6, 38), "[Thermal] Thermal pressure state changed, is elevated: false"),
    ]
}

#[test]
fn thermal_counts_one_episode_not_every_echo() {
    use crate::logscan::{thermal_elevated, thermal_verdict};
    let run = thermal_field_run();
    let kept: Vec<_> = run
        .iter()
        .copied()
        .filter(|(_, m)| thermal_elevated(m))
        .collect();
    assert_eq!(
        kept.len(),
        4,
        "only the 'rose to' / 'is elevated: true' records"
    );
    let (sev, summary, detail, next) = thermal_verdict(&kept);
    assert_eq!(
        sev,
        Severity::Low,
        "one 3-minute episode on a fanless Air is not Medium"
    );
    assert_eq!(
        summary,
        "Thermal pressure rose above nominal (1 episode(s))"
    );
    assert!(
        !detail.contains("limited to"),
        "no CPU_Speed_Limit was logged"
    );
    assert!(next.contains("on Macs with a fan"));
}

#[test]
fn thermal_speed_limits_and_frequent_episodes_still_escalate() {
    use crate::logscan::{thermal_elevated, thermal_verdict};
    use chrono::TimeZone;
    assert!(thermal_elevated("CPU_Speed_Limit \t= 60"));
    assert!(
        !thermal_elevated("CPU_Speed_Limit \t= 100"),
        "100 means not throttled"
    );
    let at = |m: u32| Some(chrono::Utc.with_ymd_and_hms(2026, 9, 30, 12, m, 0).unwrap());
    let (sev, summary, _, _) = thermal_verdict(&[(at(0), "CPU_Speed_Limit = 60")]);
    assert_eq!(sev, Severity::Medium);
    assert!(summary.contains("down to 60% speed"));
    assert_eq!(
        thermal_verdict(&[(at(0), "CPU_Speed_Limit = 40")]).0,
        Severity::High
    );
    // Ten separate episodes (6 minutes apart) are Medium.
    let ten: Vec<_> = (0..10)
        .map(|i| (at(i * 6), "Thermal pressure rose to moderate"))
        .collect();
    let (sev, summary, _, _) = thermal_verdict(&ten);
    assert_eq!(sev, Severity::Medium);
    assert!(summary.contains("10 episode(s)"));
}

#[test]
fn backup_deferral_is_not_a_backup_failure() {
    let backupd = crate::logscan::LOG_RULES
        .iter()
        .find(|r| r.id == "log.backupd")
        .unwrap();
    assert!(!(backupd.matches)(
        "backupd",
        "Backup failed: BACKUP_DELAYED_NOT_ENOUGH_ELAPSED_TIME (107)"
    ));
    // Positive control: a real failure still matches.
    assert!((backupd.matches)(
        "backupd",
        "Failed event collection with error: Error Domain=com.apple.backupd.ErrorDomain Code=18"
    ));
}

// ── v0.11.4: sleep-blocker attribution, Bluetooth retries, CPU-limit recurrence ──

#[test]
fn runningboardd_assertions_name_the_real_app() {
    use crate::power::assertion_holder;
    let powerd = r#"   pid 363(powerd): [0x00019bf400018262] 01:25:17 PreventUserIdleSystemSleep named: "Powerd - Prevent sleep while display is on""#;
    assert_eq!(assertion_holder(powerd).as_deref(), Some("powerd"));
    // Client strings as powerd logged them for runningboardd on 2026-09-30.
    let teams = r#"   pid 427(runningboardd): [0x0001b00000018aa1] 00:00:12 PreventUserIdleSystemSleep named: "app<application.com.microsoft.teams2.16170346.16172491(501)>427-20447-116022:com.apple.CFNetwork.StorageDB""#;
    assert_eq!(
        assertion_holder(teams).as_deref(),
        Some("com.microsoft.teams2 (via runningboardd)")
    );
    let backupd = r#"   pid 427(runningboardd): [0x0001b00000018aa2] 00:00:03 PreventUserIdleSystemSleep named: "osservice<com.apple.backupd>;427-850-93096:File Coordination Claim 6B9889E7(FinishTask)""#;
    assert_eq!(
        assertion_holder(backupd).as_deref(),
        Some("com.apple.backupd (via runningboardd)")
    );
    // Unrecognised name: fall back to the holder, never drop it.
    let opaque = r#"   pid 427(runningboardd): [0x0001] 00:00:01 PreventUserIdleSystemSleep named: "something else""#;
    assert_eq!(assertion_holder(opaque).as_deref(), Some("runningboardd"));
}

#[test]
fn bluetooth_single_device_retries_are_low() {
    use crate::logscan::bluetooth_verdict;
    let iphone = r#"Connection failed to device "BB247BF2-5345-3257-3C0D-C2FF1EF21EA3", Retrying"#;
    let (sev, summary, detail, next) = bluetooth_verdict(&vec![iphone; 65]);
    assert_eq!(sev, Severity::Low);
    assert_eq!(summary, "Bluetooth keeps retrying one device (65 attempts)");
    assert!(detail.contains("Continuity"));
    assert!(next.starts_with("No action unless"));
    // Positive control: failures across two devices are still Medium.
    let other = r#"Connection failed to device "0A1B2C3D-0000-1111-2222-333344445555", Retrying"#;
    let mut two = vec![iphone; 13];
    two.extend(vec![other; 12]);
    let (sev, summary, _, _) = bluetooth_verdict(&two);
    assert_eq!(sev, Severity::Medium);
    assert!(summary.contains("25 events, 2 device(s)"));
    // One device timing out (not retrying) is not assumed benign.
    let timeouts =
        vec![r#"LE connection timeout for device "BB247BF2-5345-3257-3C0D-C2FF1EF21EA3""#; 25];
    assert_eq!(bluetooth_verdict(&timeouts).0, Severity::Medium);
}

#[test]
fn cpu_limit_reports_are_low_unless_recurring() {
    let one = |p: &str| {
        let mut f = Finding::new(
            "file.cpu_resource",
            Severity::Medium,
            "resource_abuse",
            &format!("{p} exceeded its CPU usage limit"),
        );
        f.process = Some(p.into());
        f
    };
    let mut input = vec![one("fileproviderd"), one("Perplexity")];
    input.extend((0..4).map(|_| one("signpost_reporter")));
    let out = crate::correlate::run(input, &[], &[], &[]);
    let get = |p: &str| {
        out.iter()
            .find(|f| f.rule_id == "file.cpu_resource" && f.process.as_deref() == Some(p))
            .unwrap()
    };
    assert_eq!(get("fileproviderd").severity, Severity::Low);
    assert_eq!(get("Perplexity").severity, Severity::Low);
    let rec = get("signpost_reporter");
    assert_eq!(rec.severity, Severity::Medium);
    assert_eq!(
        rec.summary,
        "signpost_reporter exceeded its CPU usage limit 4 times"
    );
}
