<p align="center"><img src="docs/images/banner.svg" alt="mactriage" width="100%"></p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-macOS%2012%2B-F4BD47?style=flat-square&logo=apple&logoColor=white&labelColor=000000" alt="Platform: macOS 12 or later">
  <img src="https://img.shields.io/badge/language-Rust-C00027?style=flat-square&logo=rust&logoColor=white&labelColor=000000" alt="Language: Rust">
  <img src="https://img.shields.io/badge/version-0.12.0-F4BD47?style=flat-square&labelColor=000000" alt="Version 0.12.0">
  <img src="https://img.shields.io/badge/mode-read--only-C00027?style=flat-square&labelColor=000000" alt="Mode: read-only">
</p>

mactriage is a read-only command-line tool for Mac support work. It reads the crash reports, panic records, unified log, and live state that macOS already keeps. It then shows one list of problems, sorted by severity, with a next step for each problem.

<p align="center">
  <img src="docs/images/report.png" width="760" alt="The mactriage HTML report for a demo Mac. The overall condition is SERIOUS. The report shows six vitals, the recovery decision NO ERASE NEEDED, and a High finding for a boot volume that is 96% full.">
</p>
<p align="center"><sub>The HTML report from a demo scan. This image shows invented data only.</sub></p>

**Contents:** [Quick start](#quick-start) · [What it checks](#what-it-checks) · [What it changes](#what-it-changes) · [Reading the report](#reading-the-report) · [More detail](#more-detail) · [History](#history)

## Quick start

You need macOS 12 or later, Rust (stable), and the Xcode command-line tools. Clone this repository. Open Terminal in the repository folder.

### MacSecurity.app

```
./build-app.sh security
open dist/build/MacSecurity.app
```

The app opens Terminal and runs the security audit. Type your administrator password for full coverage. Press Ctrl-C at the password prompt to run the audit without root. The app writes the HTML report to `~/Library/Logs/MacSecurity/`.

The `mactriage` binary runs on macOS 12 and later. The app launcher is different: `osacompile` writes the macOS version of the build Mac into it as its minimum version. Build the app on the oldest macOS version that you must support.

### The command-line tool

```
cargo install --path .
```

This command installs the binary to `~/.cargo/bin/mactriage`.

### Commands to start with

```
mactriage                 # full scan: 6h of unified log, 7d of reports, live vitals, audits
sudo mactriage            # same scan with full coverage (see "Running as root")
mactriage ui              # interactive dashboard in Terminal
mactriage snapshot        # live vitals only, finishes in seconds
mactriage security        # read-only security audit
mactriage --no-log        # fast mode: skip the unified log
mactriage --html r.html   # also write a self-contained HTML report (new file, mode 0600)
mactriage --json          # machine-readable output (schema_version 2)
```

<details>
<summary><b>More commands and options</b></summary>

```
mactriage --only hardware --no-log   # SSD wear, battery and charger, keyboard and trackpad
mactriage rules                      # list every detection rule
mactriage baseline                   # save an inventory of this Mac while it works
mactriage diff                       # show what changed since the baseline
mactriage watch install              # scan every 6h in the background, notify on new problems
```

| Option | What it does |
|---|---|
| `--last 24h` | Sets how much of the unified log to read. The default is `6h`. |
| `--files-last 14d` | Sets how far back to read crash and panic reports. The default is `7d`. |
| `--from "2026-07-01 08:30" --to ...` | Scans a fixed time range instead. |
| `--only <cat>` / `--skip <cat>` | `--only` limits the scan to the named categories. `--skip` removes them from the scan. |
| `--min-severity medium` | Hides findings below this level. |
| `--timeout 900` | Sets the upper limit in seconds for the unified-log pass. The default is `600`. |
| `--full` | Shows every finding. By default, the terminal report shows 10 findings per category. |
| `-v` / `-vv` | `-v` shows evidence lines. `-vv` shows timing and skipped checks on stderr. |

Run `mactriage --help` for the full list of categories and options.

</details>

## What it checks

| Area | What mactriage checks |
|---|---|
| **Crash and panic reports** | Kernel panics with a likely cause, app crashes, hangs, jetsam kills, CPU and wakeup limits, GPU restarts, shutdown stalls |
| **Unified log: system** | Shutdown causes, watchdog timeouts, thermal throttling, disk and APFS errors, GPU resets, launchd service crashes |
| **Unified log: devices** | Kext load failures, USB and Thunderbolt over-current, sleep and wake failures, Wi-Fi disconnects, Bluetooth retries |
| **Unified log: services** | Spotlight errors, Software Update failures, Time Machine errors |
| **Vitals** | Memory pressure and swap, the top memory user, CPU load, free disk space, uptime |
| **Hardware** | SSD wear, battery capacity and cycle count, the charger, the built-in keyboard and trackpad and their controller, the lid angle sensor, Bluetooth input battery level |
| **Power** | Apps and services that prevent sleep |
| **Network** | Default route, gateway, DNS, Wi-Fi signal quality |
| **Storage and backups** | APFS local snapshots, purgeable space, the age of the last Time Machine backup |
| **Launch items and kexts** | Broken LaunchAgents and LaunchDaemons, background items without an owner, third-party kexts, install history |
| **Security** | SIP, Gatekeeper, FileVault, firewall, XProtect, sharing, network listeners, SSH, DNS, `/etc/hosts`, updates, screen lock, MDM, Jamf, certificates, boot arguments, UID 0 accounts |

After the checks, mactriage joins related findings into one finding. A full scan ends with a recovery assessment: does the evidence support an erase of this Mac?

## What it changes

mactriage only reads. It does not delete files, change settings, start Recovery, or touch firmware. It writes only its own state: a baseline file, watch state, and the reports you ask for.

## Reading the report

Each finding has one of five levels:

| Level | Meaning |
|---|---|
| Fatal | The Mac itself stopped: kernel panic, watchdog, thermal, or power shutdown |
| High | Something important is broken or close to failure |
| Medium | A real problem that affects use |
| Low | Worth knowing about, usually not urgent |
| Info | Context. Not counted against the Mac |

The report also gives the whole Mac one overall condition:

| Condition | Rule |
|---|---|
| CRITICAL | At least one Fatal finding |
| SERIOUS | At least one High finding |
| DEGRADED | At least one Medium finding |
| MINOR | Only Low findings |
| HEALTHY | A complete scan with no findings above Info |
| UNKNOWN | An incomplete scan with no findings above Info |

The exit code follows the worst finding: `0` healthy, `10` low, `20` medium, `30` high, `40` fatal. Code `2` is a usage error, and code `70` is an internal error. Scripts can use the exit code without parsing the output.

### When a scan is incomplete

A scan with zero findings is good news only if mactriage read every source. mactriage marks the scan incomplete when any of these events occur:

- `log show` fails, exits with an error, or reaches the timeout.
- A multi-hour log window returns zero lines.
- mactriage cannot read a report folder. The usual cause is missing Full Disk Access.

An incomplete scan shows a note in the terminal and HTML reports. In JSON, it sets `"complete": false`. Its condition is UNKNOWN, never HEALTHY.

## More detail

<details>
<summary><b>How a scan works</b></summary>

A full scan runs in five stages. The progress bar follows them. For the log stage, the bar shows how much of the time window mactriage has read.

#### 1. Diagnostic report files

mactriage reads `/Library/Logs/DiagnosticReports`, your own `~/Library/Logs/DiagnosticReports`, and the `Retired` folders inside them. As root, it also reads the folder of every user. It parses each report by its type:

| Report | What mactriage takes from it |
|---|---|
| Kernel panic (`.panic`, `.ips` type 210) | The panic string, the kernel extensions in the backtrace, and a cause class: hardware, firmware/coprocessor, or software |
| App crash (`.ips` type 309, `.crash`) | Process, exception type, signal, termination reason |
| Hang (`.hang`, `.spin`, `.ips` type 288) | The app that stopped responding |
| Jetsam (`.ips` type 298) | The processes that the kernel killed to free memory |
| CPU and wakeup limits (`.diag`) | Processes that ran too hot or woke the CPU too often |
| GPU restart, shutdown stall | Driver resets, and processes that delayed shutdown |

Some reports are not failures. An `ExcUserFault_*.ips` file is a fault snapshot from a process that continued to run. mactriage lists it as Info and never counts it as a crash.

#### 2. The unified log

This is the slow stage. mactriage runs `/usr/bin/log show` one time, with one combined predicate for every log rule. It streams the output as JSON lines. One pass is about ten times faster than one query per rule. On a busy Mac, a 6-hour window takes 2 to 5 minutes.

A classifier in Rust reads each matching line. The classifier removes known noise first. Examples are thermal messages that report the all-clear, and Spotlight errors for files deleted during the read. Time Machine "backup delayed" messages are noise too, and so are the lines that `log show` itself creates.

mactriage counts the remaining lines per rule, and the count sets the severity. Five thermal episodes are Low. Thirty are High.

The log rules cover shutdown causes, watchdog timeouts, thermal throttling, disk and APFS errors, GPU resets, and launchd service crashes. They also cover Spotlight errors, kext load failures, USB and Thunderbolt over-current, sleep and wake failures, and Wi-Fi disconnects. Bluetooth retries, Software Update failures, and Time Machine errors complete the list.

If the pass reaches `--timeout`, mactriage stops it and keeps the lines it already has. It then marks the scan incomplete.

#### 3. Live checks

These checks read the current state of the Mac. Most of them finish in less than one second each.

- **Vitals:** memory pressure and swap, the top memory user, CPU load, free disk space, and uptime.
- **Hardware:** SSD wear from the NVMe health log (through `smartctl`), and battery capacity and cycle count against the design rating. It also finds a charger that cannot supply enough power: the charger is connected, but the battery drains across two samples. It checks the built-in keyboard and trackpad. A laptop whose keyboard or trackpad is missing from the I/O registry gets a finding. A nonzero critical-error status from the keyboard/trackpad controller also gets a finding; a healthy Mac reads 0x0. On Apple silicon laptops it reads the lid angle sensor and flags a sensor that reads almost shut while the lid switch reports open. These checks do not run when the lid is closed. Bluetooth keyboards, mice, and trackpads at 10% battery or less also get a finding.
- **Power:** sleep preventers from `pmset -g assertions`. When `runningboardd` holds an assertion for an app, mactriage names the app, not `runningboardd`.
- **Network:** default route, gateway reachability, DNS, and Wi-Fi signal quality on the real Wi-Fi port.
- **Storage and backups:** APFS local snapshots, purgeable space, and the age of the last Time Machine backup.

#### 4. Audits

- **Launch items:** LaunchAgents and LaunchDaemons that point to a missing program. As root, mactriage also finds background items in the macOS Background Task Management database that have no owner. It lists every third-party item with the program that the item runs. An item counts as Apple's only when its program carries Apple's own signature. As root, mactriage reads the LaunchAgents folder of every user.
- **Kernel extensions:** the loaded third-party kexts. mactriage keeps this list for the correlation stage.
- **Install history:** each install and its date.
- **Posture:** SIP, Gatekeeper, FileVault, the firewall, XProtect updates, and MDM profiles.
- **Security:** the firewall and its app exceptions, Wi-Fi encryption, sharing services, network listeners, SSH password login, and changes to DNS and `/etc/hosts`. Also pending updates, screen lock, MDM and Jamf state, trusted certificates, boot arguments, writable root daemons, and extra UID 0 accounts. `mactriage security` runs this part alone.

#### 5. Correlation

The next section explains this stage.

</details>

<details>
<summary><b>How related findings join</b></summary>

A raw list of findings is hard to read. One broken app can produce twenty lines. The correlator joins related findings into one finding, in this order:

1. **Repeats:** the same rule from the same process becomes one finding. That finding has a count, a first time, and a last time.
2. **Crash loop:** a process that crashed 3 or more times in 60 minutes, or 5 or more times in 24 hours, becomes one High finding.
3. **Story:** two or more failure signals from one process become one finding with one fix. An example is a crash, a hang, and a launchd restart.
4. **Panic kext:** a kernel extension that a panic backtrace names and that is still loaded now. This is the strongest single cause that mactriage can identify.
5. **After an update:** when a group of findings starts shortly after an install, mactriage links the group to that install.

Then a boot filter runs. A log finding whose events all fall in the first 2 minutes after boot is usually normal startup work. The severity of that finding drops one level. Fatal findings never drop.

</details>

<details>
<summary><b>The recovery assessment</b></summary>

Full scans end with a recovery assessment. It answers one question: does the evidence support an erase of this Mac? A clean install costs data and time, so a severity score never decides the answer. The assessment checks the evidence in this order and stops at the first match:

| Order | Evidence | Recommendation |
|---|---|---|
| 1 | A panic that names a hardware fault (CATERR, machine check, ECC). A panic that names a firmware path (SEP, BridgeOS, SMC, ANS, DCP, AOP, RTKit). A failing SSD health log. Heavy disk I/O errors that SMART does not contradict. A shutdown that power or thermal hardware caused. | Firmware or hardware first. Make a backup. Run Apple Diagnostics. Then do a DFU Revive. An erase cannot fix this. |
| 2 | A loaded third-party kext that appears in a panic backtrace | Repair software first. Update or remove that product. Then test again. |
| 3 | Two or more kernel panics | Firmware or hardware first. A clean install is not yet justified. |
| 4 | An incomplete scan, or a scan without root, the unified log, or all categories | Collect more evidence. A clean install is blocked. |
| 5 | A crash loop, a multi-signal story, a broken launch item, or a failing service | Repair software first. Fix the named component. Test in Safe Mode and in a new user account. |
| 6 | Software Update failures, one kernel panic, or a system-wide watchdog, GPU, boot, or storage failure | Reinstall macOS without an erase. A clean install is not yet justified. |
| 7 | None of the above | No erase needed. |

Every assessment lists five gates. All five must be true before anyone considers an erase:

1. A test restore or a read of a current full backup was successful.
2. Apple Diagnostics passes, or a repair removed the hardware fault.
3. The problem occurs in Safe Mode.
4. The problem occurs in a new user account.
5. A macOS reinstall without an erase is complete, and the problem is still there.

A missing or old backup is a reason to stop. It is never a reason to continue. Snapshot and watch reports do not include this section. They do not read enough history to support the decision.

</details>

<details>
<summary><b>Running as root</b></summary>

Without sudo, mactriage still runs every check it can. It lists the other checks as Skipped. With sudo, it adds:

- the crash and panic reports of every user, not only yours
- the full kernel panic record
- `powermetrics` thermal sampling
- full Wi-Fi details
- the Background Task Management audit, which uses `sfltool dumpbtm`

`sfltool dumpbtm` hangs without root. For that reason, mactriage never runs it as a normal user.

The recovery assessment needs root and the full log pass. Without them, it returns "collect more evidence".

Also give your terminal app Full Disk Access (System Settings > Privacy & Security > Full Disk Access). Without it, some report folders and `tmutil` stay hidden. mactriage then marks the scan incomplete.

</details>

<details>
<summary><b>The security audit and MacSecurity.app</b></summary>

`mactriage security` checks settings only. It reads no logs and no report files, and it finishes in seconds. These rules control some of its decisions:

- **Network listeners:** a program counts as exposed when it listens on any address other than loopback. The real program path comes from the kernel, not from the process name. Thus a renamed process cannot pass the Apple check. mactriage checks Apple's own services with `codesign` against Apple's signature.
- **Sharing ports:** mactriage leaves ports 22, 445, 5900, 3031, and 3283 to the sharing check only when launchd or an Apple binary holds them.
- **Certificates:** a certificate with a name like the Jamf CA is Info only when it matches a certificate from an installed profile. Without that match, it is Low.
- **`/etc/hosts`:** a block of an Apple update, revocation, or notarization host is High. A block of any other Apple host is Medium.
- **Failed tools:** sometimes a tool such as `csrutil` or `security` gives no usable answer. Then the check shows as Skipped. It never shows as a pass.

Every system tool runs by its full path, and each tool has a time limit.

#### MacSecurity.app

`MacSecurity.app` opens Terminal and runs the audit from the binary inside the bundle. It writes the HTML report to `~/Library/Logs/MacSecurity/`. The folder is private to your account (mode 0700), and each report has mode 0600.

The app asks for your administrator password first. With the password, the audit runs as root. It then adds computer-level profiles, the Bootstrap Token, and the Jamf server check. Press Ctrl-C at the password prompt to skip the password. The audit then runs as your user with reduced coverage.

Before the app asks for the password, it checks its own code signature. If the check fails, the app does not ask, and it runs the reduced audit instead. Under sudo, root writes the report to a private temporary folder. Your own account then copies the report to the Logs folder. Thus root never writes into your home folder. The app clears the cached sudo password when it finishes.

`mactriage --html` creates a new file only. It refuses a path that already exists, and it never follows a symbolic link.

</details>

<details>
<summary><b>The dashboard</b></summary>

`mactriage ui` opens a terminal dashboard built with Ratatui. You select a profile (Full, Fast, or Snapshot) and watch the progress. You can cancel the scan safely at any time. The results have tabs for Summary, Findings, Recovery, Vitals, and Coverage, plus the full rule list. Page Up and Page Down scroll long panels. Press `?` for the full list of keys.

Export writes HTML or JSON and never overwrites an existing file. The first results screen lists every Fatal, High, Medium, and Low finding with its next step. The dashboard does not limit the number of findings per category. Info findings stay in the Findings tab.

The dashboard itself runs as you. When it needs root, it starts a separate scan worker with sudo. The dashboard and the worker communicate over a private JSON-lines channel on stdin and stdout. Only the read-only scanner runs as root. The dashboard and the files it exports stay owned by your user.

</details>

<details>
<summary><b>Baseline, diff, and watch</b></summary>

`mactriage baseline` saves an inventory of the Mac to `~/Library/Application Support/mactriage/baseline.json`. The inventory holds loaded kexts, launch items, security posture, disk use, and hardware wear. Save a baseline while the Mac works. If the Mac breaks later, `mactriage diff` shows what changed since then.

`mactriage watch install` adds a LaunchAgent for your user (no sudo). By default, it runs a fast scan of report files and live vitals every 6 hours. It compares the result with the last run. It sends a notification for each new finding at or above High. `--interval` and `--min-severity` change these two values.

`mactriage watch status` shows whether the watch is loaded and when it last ran. `mactriage watch uninstall` unloads the watch and archives the plist.

</details>

<details>
<summary><b>Output formats</b></summary>

- **Terminal:** color when the output is a TTY. `--no-color` and `NO_COLOR` disable the color.
- **HTML:** one self-contained file with no external assets. You can attach it to a ticket.
- **JSON:** `schema_version` 2. It includes the tool version, the scanned time window, the `complete` flag, and every finding with its evidence. It also holds the recovery assessment and `log_events` (every log line that matched a rule). New versions only add fields, so older consumers continue to work.

Reports never include serial numbers. mactriage does not read them from the battery, the SSD, or the system.

</details>

<details>
<summary><b>Build from source</b></summary>

You need Rust (stable) and the Xcode command-line tools.

```
cargo build --release          # native build
./build-universal.sh           # arm64 + x86_64 binary → target/universal/mactriage
cargo install --path .         # installs to ~/.cargo/bin/mactriage
cargo test                     # unit and fixture tests
./build-app.sh                 # dist/build/MacTriage.app
./build-app.sh security        # dist/build/MacSecurity.app: runs `mactriage security`
./build-app.sh security ~/Apps # same app, built into another folder
```

`MacTriage.app` is an AppleScript launcher. It opens Terminal and asks for your password with `sudo -v`. Then it starts the dashboard from the universal binary inside the bundle. Ctrl-C or three wrong passwords start the dashboard with reduced coverage instead. Like `MacSecurity.app`, it checks its own signature before it asks for a password.

The build signs the app ad hoc. For a signature that stays the same between builds, make a self-signed code-signing certificate in Keychain Access. Give it the name "MacTriage Dev". You do not need a paid Apple Developer account. On another Mac, a copy of the app needs one right-click > Open the first time.

#### smartctl

The SSD wear check needs `smartctl` from smartmontools. `MacTriage.app` includes a universal copy for macOS 12 and later. `dist/build-smartctl.sh` builds that copy from smartmontools 7.5 source with a pinned SHA-256 (GPL-2.0). The command-line tool searches for `smartctl` in these places, in this order, and never searches `PATH`:

1. `MACTRIAGE_SMARTCTL=/path/to/smartctl`
2. next to the mactriage binary
3. `/opt/homebrew/bin`, then `/usr/local/bin`

If mactriage finds no copy, the check shows as Skipped.

#### Testing against saved reports

Set `MACTRIAGE_REPORTS_DIR` to a folder of sample reports. mactriage then reads that folder instead of the system folders. The test suite uses this variable for its fixtures.

</details>

<details>
<summary><b>Source layout</b></summary>

| File | Job |
|---|---|
| `main.rs` | Command-line parsing |
| `scan.rs` | Runs the stages for full, snapshot, security, and watch scans |
| `files.rs` | Crash, panic, hang, and jetsam report parsing |
| `logscan.rs` | The unified-log pass and its classifiers |
| `host.rs`, `power.rs`, `hardware.rs` | Vitals, battery, charger, sleep blockers, SSD, input devices |
| `netcheck.rs`, `storage.rs` | Network health, snapshots, Time Machine |
| `audit.rs`, `security.rs` | Launch items, kexts, install history, posture, security audit |
| `correlate.rs` | Joins findings into crash loops, stories, and root causes |
| `recovery.rs` | The recovery assessment |
| `render.rs`, `html.rs`, `report.rs` | Terminal, HTML, and JSON output |
| `baseline.rs`, `watch.rs` | Baseline and diff, background watch |
| `protocol.rs`, `progress.rs` | Dashboard-to-worker channel, progress reports |
| `rules.rs` | The rule catalog that `mactriage rules` shows |

</details>

<details>
<summary><b>Rule list</b></summary>

There are 112 rules. The table splits the 39 security rules into three rows. `mactriage rules` prints each rule with its category, severity, source, and what it detects.

| Group | Count | Rule IDs |
|---|---|---|
| Report files | 14 | `file.kernel_panic`, `file.jetsam`, `file.crash`, `file.user_fault`, `file.hang`, `file.shutdown_stall`, `file.gpu_restart`, `file.cpu_resource`, `file.wakeups`, `file.sleep_wake_failure`, `file.reset_count`, `file.system_watchdog`, `file.force_reset`, `file.unknown_report` |
| Unified log | 19 | `log.shutdown_cause`, `log.crash_reported`, `log.jetsam`, `log.watchdog`, `log.thermal`, `log.io_errors`, `log.gpu_reset`, `log.launchd_services`, `log.spotlight`, `log.kext`, `log.usb_tb`, `log.sleep_wake`, `log.wifi`, `log.mdnsresponder`, `log.bluetooth`, `log.gatekeeper`, `log.keychain`, `log.software_update`, `log.backupd` |
| Live | 23 | `snap.memory_pressure`, `snap.swap_heavy`, `snap.thermal_throttle`, `snap.disk_full`, `snap.smart`, `snap.load`, `snap.top_procs`, `snap.top_mem`, `snap.windowserver`, `snap.apfs_snapshots`, `snap.tm_stale`, `snap.ssd_wear`, `snap.battery_health`, `snap.charger`, `snap.input_devices`, `snap.input_controller`, `snap.lid_angle`, `snap.power_assertions`, `snap.darkwake_storm`, `snap.net_offline`, `snap.gateway_down`, `snap.dns_failing`, `snap.wifi_quality` |
| Audit | 5 | `audit.launch_broken`, `audit.launch_inventory`, `audit.btm_orphan`, `audit.kext_inventory`, `audit.install_history` |
| Posture | 6 | `posture.sip_disabled`, `posture.gatekeeper_off`, `posture.filevault_off`, `posture.firewall_off`, `posture.xprotect_stale`, `posture.mdm_profiles` |
| Security: network | 17 | `sec.wifi_open`, `sec.wifi_weak`, `sec.wifi_unknown`, `sec.firewall_stealth_off`, `sec.firewall_allow_signed`, `sec.remote_access`, `sec.listener_exposed`, `sec.listener_apple`, `sec.internet_sharing`, `sec.dns_public`, `sec.proxy_set`, `sec.hosts_redirect`, `sec.hosts_block`, `sec.traffic_extensions`, `sec.firewall_exception_risky`, `sec.firewall_exception_stale`, `sec.ssh_weak_auth` |
| Security: system and accounts | 12 | `sec.auto_updates_off`, `sec.update_deferred`, `sec.screen_lock_weak`, `sec.autologin_on`, `sec.guest_enabled`, `sec.admin_accounts`, `sec.updates_pending`, `sec.update_scan_stale`, `sec.boot_args`, `sec.privileged_launch_writable`, `sec.uid0_extra`, `sec.root_enabled` |
| Security: MDM and trust | 10 | `sec.mdm_not_approved`, `sec.bootstrap_token`, `sec.jamf_broken`, `sec.jamf_unreachable`, `sec.profile_inventory`, `sec.managed_prefs`, `sec.custom_trust`, `sec.mdm_mismatch`, `sec.managed_extension_inactive`, `sec.jamf_checkin_stale` |
| Boot | 1 | `boot.slow_boot` |
| Correlation | 5 | `correlate.crash_loop`, `correlate.story`, `correlate.panic_kext`, `correlate.post_update`, `correlate.spotlight_stack` |

</details>

## History

The v0.1.0 source is lost. v0.2.0 is a full rewrite that kept the same rule IDs and command line. v0.3.0 fixed trust and correctness problems. Later versions added the dashboard, the recovery assessment, the security audit, and hardware checks. Since 0.11.1, most changes tune rules that raised false alarms on real Macs. Version 0.12.0 hardened the security audit and the app launchers. Version 0.13.0 checks the keyboard/trackpad controller and the lid angle sensor. See [CHANGELOG.md](CHANGELOG.md) for the reason behind each change.
