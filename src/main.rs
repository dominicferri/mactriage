//! mactriage — severity-ranked triage of macOS crashes, panics, hangs, and
//! performance problems.

mod audit;
mod baseline;
mod boot;
mod correlate;
mod files;
mod hardware;
mod host;
mod html;
mod lidangle;
mod logscan;
mod netcheck;
mod power;
mod progress;
mod protocol;
mod recovery;
mod render;
mod report;
mod rules;
mod scan;
mod security;
mod storage;
#[cfg(test)]
mod tests;
mod tui;
mod util;
mod watch;

use clap::{Args, Parser, Subcommand};
use progress::{CancellationToken, Progress};
use report::{Report, Severity};
use scan::{ScanOpts, SecurityOpts, SnapshotOpts};

/// Scans DiagnosticReports, the unified log, live system vitals, launch items,
/// kext inventory, security posture, battery, network, and backups for anything
/// that crashed, panicked, hung, or is degrading performance, then prints a
/// severity-ranked triage report.
///
/// Run with sudo for full coverage (kernel panic record, all users' reports,
/// powermetrics thermal sampling, Wi-Fi quality, background-item audit).
///
/// Exit codes: 0 healthy, 10/20/30/40 = worst finding is low/medium/high/fatal,
/// 2 usage, 70 internal error.
#[derive(Parser)]
#[command(name = "mactriage", version, max_term_width = 100)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[command(flatten)]
    scan: ScanOpts,
}

#[derive(Subcommand)]
enum Command {
    /// Scan everything and print the triage report (the default when no subcommand is given)
    Scan(ScanOpts),
    /// Instant "is it sick right now" check: live vitals only, no history
    Snapshot(SnapshotOpts),
    /// Security audit: firewall, Wi-Fi encryption, remote access, DNS/hosts,
    /// updates, screen lock, MDM/Jamf state, trusted certs (read-only)
    Security(SecurityOpts),
    /// Open the interactive terminal dashboard
    Ui(tui::UiOpts),
    /// List every detection rule: id, category, severity, source
    Rules,
    /// Save an inventory baseline (kexts, launch items, posture, disk) to diff against later
    Baseline,
    /// Compare the current inventory against the saved baseline: what changed since it worked?
    Diff,
    /// Periodic background scan via launchd; notifies on new findings
    Watch(WatchOpts),
    #[command(name = "__worker", hide = true)]
    Worker(protocol::WorkerOpts),
}

#[derive(Args)]
struct WatchOpts {
    #[command(subcommand)]
    action: WatchAction,
}

#[derive(Subcommand)]
enum WatchAction {
    /// Install a user LaunchAgent that scans periodically and notifies on new findings
    Install {
        /// How often to scan (e.g. 30m, 6h)
        #[arg(long, default_value = "6h")]
        interval: String,
        /// Notify only for new findings at or above this severity
        #[arg(long, value_enum, default_value = "high")]
        min_severity: Severity,
    },
    /// Unload and archive the LaunchAgent
    Uninstall,
    /// Show whether the watch LaunchAgent is installed, loaded, and when it last ran
    Status,
    /// Run one watch iteration (what the LaunchAgent executes)
    #[command(hide = true)]
    Run {
        #[arg(long, value_enum, default_value = "high")]
        min_severity: Severity,
    },
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        None => run_scan_cli(cli.scan),
        Some(Command::Scan(opts)) => run_scan_cli(opts),
        Some(Command::Snapshot(opts)) => run_snapshot_cli(opts),
        Some(Command::Security(opts)) => {
            let report = scan::collect_security(&Progress::new(true));
            output(
                &report,
                opts.json,
                opts.html.as_deref(),
                opts.verbose,
                false,
                opts.no_color,
            )
        }
        Some(Command::Ui(opts)) => match tui::run(opts) {
            Ok(code) => code,
            Err(error) => {
                eprintln!("mactriage: {error}");
                70
            }
        },
        Some(Command::Rules) => {
            println!("{}", rules::table());
            0
        }
        Some(Command::Baseline) => match baseline::save(&baseline::capture(util::is_root())) {
            Ok(path) => {
                println!("baseline saved: {}", path.display());
                0
            }
            Err(error) => {
                eprintln!("mactriage: could not save baseline: {error}");
                70
            }
        },
        Some(Command::Diff) => match baseline::diff(util::is_root()) {
            Ok(text) => {
                print!("{text}");
                0
            }
            Err(error) => {
                eprintln!("mactriage: {error}");
                70
            }
        },
        Some(Command::Watch(watch_opts)) => run_watch(watch_opts),
        Some(Command::Worker(worker_opts)) => protocol::run_worker(worker_opts),
    };
    std::process::exit(code);
}

fn run_scan_cli(opts: ScanOpts) -> i32 {
    let progress = if opts.verbose >= 2 {
        Progress::disabled()
    } else {
        Progress::new(true)
    };
    let cancel = CancellationToken::default();
    match scan::collect_scan(&opts, &progress, &cancel) {
        Ok(run) => output(
            &run.report,
            opts.json,
            opts.html.as_deref(),
            opts.verbose,
            opts.quiet,
            opts.no_color,
        ),
        Err(error) => {
            eprintln!("mactriage: {}", error.message);
            error.code
        }
    }
}

fn run_snapshot_cli(opts: SnapshotOpts) -> i32 {
    let progress = Progress::new(true);
    let cancel = CancellationToken::default();
    let run = scan::collect_snapshot(&opts, &progress, &cancel);
    output(
        &run.report,
        opts.json,
        None,
        opts.verbose,
        false,
        opts.no_color,
    )
}

fn run_watch(opts: WatchOpts) -> i32 {
    match opts.action {
        WatchAction::Install {
            interval,
            min_severity,
        } => match watch::install(&interval, min_severity) {
            Ok(message) => {
                println!("{message}");
                0
            }
            Err(error) => {
                eprintln!("mactriage: {error}");
                70
            }
        },
        WatchAction::Uninstall => match watch::uninstall() {
            Ok(message) => {
                println!("{message}");
                0
            }
            Err(error) => {
                eprintln!("mactriage: {error}");
                70
            }
        },
        WatchAction::Status => {
            println!("{}", watch::status());
            0
        }
        WatchAction::Run { min_severity } => watch::run_once(min_severity),
    }
}

fn output(
    report: &Report,
    json: bool,
    html_path: Option<&str>,
    verbose: u8,
    quiet: bool,
    no_color: bool,
) -> i32 {
    if let Some(path) = html_path {
        match write_new_private(path, &html::render(report)) {
            Ok(()) => eprintln!("html report written: {path}"),
            Err(error) => {
                eprintln!("mactriage: cannot write html report to {path}: {error}");
                return 70;
            }
        }
    }
    if json {
        match serde_json::to_string_pretty(report) {
            Ok(json) => println!("{json}"),
            Err(error) => {
                eprintln!("mactriage: json serialization failed: {error}");
                return 70;
            }
        }
    } else {
        let style = render::Style::new(no_color);
        print!("{}", render::render(report, &style, verbose, quiet));
    }
    report.exit_code()
}

/// Create `path` as a new 0600 file. Refuses an existing path or a symlink, so
/// a run under sudo can't be pointed at a file it should not overwrite.
fn write_new_private(path: &str, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if std::fs::symlink_metadata(path).is_ok() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "the path already exists (refusing to overwrite it or follow a symlink)",
        ));
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?
        .write_all(text.as_bytes())
}
