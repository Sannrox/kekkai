//! Per-job sandbox overhead: `prepare` + `apply` + spawn `/bin/true` + `finish`.
//!
//! Run with `cargo bench --bench overhead`. Compare a Linux runner against a
//! stored baseline with `--check crates/kekkai/benches/baseline-linux-x86_64.json`.
//! Scenarios the host cannot enforce print `skip:` and are omitted from the
//! report. They never count as a passing measurement.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use kekkai::{
    AllowHost, Backend, CgroupLimits, FilesystemView, Health, Limits, Namespaces, Network,
    OverlayPersist, Sandbox, Settings, SyscallProfile,
};
use serde::{Deserialize, Serialize};

fn resolve_path(raw: &str) -> PathBuf {
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        return path;
    }
    if path.exists() {
        return path;
    }
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    if manifest.join(&path).exists() {
        return manifest.join(path);
    }
    if let Some(rest) = raw.strip_prefix("crates/kekkai/") {
        return manifest.join(rest);
    }
    path
}

fn payload_path() -> &'static str {
    if Path::new("/bin/true").exists() {
        "/bin/true"
    } else if Path::new("/usr/bin/true").exists() {
        "/usr/bin/true"
    } else {
        panic!("need /bin/true or /usr/bin/true");
    }
}
const DEFAULT_SAMPLES: usize = 80;
const DEFAULT_WARMUP: usize = 10;
const THROUGHPUT_JOBS: usize = 50;
const PARALLEL_THREADS: usize = 4;
const REGRESSION: f64 = 1.20;
const RLIMIT_OVERHEAD_BUDGET: Duration = Duration::from_millis(2);
const FULL_STACK_OVERHEAD_BUDGET: Duration = Duration::from_millis(25);
const MIN_JOBS_PER_S: f64 = 50.0;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Report {
    schema_version: u32,
    scenarios: Vec<ScenarioReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScenarioReport {
    name: String,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    jobs_per_s: f64,
    jobs_per_s_parallel: f64,
    samples: usize,
}

struct Sampled {
    samples: Vec<Duration>,
    jobs_per_s: f64,
    jobs_per_s_parallel: f64,
}

fn main() {
    let opts = Opts::parse();
    let tmp = tempfile::tempdir().expect("bench workspace");
    let workspace = tmp.path().join("ws");
    fs::create_dir_all(&workspace).expect("create workspace");

    let mut scenarios: Vec<(&str, Option<Settings>)> = vec![
        ("unsandboxed", None),
        (
            "none",
            Some(Settings::builder().backend(Backend::None).build()),
        ),
        (
            "rlimit",
            Some(
                Settings::builder()
                    .backend(Backend::Rlimit)
                    .limits(Limits {
                        open_files: Some(1024),
                        ..Limits::default()
                    })
                    .build(),
            ),
        ),
        (
            "linux_native",
            Some(Settings::builder().backend(Backend::LinuxNative).build()),
        ),
        (
            "linux_native_namespaces",
            Some(
                Settings::builder()
                    .backend(Backend::LinuxNative)
                    .namespaces(Namespaces::Isolate)
                    .build(),
            ),
        ),
        (
            "linux_native_fs_view",
            Some(
                Settings::builder()
                    .backend(Backend::LinuxNative)
                    .namespaces(Namespaces::Isolate)
                    .filesystem_view(FilesystemView::Isolate {
                        overlay: OverlayPersist::Discard,
                    })
                    .build(),
            ),
        ),
        (
            "linux_native_loopback",
            Some(
                Settings::builder()
                    .backend(Backend::LinuxNative)
                    .namespaces(Namespaces::Isolate)
                    .network(Network::Loopback)
                    .build(),
            ),
        ),
        (
            "linux_native_allowlist",
            Some(
                Settings::builder()
                    .backend(Backend::LinuxNative)
                    .network(Network::Allowlist(vec![AllowHost {
                        host: "example.com".into(),
                        port: Some(443),
                    }]))
                    .build(),
            ),
        ),
        (
            "linux_native_cgroup",
            Some(
                Settings::builder()
                    .backend(Backend::LinuxNative)
                    .cgroup(CgroupLimits {
                        memory_max: Some(512 * 1024 * 1024),
                        ..CgroupLimits::default()
                    })
                    .build(),
            ),
        ),
        (
            "linux_native_syscall_strict",
            Some(
                Settings::builder()
                    .backend(Backend::LinuxNative)
                    .syscall_profile(SyscallProfile::Strict)
                    .build(),
            ),
        ),
        (
            "linux_native_full",
            Some(
                Settings::builder()
                    .backend(Backend::LinuxNative)
                    .namespaces(Namespaces::Isolate)
                    .filesystem_view(FilesystemView::Isolate {
                        overlay: OverlayPersist::Discard,
                    })
                    .cgroup(CgroupLimits {
                        memory_max: Some(512 * 1024 * 1024),
                        ..CgroupLimits::default()
                    })
                    .build(),
            ),
        ),
    ];

    let mut reports = Vec::new();
    let mut failed = false;
    for (name, settings) in scenarios.drain(..) {
        match measure(settings.as_ref(), &workspace, opts.warmup, opts.samples) {
            Ok(sampled) => {
                let report = ScenarioReport {
                    name: name.to_string(),
                    p50_ns: percentile_ns(&sampled.samples, 50),
                    p95_ns: percentile_ns(&sampled.samples, 95),
                    p99_ns: percentile_ns(&sampled.samples, 99),
                    jobs_per_s: sampled.jobs_per_s,
                    jobs_per_s_parallel: sampled.jobs_per_s_parallel,
                    samples: sampled.samples.len(),
                };
                eprintln!(
                    "{name}: p50={:.3}ms p95={:.3}ms p99={:.3}ms seq={:.1}/s par={:.1}/s n={}",
                    report.p50_ns as f64 / 1e6,
                    report.p95_ns as f64 / 1e6,
                    report.p99_ns as f64 / 1e6,
                    report.jobs_per_s,
                    report.jobs_per_s_parallel,
                    report.samples
                );
                reports.push(report);
            }
            Err(MeasureError::Skip(reason)) => eprintln!("skip: {name}: {reason}"),
            Err(MeasureError::Fail(reason)) => {
                eprintln!("{name}: {reason}");
                failed = true;
            }
        }
    }

    let report = Report {
        schema_version: 1,
        scenarios: reports,
    };
    if opts.json {
        serde_json::to_writer_pretty(io::stdout(), &report).expect("write json");
        println!();
    }
    if let Some(path) = &opts.write_baseline {
        let mut file = fs::File::create(path).expect("create baseline");
        serde_json::to_writer_pretty(&mut file, &report).expect("write baseline");
        file.write_all(b"\n").expect("newline");
        eprintln!("wrote baseline {}", path.display());
    }

    if let Err(message) = check_budgets(&report) {
        eprintln!("budget: {message}");
        failed = true;
    }
    if let Some(path) = &opts.check {
        match check_baseline(path, &report) {
            Ok(()) => {}
            Err(message) => {
                eprintln!("baseline: {message}");
                failed = true;
            }
        }
    }
    if failed {
        std::process::exit(1);
    }
}

struct Opts {
    samples: usize,
    warmup: usize,
    json: bool,
    check: Option<PathBuf>,
    write_baseline: Option<PathBuf>,
}

impl Opts {
    fn parse() -> Self {
        let mut samples = DEFAULT_SAMPLES;
        let mut warmup = DEFAULT_WARMUP;
        let mut json = false;
        let mut check = None;
        let mut write_baseline = None;
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--json" => json = true,
                "--samples" => {
                    samples = args
                        .next()
                        .expect("--samples needs a value")
                        .parse()
                        .expect("samples");
                }
                "--warmup" => {
                    warmup = args
                        .next()
                        .expect("--warmup needs a value")
                        .parse()
                        .expect("warmup");
                }
                "--check" => {
                    check = Some(resolve_path(&args.next().expect("--check needs a path")));
                }
                "--write-baseline" => {
                    write_baseline = Some(resolve_path(
                        &args.next().expect("--write-baseline needs a path"),
                    ));
                }
                "--bench" => {}
                other => panic!("unknown argument: {other}"),
            }
        }
        Self {
            samples,
            warmup,
            json,
            check,
            write_baseline,
        }
    }
}

enum MeasureError {
    Skip(String),
    Fail(String),
}

fn measure(
    settings: Option<&Settings>,
    workspace: &Path,
    warmup: usize,
    samples: usize,
) -> Result<Sampled, MeasureError> {
    if let Some(settings) = settings {
        match kekkai::health(settings) {
            Health::Ok(_) | Health::Warning(_) => {}
            Health::Error(message) => return Err(MeasureError::Skip(message)),
            _ => return Err(MeasureError::Skip("unrecognized health variant".into())),
        }
        one_job(settings, workspace).map_err(MeasureError::Fail)?;
    } else {
        unsandboxed().map_err(MeasureError::Fail)?;
    }

    for _ in 0..warmup {
        if let Some(settings) = settings {
            one_job(settings, workspace).map_err(MeasureError::Fail)?;
        } else {
            unsandboxed().map_err(MeasureError::Fail)?;
        }
    }

    let mut times = Vec::with_capacity(samples);
    for _ in 0..samples {
        let started = Instant::now();
        if let Some(settings) = settings {
            one_job(settings, workspace).map_err(MeasureError::Fail)?;
        } else {
            unsandboxed().map_err(MeasureError::Fail)?;
        }
        times.push(started.elapsed());
    }

    let jobs_per_s =
        throughput(settings, workspace, THROUGHPUT_JOBS, 1).map_err(MeasureError::Fail)?;
    let jobs_per_s_parallel = throughput(settings, workspace, THROUGHPUT_JOBS, PARALLEL_THREADS)
        .map_err(MeasureError::Fail)?;
    Ok(Sampled {
        samples: times,
        jobs_per_s,
        jobs_per_s_parallel,
    })
}

fn throughput(
    settings: Option<&Settings>,
    workspace: &Path,
    jobs: usize,
    threads: usize,
) -> Result<f64, String> {
    let started = Instant::now();
    if threads <= 1 {
        for _ in 0..jobs {
            if let Some(settings) = settings {
                one_job(settings, workspace)?;
            } else {
                unsandboxed()?;
            }
        }
    } else {
        let per_thread = jobs.div_ceil(threads);
        std::thread::scope(|scope| {
            let mut joins = Vec::new();
            for _ in 0..threads {
                joins.push(scope.spawn(|| {
                    for _ in 0..per_thread {
                        if let Some(settings) = settings {
                            one_job(settings, workspace)?;
                        } else {
                            unsandboxed()?;
                        }
                    }
                    Ok::<(), String>(())
                }));
            }
            for join in joins {
                join.join().expect("throughput thread")?;
            }
            Ok::<(), String>(())
        })?;
    }
    let elapsed = started.elapsed().as_secs_f64().max(1e-9);
    let total = if threads <= 1 {
        jobs
    } else {
        threads * jobs.div_ceil(threads)
    };
    Ok(total as f64 / elapsed)
}

fn one_job(settings: &Settings, workspace: &Path) -> Result<(), String> {
    let sandbox = Sandbox::prepare(settings, workspace).map_err(|error| error.to_string())?;
    let mut cmd = payload();
    sandbox.apply(&mut cmd).map_err(|error| error.to_string())?;
    let status = cmd.status().map_err(|error| error.to_string())?;
    if !status.success() {
        return Err(format!("{} failed: {status}", payload_path()));
    }
    let _ = sandbox.finish();
    Ok(())
}

fn unsandboxed() -> Result<(), String> {
    let status = payload().status().map_err(|error| error.to_string())?;
    if !status.success() {
        return Err(format!("{} failed: {status}", payload_path()));
    }
    Ok(())
}

fn payload() -> Command {
    let mut cmd = Command::new(payload_path());
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());
    cmd
}

fn percentile_ns(samples: &[Duration], pct: u8) -> u64 {
    let mut ns: Vec<u64> = samples.iter().map(|d| d.as_nanos() as u64).collect();
    ns.sort_unstable();
    let n = ns.len();
    if n == 0 {
        return 0;
    }
    let rank = ((pct as usize) * n)
        .div_ceil(100)
        .saturating_sub(1)
        .min(n - 1);
    ns[rank]
}

fn check_budgets(report: &Report) -> Result<(), String> {
    let unsandboxed = match find(report, "unsandboxed") {
        Some(row) => row,
        None => return Err("unsandboxed scenario missing".into()),
    };
    if let Some(rlimit) = find(report, "rlimit") {
        let overhead = rlimit.p95_ns.saturating_sub(unsandboxed.p95_ns);
        if overhead > RLIMIT_OVERHEAD_BUDGET.as_nanos() as u64 {
            return Err(format!(
                "rlimit p95 overhead {}ns exceeds {}ns",
                overhead,
                RLIMIT_OVERHEAD_BUDGET.as_nanos()
            ));
        }
    }
    if let Some(full) = find(report, "linux_native_full") {
        let overhead = full.p95_ns.saturating_sub(unsandboxed.p95_ns);
        if overhead > FULL_STACK_OVERHEAD_BUDGET.as_nanos() as u64 {
            return Err(format!(
                "linux_native_full p95 overhead {}ns exceeds {}ns",
                overhead,
                FULL_STACK_OVERHEAD_BUDGET.as_nanos()
            ));
        }
    }
    if let Some(native) = find(report, "linux_native")
        && native.jobs_per_s < MIN_JOBS_PER_S
    {
        return Err(format!(
            "linux_native sequential {:.1} jobs/s is below {MIN_JOBS_PER_S}",
            native.jobs_per_s
        ));
    }
    Ok(())
}

fn check_baseline(path: &Path, report: &Report) -> Result<(), String> {
    let text = fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let baseline: Report =
        serde_json::from_str(&text).map_err(|error| format!("baseline json: {error}"))?;
    if baseline.schema_version != 1 {
        return Err(format!(
            "baseline schema_version {} is not 1",
            baseline.schema_version
        ));
    }
    for previous in &baseline.scenarios {
        let Some(current) = find(report, &previous.name) else {
            continue;
        };
        let limit = (previous.p95_ns as f64 * REGRESSION) as u64;
        if current.p95_ns > limit {
            return Err(format!(
                "{} p95 {}ns exceeds 20% of baseline {}ns (limit {limit}ns)",
                previous.name, current.p95_ns, previous.p95_ns
            ));
        }
    }
    Ok(())
}

fn find<'a>(report: &'a Report, name: &str) -> Option<&'a ScenarioReport> {
    report.scenarios.iter().find(|row| row.name == name)
}
