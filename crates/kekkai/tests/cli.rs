//! `kekkai run` CLI on the shipped binary: same prepare/apply/spawn path as the library.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use kekkai::{Backend, Health, RunReport, SCHEMA_VERSION, Settings};

fn skip(reason: &str) {
    eprintln!("skip: {reason}");
}

fn kekkai_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kekkai"))
}

fn probe_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kekkai-probe"))
}

fn host_true() -> PathBuf {
    for path in ["/usr/bin/true", "/bin/true"] {
        if Path::new(path).exists() {
            return PathBuf::from(path);
        }
    }
    PathBuf::from("true")
}

fn host_sh() -> Option<PathBuf> {
    for path in ["/bin/sh", "/usr/bin/sh"] {
        if Path::new(path).exists() {
            return Some(PathBuf::from(path));
        }
    }
    None
}

fn native_backend() -> Option<Backend> {
    let backend = if cfg!(target_os = "linux") {
        Backend::LinuxNative
    } else if cfg!(target_os = "macos") {
        Backend::Macos
    } else {
        skip("native isolation tests require Linux or macOS");
        return None;
    };
    let settings = Settings::builder().backend(backend).build();
    match kekkai::health(&settings) {
        Health::Ok(_) => Some(backend),
        Health::Warning(message) | Health::Error(message) => {
            skip(&format!("{backend} unavailable: {message}"));
            None
        }
        _ => {
            skip("unrecognized health variant");
            None
        }
    }
}

fn run_cli(args: &[&str]) -> Output {
    Command::new(kekkai_exe())
        .args(args)
        .output()
        .expect("spawn kekkai")
}

fn report_from(path: &Path) -> RunReport {
    let json = fs::read_to_string(path).expect("read report");
    RunReport::from_json(json.trim()).expect("parse RunReport")
}

#[test]
fn help_documents_exit_codes_and_json_report() {
    let output = run_cli(&["--help"]);
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("kekkai run"), "{stdout}");
    assert!(stdout.contains("schema_version 1"), "{stdout}");
    assert!(stdout.contains("128+N"), "{stdout}");
    assert!(stdout.contains("  2 "), "{stdout}");
}

#[test]
fn missing_command_exits_two() {
    let output = run_cli(&["run", "--backend", "none"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn none_backend_writes_json_report_and_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let report = tmp.path().join("report.json");
    let workspace = tmp.path().join("ws");
    fs::create_dir_all(&workspace).unwrap();
    let true_bin = host_true();
    let output = run_cli(&[
        "run",
        "--backend",
        "none",
        "--workspace",
        workspace.to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
        "--",
        true_bin.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed = report_from(&report);
    assert_eq!(parsed.schema_version, SCHEMA_VERSION);
    assert_eq!(parsed.settings.backend, "none");
    assert_eq!(parsed.settings.network, "deny");
}

#[test]
fn child_exit_code_is_propagated() {
    let Some(sh) = host_sh() else {
        skip("/bin/sh is required to assert a numeric child exit code");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let report = tmp.path().join("report.json");
    let output = run_cli(&[
        "run",
        "--backend",
        "none",
        "--report",
        report.to_str().unwrap(),
        "--",
        sh.to_str().unwrap(),
        "-c",
        "exit 7",
    ]);
    assert_eq!(
        output.status.code(),
        Some(7),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(report.exists(), "report should still be written");
}

#[test]
fn unknown_settings_key_exits_two() {
    let tmp = tempfile::tempdir().unwrap();
    let settings = tmp.path().join("settings.json");
    fs::write(&settings, r#"{"backend":"none","nope":true}"#).unwrap();
    let true_bin = host_true();
    let output = run_cli(&[
        "run",
        "--settings",
        settings.to_str().unwrap(),
        "--",
        true_bin.to_str().unwrap(),
    ]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn settings_file_is_overridden_by_flags() {
    let tmp = tempfile::tempdir().unwrap();
    let report = tmp.path().join("report.json");
    let settings = tmp.path().join("settings.json");
    fs::write(&settings, r#"{"backend":"rlimit","network":"allow"}"#).unwrap();
    let true_bin = host_true();
    let output = run_cli(&[
        "run",
        "--settings",
        settings.to_str().unwrap(),
        "--backend",
        "none",
        "--network",
        "deny",
        "--report",
        report.to_str().unwrap(),
        "--",
        true_bin.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed = report_from(&report);
    assert_eq!(parsed.settings.backend, "none");
    assert_eq!(parsed.settings.network, "deny");
}

#[test]
fn unsupported_backend_exits_two() {
    let (backend, label) = if cfg!(target_os = "macos") {
        ("linux_native", "linux_native")
    } else if cfg!(target_os = "linux") {
        ("macos", "macos")
    } else {
        skip("cross-OS unsupported backend test requires Linux or macOS");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let report = tmp.path().join("report.json");
    let true_bin = host_true();
    let output = run_cli(&[
        "run",
        "--backend",
        backend,
        "--report",
        report.to_str().unwrap(),
        "--",
        true_bin.to_str().unwrap(),
    ]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(label) || stderr.contains("Unsupported") || stderr.contains("unsupported"),
        "{stderr}"
    );
    assert!(
        !report.exists(),
        "report must not be written when prepare fails"
    );
}

#[test]
fn write_outside_workspace_is_denied() {
    let Some(backend) = native_backend() else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("ws");
    fs::create_dir_all(&workspace).unwrap();
    let outside = tmp.path().join("outside.txt");
    let report = tmp.path().join("report.json");
    let probe = probe_exe();
    let probe_dir = probe.parent().expect("probe parent").to_str().unwrap();
    let backend_name = backend.to_string();
    let output = run_cli(&[
        "run",
        "--backend",
        &backend_name,
        "--workspace",
        workspace.to_str().unwrap(),
        "--readable",
        probe_dir,
        "--report",
        report.to_str().unwrap(),
        "--",
        probe.to_str().unwrap(),
        "write",
        outside.to_str().unwrap(),
    ]);
    assert!(!outside.exists(), "write escaped to {}", outside.display());
    assert!(
        !output.status.success(),
        "child succeeded writing outside the workspace: stderr={} stdout={}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let parsed = report_from(&report);
    assert_eq!(parsed.settings.backend, backend_name);
}

#[test]
fn write_inside_workspace_is_allowed() {
    let Some(backend) = native_backend() else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("ws");
    fs::create_dir_all(&workspace).unwrap();
    let inside = workspace.join("inside.txt");
    let report = tmp.path().join("report.json");
    let probe = probe_exe();
    let probe_dir = probe.parent().expect("probe parent").to_str().unwrap();
    let backend_name = backend.to_string();
    let output = run_cli(&[
        "run",
        "--backend",
        &backend_name,
        "--workspace",
        workspace.to_str().unwrap(),
        "--readable",
        probe_dir,
        "--report",
        report.to_str().unwrap(),
        "--",
        probe.to_str().unwrap(),
        "write",
        inside.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "stderr={} stdout={}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(fs::read(&inside).expect("read inside"), b"pwned\n");
}
