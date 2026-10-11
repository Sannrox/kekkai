//! JSON run report and optional tracing spans.

use kekkai::{RunReport, SCHEMA_VERSION, Sandbox, Settings};

#[test]
fn run_report_json_round_trips() {
    let sandbox = Sandbox::prepare(&Settings::default(), ".").expect("prepare");
    let report = sandbox.report();
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.settings.backend, "none");
    assert_eq!(report.settings.network, "deny");
    assert_eq!(report.settings.syscall_profile, "default");
    assert_eq!(report.settings.namespaces, "off");
    assert_eq!(report.settings.filesystem_view, "host");
    assert!(!report.settings.cgroup);
    assert_eq!(report.settings.devices, 0);
    let json = report.to_json().expect("to_json");
    assert!(
        json.contains("\"schema_version\":1"),
        "documented schema version missing: {json}"
    );
    let back = RunReport::from_json(&json).expect("from_json");
    assert_eq!(report, back);
}

#[test]
fn run_report_records_prepare_timing() {
    let sandbox = Sandbox::prepare(&Settings::default(), ".").expect("prepare");
    let mut command = std::process::Command::new("true");
    sandbox.apply(&mut command).expect("apply");
    let report = sandbox.report();
    assert!(
        report.timing.since_prepare_ms >= report.timing.prepare_ms,
        "{:?}",
        report.timing
    );
}

#[test]
fn run_report_rejects_zero_schema_version() {
    let error = RunReport::from_json("{\"schema_version\":0}").unwrap_err();
    assert!(error.to_string().contains("schema_version"), "{error}");
}
