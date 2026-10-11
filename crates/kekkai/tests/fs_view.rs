//! Filesystem view tests on the shipped prepare/apply path.
//!
//! Hosts without isolate namespaces or overlay skip with `skip:`. They never
//! pass vacuously.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use kekkai::{Backend, FilesystemView, Health, Namespaces, OverlayPersist, Sandbox, Settings};

fn skip(reason: &str) {
    eprintln!("skip: {reason}");
}

fn probe_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kekkai-probe"))
}

fn view_or_skip(overlay: OverlayPersist) -> Option<(Settings, tempfile::TempDir, PathBuf)> {
    if !cfg!(target_os = "linux") {
        skip("filesystem view requires Linux");
        return None;
    }
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("ws");
    std::fs::create_dir_all(&workspace).unwrap();
    let probe_dir = probe_exe()
        .parent()
        .expect("kekkai-probe has a parent directory")
        .to_path_buf();
    let settings = Settings::builder()
        .backend(Backend::LinuxNative)
        .namespaces(Namespaces::Isolate)
        .filesystem_view(FilesystemView::Isolate { overlay })
        .readable_roots(vec![probe_dir])
        .build();
    match kekkai::health(&settings) {
        Health::Ok(_) => Some((settings, tmp, workspace)),
        Health::Warning(message) | Health::Error(message) => {
            skip(&format!("filesystem view unavailable: {message}"));
            None
        }
        _ => {
            skip("unrecognized health variant");
            None
        }
    }
}

fn run(sandbox: &Sandbox, mut cmd: Command) -> std::process::Output {
    sandbox.apply(&mut cmd).expect("apply");
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.output().expect("spawn sandboxed child")
}

fn probe(args: &[&str]) -> Command {
    let mut cmd = Command::new(probe_exe());
    cmd.args(args);
    cmd
}

#[test]
fn write_to_a_read_only_bind_fails() {
    let Some((mut settings, tmp, workspace)) = view_or_skip(OverlayPersist::Discard) else {
        return;
    };
    let input = tmp.path().join("in");
    std::fs::create_dir_all(&input).unwrap();
    let file = input.join("data.txt");
    std::fs::write(&file, "secret\n").unwrap();
    settings.inputs.push(input);
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["write", file.to_str().unwrap()]));
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "secret\n");
    assert!(
        !output.status.success(),
        "write to a read-only bind succeeded: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn overlay_writes_are_discarded_by_default() {
    let Some((settings, _tmp, workspace)) = view_or_skip(OverlayPersist::Discard) else {
        return;
    };
    let created = workspace.join("from-child.txt");
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["write", created.to_str().unwrap()]));
    assert!(
        output.status.success(),
        "overlay write failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !created.exists(),
        "discard overlay leaked a write onto the host workspace"
    );
}

#[test]
fn overlay_keep_persists_writes() {
    let Some((mut settings, tmp, workspace)) = view_or_skip(OverlayPersist::Discard) else {
        return;
    };
    let keep = tmp.path().join("keep");
    std::fs::create_dir_all(&keep).unwrap();
    settings.filesystem_view = FilesystemView::Isolate {
        overlay: OverlayPersist::Keep(keep.clone()),
    };
    match kekkai::health(&settings) {
        Health::Ok(_) => {}
        Health::Warning(message) | Health::Error(message) => {
            skip(&format!("filesystem view keep unavailable: {message}"));
            return;
        }
        _ => {
            skip("unrecognized health variant");
            return;
        }
    }
    let created = workspace.join("kept.txt");
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["write", created.to_str().unwrap()]));
    assert!(
        output.status.success(),
        "keep overlay write failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !created.exists(),
        "keep overlay wrote through to the lower workspace"
    );
    let kept = keep.join("upper").join("kept.txt");
    assert!(
        kept.exists(),
        "keep overlay upper missing {}: {}",
        kept.display(),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn path_outside_the_view_does_not_exist() {
    let Some((settings, tmp, workspace)) = view_or_skip(OverlayPersist::Discard) else {
        return;
    };
    let secret = tmp.path().join("secret.txt");
    std::fs::write(&secret, "plane-token\n").unwrap();
    let sandbox = Sandbox::prepare(&settings, &workspace).expect("prepare");
    let output = run(&sandbox, probe(&["read", secret.to_str().unwrap()]));
    assert!(
        !output.status.success(),
        "read of a path outside the view succeeded"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("plane-token"),
        "secret leaked on stdout: {stdout}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No such file"),
        "outside path should be missing, stderr={stderr}"
    );
}
