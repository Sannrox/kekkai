#![no_main]

use kekkai::{Backend, Sandbox, Settings};
use libfuzzer_sys::fuzz_target;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

fn take_path(data: &mut &[u8]) -> PathBuf {
    if data.is_empty() {
        return PathBuf::from("/");
    }
    let len = usize::from(data[0]) % 80;
    *data = &data[1..];
    let take = len.min(data.len());
    let bytes = data[..take].to_vec();
    *data = &data[take..];
    let mut path = PathBuf::from(OsString::from_vec(bytes));
    if !path.is_absolute() {
        path = PathBuf::from("/").join(path);
    }
    path
}

fuzz_target!(|data: &[u8]| {
    let mut rest = data;
    let mut settings = Settings::builder()
        .backend(Backend::LinuxNative)
        .build();
    if rest.first().copied().unwrap_or(0) & 1 == 1 {
        settings.backend = Backend::None;
    }
    settings.inputs.push(take_path(&mut rest));
    settings.output = Some(take_path(&mut rest));
    settings.readable_roots.push(take_path(&mut rest));
    settings.writable_roots.push(take_path(&mut rest));
    if rest.first().copied().unwrap_or(0) & 2 == 2 {
        // Overlap: input under output, plus `..` and slash noise.
        settings
            .inputs
            .push(PathBuf::from("/tmp/kekkai-fuzz/../kekkai-fuzz/in"));
        settings.output = Some(PathBuf::from("/tmp/kekkai-fuzz"));
        settings
            .writable_roots
            .push(PathBuf::from("/tmp/kekkai-fuzz/out"));
    }
    let Ok(tmp) = tempfile::tempdir() else {
        return;
    };
    let ws = tmp.path().join("ws");
    let _ = std::fs::create_dir_all(&ws);
    let _ = Sandbox::prepare(&settings, &ws);
    let _ = Sandbox::prepare(&settings, PathBuf::from("/").join(take_path(&mut rest)));
});
