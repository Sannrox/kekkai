//! Userspace guest helper: owns spawn and applies linux_native in the child.
//!
//! Protocol: `kekkai-guest --workspace DIR [--output DIR] [--network deny|allow]
//! [--input DIR]... [--readable DIR]... [--writable DIR]...
//! [--cpu-time-secs N] [--memory-mb N] [--user-processes N] [--file-size-mb N]
//! [--open-files N] -- PROGRAM [ARGS...]`

fn main() -> std::process::ExitCode {
    kekkai::run_guest_helper()
}
