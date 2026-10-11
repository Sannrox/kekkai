//! Read-only inputs, writable output, no sockets, cgroup memory cap.
//!
//! Usage: `transform <input-dir> <output-dir>`
//! Both paths must be absolute. The input directory is `Settings.inputs`
//! (read-only). The output directory is `Settings.output`.

use std::path::PathBuf;
use std::process::Command;

use kekkai::{Backend, CgroupLimits, Health, Network, Sandbox, Settings};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: transform <input-dir> <output-dir>";
    let (Some(input), Some(output)) = (args.next(), args.next()) else {
        return Err(usage.into());
    };
    let input = PathBuf::from(input);
    let output = PathBuf::from(output);
    if !input.is_absolute() || !output.is_absolute() {
        return Err("input and output directories must be absolute paths".into());
    }
    std::fs::create_dir_all(&output)?;

    let settings = Settings {
        backend: Backend::LinuxNative,
        network: Network::Deny,
        inputs: vec![input.clone()],
        output: Some(output.clone()),
        cgroup: CgroupLimits {
            memory_max: Some(512 * 1024 * 1024),
            ..CgroupLimits::default()
        },
        ..Settings::default()
    };
    match kekkai::health(&settings) {
        Health::Ok(message) | Health::Warning(message) => eprintln!("{message}"),
        Health::Error(message) => return Err(message.into()),
    }

    let sandbox = Sandbox::prepare(&settings, &output)?;
    let mut cmd = Command::new("python3");
    cmd.env("KEKKAI_INPUT", &input)
        .env("KEKKAI_OUTPUT", &output)
        .args([
            "-c",
            "import os, duckdb\n\
             src, dst = os.environ['KEKKAI_INPUT'], os.environ['KEKKAI_OUTPUT']\n\
             con = duckdb.connect()\n\
             con.execute(\"COPY (SELECT * FROM read_parquet(?)) TO ?\", [src + '/*.parquet', dst + '/result.parquet'])\n",
        ]);
    sandbox.apply(&mut cmd)?;
    let status = cmd.status()?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}
