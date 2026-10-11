//! Serializable run report: settings summary, usage, violations, timing.

use serde::{Deserialize, Serialize};

use crate::{ChildUsage, FilesystemView, Namespaces, Network, Settings, SyscallProfile};

/// Current JSON schema version for [`RunReport`].
pub const SCHEMA_VERSION: u32 = 1;

/// Compact settings included in a run report. Paths are omitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(default)]
pub struct SettingsSummary {
    /// [`crate::Backend`] display name (`none`, `rlimit`, `linux_native`, `userspace`).
    pub backend: String,
    /// Network policy kind (`deny`, `allow`, `allowlist`, `loopback`).
    pub network: String,
    /// Syscall profile label (`default`, `strict`, `python`).
    pub syscall_profile: String,
    /// Namespace mode (`off`, `isolate`).
    pub namespaces: String,
    /// Filesystem view (`host`, `isolate`).
    pub filesystem_view: String,
    /// True when any cgroup limit was requested.
    pub cgroup: bool,
}

impl Default for SettingsSummary {
    fn default() -> Self {
        Self {
            backend: crate::Backend::None.to_string(),
            network: "deny".into(),
            syscall_profile: "default".into(),
            namespaces: "off".into(),
            filesystem_view: "host".into(),
            cgroup: false,
        }
    }
}

impl SettingsSummary {
    pub(crate) fn from_settings(settings: &Settings) -> Self {
        Self {
            backend: settings.backend.to_string(),
            network: match settings.network {
                Network::Deny => "deny",
                Network::Allow => "allow",
                Network::Allowlist(_) => "allowlist",
                Network::Loopback => "loopback",
            }
            .into(),
            syscall_profile: match settings.syscall_profile {
                SyscallProfile::Default => "default",
                SyscallProfile::Strict => "strict",
                SyscallProfile::Python => "python",
            }
            .into(),
            namespaces: match settings.namespaces {
                Namespaces::Off => "off",
                Namespaces::Isolate => "isolate",
            }
            .into(),
            filesystem_view: match settings.filesystem_view {
                FilesystemView::Host => "host",
                FilesystemView::Isolate { .. } => "isolate",
            }
            .into(),
            cgroup: !settings.cgroup.is_empty(),
        }
    }
}

/// Wall-clock timing for one sandbox, in milliseconds.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(default)]
pub struct RunTiming {
    /// Time spent in [`crate::Sandbox::prepare`].
    pub prepare_ms: u64,
    /// Cumulative time spent in [`crate::Sandbox::apply`].
    pub apply_ms: u64,
    /// Time from the start of prepare until this report was built.
    pub since_prepare_ms: u64,
}

/// Stable JSON run report. Schema version is [`SCHEMA_VERSION`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(default)]
pub struct RunReport {
    /// Schema version. Bump when the JSON shape changes incompatibly.
    pub schema_version: u32,
    /// Settings that affect isolation, without host paths.
    pub settings: SettingsSummary,
    /// Usage and violations from [`crate::Sandbox::finish`].
    pub usage: ChildUsage,
    /// Prepare, apply, and elapsed timing.
    pub timing: RunTiming,
}

impl Default for RunReport {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            settings: SettingsSummary::default(),
            usage: ChildUsage::default(),
            timing: RunTiming::default(),
        }
    }
}

impl RunReport {
    /// JSON schema version written by [`Self::to_json`].
    pub const SCHEMA_VERSION: u32 = SCHEMA_VERSION;

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, crate::Error> {
        serde_json::to_string(self)
            .map_err(|error| crate::Error::invalid(format!("run report json: {error}")))
    }

    /// Deserialize from JSON produced by [`Self::to_json`].
    pub fn from_json(json: &str) -> Result<Self, crate::Error> {
        let report: Self = serde_json::from_str(json)
            .map_err(|error| crate::Error::invalid(format!("run report json: {error}")))?;
        if report.schema_version == 0 {
            return Err(crate::Error::invalid(
                "run report json: schema_version must be greater than zero",
            ));
        }
        Ok(report)
    }
}
