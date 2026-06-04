use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt;

pub const FILE_NAME: &str = "moat.toml";

/// A fatal error indicating that a repository's `moat.toml` is invalid.
///
/// Surfaces through `anyhow::Error` so the runner can downcast and abort the
/// whole run instead of skipping the offending repo.
#[derive(Debug)]
pub struct InvalidConfigError {
    pub org_repo: String,
    pub source: anyhow::Error,
}

impl fmt::Display for InvalidConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Invalid moat.toml in {}: {:#}",
            self.org_repo, self.source
        )
    }
}

impl std::error::Error for InvalidConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[derive(Debug, Default, Clone)]
pub struct Config {
    checks: HashMap<String, CheckState>,
    release_branches: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckState {
    On,
    Off,
}

#[derive(Deserialize)]
struct RawConfig {
    #[serde(default)]
    checks: HashMap<String, String>,
    #[serde(default)]
    release_branches: Vec<String>,
}

impl Config {
    pub fn parse(text: &str, known_check_ids: &[&str]) -> Result<Self> {
        let raw: RawConfig = toml::from_str(text).context("Invalid moat.toml")?;
        let mut checks = HashMap::with_capacity(raw.checks.len());
        for (id, value) in raw.checks {
            if !known_check_ids.iter().any(|known| *known == id) {
                anyhow::bail!("Unknown check `{id}` in moat.toml");
            }
            let state = match value.as_str() {
                "on" => CheckState::On,
                "off" => CheckState::Off,
                other => anyhow::bail!(
                    "Invalid value `{other}` for check `{id}` in moat.toml — expected `on` or `off`"
                ),
            };
            checks.insert(id, state);
        }
        Ok(Self {
            checks,
            release_branches: raw.release_branches,
        })
    }

    pub fn is_off(&self, check_id: &str) -> bool {
        matches!(self.checks.get(check_id), Some(CheckState::Off))
    }

    pub fn release_branches(&self) -> &[String] {
        &self.release_branches
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KNOWN: &[&str] = &[
        "repositories_commits_are_signed",
        "repositories_workflow_actions_are_sha_pinned",
    ];

    #[test]
    fn parses_off_and_on() {
        let cfg = Config::parse(
            r#"
                [checks]
                repositories_commits_are_signed = "off"
                repositories_workflow_actions_are_sha_pinned = "on"
            "#,
            KNOWN,
        )
        .unwrap();
        assert!(cfg.is_off("repositories_commits_are_signed"));
        assert!(!cfg.is_off("repositories_workflow_actions_are_sha_pinned"));
    }

    #[test]
    fn empty_config_is_valid() {
        let cfg = Config::parse("", KNOWN).unwrap();
        assert!(!cfg.is_off("anything"));
    }

    #[test]
    fn rejects_unknown_values() {
        let err = Config::parse(
            r#"
                [checks]
                repositories_commits_are_signed = "warning"
            "#,
            KNOWN,
        )
        .unwrap_err();
        assert!(err.to_string().contains("Invalid value"));
    }

    #[test]
    fn rejects_unknown_check_id() {
        let err = Config::parse(
            r#"
                [checks]
                does_not_exist = "off"
            "#,
            KNOWN,
        )
        .unwrap_err();
        assert!(err.to_string().contains("Unknown check"));
    }

    #[test]
    fn rejects_invalid_toml() {
        assert!(Config::parse("not = valid = toml", KNOWN).is_err());
    }
}
