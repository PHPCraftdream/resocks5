use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileLogConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_path")]
    pub path: String,
    #[serde(default = "default_also_console")]
    pub also_console: bool,
}

fn default_enabled() -> bool {
    false
}
fn default_path() -> String {
    "resocks5.log".to_string()
}
fn default_also_console() -> bool {
    true
}

impl Default for FileLogConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            path: default_path(),
            also_console: default_also_console(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_pinned() {
        let d = FileLogConfig::default();
        assert!(!d.enabled);
        assert_eq!(d.path, "resocks5.log");
        assert!(d.also_console);
    }

    #[test]
    fn serde_field_defaults_match_struct_default() {
        let d = FileLogConfig::default();
        assert_eq!(default_enabled(), d.enabled);
        assert_eq!(default_path(), d.path);
        assert_eq!(default_also_console(), d.also_console);
    }
}
