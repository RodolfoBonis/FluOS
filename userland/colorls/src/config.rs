//! Runtime user overrides from `~/.config/colorls/*.yaml`, matching the gem.
//!
//! The gem's `ColorLS::Yaml#load` reads the embedded file and, if present,
//! merges `~/.config/colorls/<file>` over it (user keys win). We mirror that:
//! embedded tables live in [`crate::tables`]; here we load the optional user
//! files and expose merged lookups.

use std::collections::HashMap;
use std::path::PathBuf;

/// Parse a flat `key: value` YAML map (same shape/rules as `build.rs`).
fn parse_flat_yaml(src: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for raw in src.lines() {
        let line = raw.trim_end();
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some(colon) = line.find(':') else { continue };
        let key = line[..colon].trim().trim_matches(|c| c == '"' || c == '\'');
        let mut val = line[colon + 1..].trim().to_string();
        if !val.starts_with('"') && !val.starts_with('\'')
            && let Some(h) = val.find(" #") {
                val = val[..h].trim_end().to_string();
            }
        let val = val.trim().trim_matches(|c| c == '"' || c == '\'').to_string();
        out.push((key.to_string(), val));
    }
    out
}

fn config_dir() -> Option<PathBuf> {
    // Mirror Ruby's `Dir.home`: prefer $HOME.
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config").join("colorls"))
}

/// Load `~/.config/colorls/<file>` as a flat map, or empty if absent/unreadable.
pub fn load_user(file: &str) -> HashMap<String, String> {
    let Some(dir) = config_dir() else {
        return HashMap::new();
    };
    let path = dir.join(file);
    match std::fs::read_to_string(&path) {
        Ok(src) => parse_flat_yaml(&src).into_iter().collect(),
        Err(_) => HashMap::new(),
    }
}
