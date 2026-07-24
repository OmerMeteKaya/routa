//! Value-parsing helpers for routa's config-file syntax: `key = value`
//! lines, `[pool NAME]` / `[tls_cert HOSTNAME]` section headers,
//! `upstream HOST:PORT [weight=N]`, `include glob-pattern`, `${VAR}`
//! environment expansion, `#` comments.

use std::env;

use super::types::*;

const MAX_INCLUDE_DEPTH: i32 = 8;

#[derive(Debug)]
pub struct ConfigWarning {
    pub line: usize,
    pub message: String,
}

/// Accumulates non-fatal parse warnings (unknown keys, malformed values
/// that fell back to a default, etc.) alongside the config being built --
/// callers decide whether to log them, surface them, or ignore them,
/// rather than the parser reaching for a global logger directly.
pub struct ParseContext {
    pub warnings: Vec<ConfigWarning>,
    pub depth: i32,
}

impl ParseContext {
    pub fn warn(&mut self, line: usize, message: impl Into<String>) {
        self.warnings.push(ConfigWarning {
            line,
            message: message.into(),
        });
    }
}

// ─── Value-format helpers ──────────────────────────────────────────────────

pub fn trim(s: &str) -> &str {
    s.trim()
}

/// Strips a trailing inline comment (`key = value  # comment`). A '#'
/// inside a quoted value is not treated as a comment start -- matches
/// the C parser's strip_inline_comment(), which only looks for '#'
/// outside of a quoted span.
pub fn strip_inline_comment(s: &str) -> &str {
    let mut in_quotes = false;
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'"' => in_quotes = !in_quotes,
            b'#' if !in_quotes => return &s[..i],
            _ => {}
        }
    }
    s
}

pub fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

pub fn cfg_atoi(val: &str, default_val: i32) -> i32 {
    if val.is_empty() {
        return default_val;
    }
    val.parse::<i32>().unwrap_or(default_val)
}

/// Accepts 0/1/true/false/yes/no/on/off (case-insensitive); anything else
/// falls back to default_val. Single flexible parser used for every
/// `foo_enabled = ...` key.
pub fn cfg_atob(val: &str, default_val: bool, ctx: &mut ParseContext, line: usize) -> bool {
    if val.is_empty() {
        return default_val;
    }
    match val.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        _ => {
            ctx.warn(line, format!("invalid boolean value '{val}', using default"));
            default_val
        }
    }
}

/// Parses a duration string with a MANDATORY unit suffix into
/// milliseconds: "ms", "s", "m", "h". A bare number with no suffix is
/// rejected -- routa requires an explicit unit on every duration so
/// operators never have to remember an implicit convention per key.
/// Examples: "500ms", "45s", "2m", "1h". No whitespace between number
/// and unit.
pub fn cfg_duration_ms(val: &str, default_val: i32, ctx: &mut ParseContext, line: usize) -> i32 {
    if val.is_empty() {
        return default_val;
    }
    // A bare "0" needs no unit: zero milliseconds, zero seconds, and
    // zero hours are all the same instant, so there's no ambiguity for
    // the unit requirement to guard against. Every other magnitude
    // still requires an explicit unit below.
    if val == "0" || val == "0.0" {
        return 0;
    }
    let split_at = val.find(|c: char| !c.is_ascii_digit() && c != '.' && c != '-');
    let Some(split_at) = split_at else {
        ctx.warn(
            line,
            format!("duration '{val}' missing/unknown unit (expected ms/s/m/h), using default"),
        );
        return default_val;
    };
    let (num_part, unit) = val.split_at(split_at);
    let Ok(n) = num_part.parse::<f64>() else {
        ctx.warn(
            line,
            format!("invalid duration '{val}' (expected e.g. \"45s\", \"500ms\", \"2m\"), using default"),
        );
        return default_val;
    };
    if n < 0.0 {
        ctx.warn(
            line,
            format!("invalid duration '{val}' (expected e.g. \"45s\", \"500ms\", \"2m\"), using default"),
        );
        return default_val;
    }
    let multiplier = match unit {
        "ms" => 1.0,
        "s" => 1000.0,
        "m" => 60.0 * 1000.0,
        "h" => 60.0 * 60.0 * 1000.0,
        _ => {
            ctx.warn(
                line,
                format!("duration '{val}' missing/unknown unit (expected ms/s/m/h), using default"),
            );
            return default_val;
        }
    };
    (n * multiplier) as i32
}

/// Same as cfg_duration_ms() but returns whole seconds (for fields whose
/// runtime type is already "seconds", e.g. lb_pool_idle_timeout_s).
pub fn cfg_duration_s(val: &str, default_val: i32, ctx: &mut ParseContext, line: usize) -> i32 {
    let ms = cfg_duration_ms(val, default_val * 1000, ctx, line);
    ms / 1000
}

/// Parses a size string with a MANDATORY unit suffix into bytes: "B",
/// "KB"/"K" (1024), "MB"/"M" (1024^2), "GB"/"G" (1024^3). Binary
/// (1024-based) units throughout, matching how these values are
/// actually used (buffer sizes, memory limits). Case-insensitive suffix.
pub fn cfg_size_bytes(val: &str, default_val: i64, ctx: &mut ParseContext, line: usize) -> i64 {
    if val.is_empty() {
        return default_val;
    }
    // Same reasoning as cfg_duration_ms(): a bare "0" is unambiguous
    // regardless of unit, so it's accepted without one.
    if val == "0" || val == "0.0" {
        return 0;
    }
    let split_at = val.find(|c: char| !c.is_ascii_digit() && c != '.' && c != '-');
    let Some(split_at) = split_at else {
        ctx.warn(
            line,
            format!("size '{val}' missing/unknown unit (expected B/KB/MB/GB), using default"),
        );
        return default_val;
    };
    let (num_part, unit) = val.split_at(split_at);
    let Ok(n) = num_part.parse::<f64>() else {
        ctx.warn(
            line,
            format!("invalid size '{val}' (expected e.g. \"64MB\", \"256KB\"), using default"),
        );
        return default_val;
    };
    if n < 0.0 {
        ctx.warn(
            line,
            format!("invalid size '{val}' (expected e.g. \"64MB\", \"256KB\"), using default"),
        );
        return default_val;
    }
    let multiplier = match unit.to_ascii_uppercase().as_str() {
        "B" => 1.0,
        "KB" | "K" => 1024.0,
        "MB" | "M" => 1024.0 * 1024.0,
        "GB" | "G" => 1024.0 * 1024.0 * 1024.0,
        _ => {
            ctx.warn(
                line,
                format!("size '{val}' missing/unknown unit (expected B/KB/MB/GB), using default"),
            );
            return default_val;
        }
    };
    (n * multiplier) as i64
}

/// Same as cfg_size_bytes() but returns whole megabytes (for fields whose
/// runtime type is already "MB", e.g. cache_memory_mb).
pub fn cfg_size_mb(val: &str, default_mb: i64, ctx: &mut ParseContext, line: usize) -> i64 {
    let bytes = cfg_size_bytes(val, default_mb * 1024 * 1024, ctx, line);
    bytes / (1024 * 1024)
}

/// Expands every "${VAR_NAME}" occurrence by looking VAR_NAME up in the
/// environment. An undefined variable expands to an empty string (with
/// a warning) rather than failing the whole line. A malformed reference
/// (`${` with no closing `}`) is left as literal text from that point on.
pub fn expand_env_vars(input: &str, ctx: &mut ParseContext, line: usize) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            if let Some(close_rel) = input[i + 2..].find('}') {
                let name = &input[i + 2..i + 2 + close_rel];
                match env::var(name) {
                    Ok(v) => out.push_str(&v),
                    Err(_) => {
                        ctx.warn(
                            line,
                            format!(
                                "environment variable '{name}' is not set, expanding to empty string"
                            ),
                        );
                    }
                }
                i = i + 2 + close_rel + 1;
                continue;
            }
        }
        // Advance by one full UTF-8 char, not one byte.
        let ch = input[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

pub fn parse_log_level(val: &str) -> String {
    match val.to_ascii_lowercase().as_str() {
        "trace" | "debug" | "info" | "warn" | "error" => val.to_ascii_lowercase(),
        _ => "info".to_string(),
    }
}
