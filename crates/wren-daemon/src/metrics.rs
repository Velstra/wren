//! Prometheus text-exposition helpers for `wren show metrics`.
//!
//! The reviewer's monitoring ask was machine-readable output for Prometheus /
//! Grafana. Rather than embed an HTTP server (a new dependency and a new listening
//! socket), Wren stays true to the BIRD/FRR model — text over the existing Unix
//! control socket — and emits the [Prometheus text exposition format][fmt] when
//! asked for `show metrics`. An operator bridges it to a Prometheus scrape with a
//! trivial sidecar (a textfile-collector cron, or `socat` + a one-line CGI), the
//! same way `bird_exporter` wraps `birdc`.
//!
//! This module is just the format: a family header (`# HELP` / `# TYPE`) and a
//! sample line writer with correct label escaping. The per-subsystem metric values
//! are produced by the task that owns the state — route counts by the
//! [router](crate::router), session state by the [BGP task](crate::bgp) — so, like
//! every other `show`, nothing reaches across task boundaries to read a RIB.
//!
//! [fmt]: https://prometheus.io/docs/instrumenting/exposition_formats/#text-based-format

use std::fmt::{Display, Write};

/// Escape a label value per the text format: backslash, double-quote and newline
/// are the only characters that must be escaped inside a `"…"` label value.
pub fn escape_label(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

/// Write a metric family's `# HELP` and `# TYPE` lines. Call this once per family,
/// before its sample lines. `kind` is `gauge`, `counter`, etc.
pub fn family(out: &mut String, name: &str, help: &str, kind: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

/// Write one sample line — `name{label="value",…} value` — with every label value
/// escaped. An empty `labels` omits the braces entirely (`name value`).
pub fn sample(out: &mut String, name: &str, labels: &[(&str, &str)], value: impl Display) {
    out.push_str(name);
    if !labels.is_empty() {
        out.push('{');
        for (i, (k, v)) in labels.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            let _ = write!(out, "{k}=\"{}\"", escape_label(v));
        }
        out.push('}');
    }
    let _ = writeln!(out, " {value}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_backslash_quote_and_newline() {
        assert_eq!(escape_label(r#"a"b\c"#), r#"a\"b\\c"#);
        assert_eq!(escape_label("line1\nline2"), "line1\\nline2");
        assert_eq!(escape_label("plain"), "plain");
    }

    #[test]
    fn family_writes_help_and_type() {
        let mut out = String::new();
        family(&mut out, "wren_x", "An example.", "gauge");
        assert_eq!(out, "# HELP wren_x An example.\n# TYPE wren_x gauge\n");
    }

    #[test]
    fn sample_with_labels_is_escaped_and_ordered() {
        let mut out = String::new();
        sample(&mut out, "wren_up", &[("neighbor", "10.0.0.2"), ("asn", "65002")], 1);
        assert_eq!(out, "wren_up{neighbor=\"10.0.0.2\",asn=\"65002\"} 1\n");
    }

    #[test]
    fn sample_without_labels_omits_braces() {
        let mut out = String::new();
        sample(&mut out, "wren_total", &[], 42);
        assert_eq!(out, "wren_total 42\n");
    }
}
