//! Making text safe to write into logs.

/// Replace control characters and cut long text, so a client can never
/// forge log lines or flood the log with one giant value.
pub fn sanitize_for_log(text: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (count, c) in text.chars().enumerate() {
        if count >= max_chars {
            out.push_str("...");
            break;
        }
        out.push(if c.is_control() { '?' } else { c });
    }
    out
}

/// The part of a request target that is safe to log: the path, plus the
/// query string only when it was asked for.
pub fn loggable_target(target: &str, include_query: bool) -> String {
    let shown = if include_query {
        target
    } else {
        target.split('?').next().unwrap_or("")
    };
    sanitize_for_log(shown, 200)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_are_replaced() {
        assert_eq!(sanitize_for_log("a\r\nb\tc\u{1b}[31m", 100), "a??b?c?[31m");
    }

    #[test]
    fn long_text_is_cut_off() {
        assert_eq!(sanitize_for_log("abcdef", 3), "abc...");
        assert_eq!(sanitize_for_log("abc", 3), "abc");
        assert_eq!(sanitize_for_log("", 3), "");
    }

    #[test]
    fn length_is_counted_in_characters_not_bytes() {
        assert_eq!(sanitize_for_log("ééééé", 3), "ééé...");
    }

    #[test]
    fn query_strings_are_left_out_by_default() {
        assert_eq!(loggable_target("/reset?token=secret", false), "/reset");
        assert_eq!(loggable_target("/plain", false), "/plain");
        assert_eq!(loggable_target("/a?b=1&c=2", true), "/a?b=1&c=2");
    }

    #[test]
    fn a_forged_log_line_cannot_survive() {
        let nasty = "/x\r\n2026-01-01 INFO access: ip=1.2.3.4 status=200";
        let shown = loggable_target(nasty, false);
        assert!(!shown.contains('\n') && !shown.contains('\r'));
    }

    #[test]
    fn very_long_targets_are_shortened() {
        let long = format!("/{}", "a".repeat(5000));
        assert!(loggable_target(&long, false).chars().count() <= 203);
    }
}
