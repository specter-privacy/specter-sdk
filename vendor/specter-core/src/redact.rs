//! Redaction helpers for anything that may carry an RPC provider credential.
//!
//! Provider API keys live in the *path* of an RPC URL
//! (`https://mainnet.infura.io/v3/<KEY>`), and two things happily copy that
//! path somewhere it does not belong:
//!
//! * `tracing` fields, if an endpoint URL is logged verbatim; and
//! * `reqwest`, which embeds the full request URL in its transport errors
//!   (`error sending request for url (https://host/v3/<KEY>)`). That string
//!   flows into [`crate::error::SpecterError`] and can reach a 5xx response
//!   body whenever error sanitisation is not active.
//!
//! Everything that logs an endpoint or stores an upstream error message must
//! pass it through here first.

/// Reduces an RPC URL to `scheme://host`, dropping the path, query, fragment,
/// and any `user:pass@` credentials.
///
/// ```
/// use specter_core::redact::redact_url;
/// assert_eq!(
///     redact_url("https://mainnet.infura.io/v3/abcdef123456"),
///     "https://mainnet.infura.io"
/// );
/// ```
pub fn redact_url(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (Some(s), r),
        None => (None, url),
    };

    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    // Strip `user:pass@` — credentials are as sensitive as a key in the path.
    let host = match authority.rsplit_once('@') {
        Some((_creds, h)) => h,
        None => authority,
    };

    match scheme {
        Some(s) => format!("{s}://{host}"),
        None => host.to_string(),
    }
}

/// Redacts every URL embedded in an arbitrary message, preserving the
/// surrounding text so the error stays diagnosable.
///
/// Used on upstream error strings before they are logged or stored.
///
/// ```
/// use specter_core::redact::sanitize_error;
/// let msg = "error sending request for url (https://h.io/v3/SECRET): timed out";
/// assert!(!sanitize_error(msg).contains("SECRET"));
/// ```
pub fn sanitize_error(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut rest = message;

    while let Some(pos) = rest.find("://") {
        // Everything before the scheme separator is ordinary prose, but the
        // scheme itself is glued to the preceding word — keep it intact.
        let (head, tail) = rest.split_at(pos);
        out.push_str(head);
        out.push_str("://");

        let after = &tail[3..];
        // The authority ends at the first path/query/fragment/delimiter char.
        let auth_end = after
            .find(|c: char| {
                c == '/'
                    || c == '?'
                    || c == '#'
                    || c.is_whitespace()
                    || matches!(c, ')' | ']' | ',' | '"' | '\'')
            })
            .unwrap_or(after.len());
        let authority = &after[..auth_end];
        let host = match authority.rsplit_once('@') {
            Some((_creds, h)) => h,
            None => authority,
        };
        out.push_str(host);

        // Drop the path/query, stopping at whatever ends the URL in the prose.
        let remainder = &after[auth_end..];
        let url_end = remainder
            .find(|c: char| c.is_whitespace() || matches!(c, ')' | ']' | ',' | '"' | '\''))
            .unwrap_or(remainder.len());
        if url_end > 0 {
            out.push_str("/<redacted>");
        }
        rest = &remainder[url_end..];
    }

    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "491b68b60b4e432ab0fee1febb9278f3";

    #[test]
    fn redact_url_drops_the_api_key_path() {
        assert_eq!(
            redact_url(&format!("https://mainnet.infura.io/v3/{KEY}")),
            "https://mainnet.infura.io"
        );
    }

    #[test]
    fn redact_url_drops_basic_auth_credentials() {
        assert_eq!(
            redact_url("https://user:hunter2@rpc.example.com/path"),
            "https://rpc.example.com"
        );
    }

    #[test]
    fn redact_url_drops_query_string_keys() {
        assert_eq!(
            redact_url("https://rpc.example.com?apikey=SECRET"),
            "https://rpc.example.com"
        );
    }

    #[test]
    fn redact_url_keeps_the_port() {
        assert_eq!(
            redact_url("https://fullnode.testnet.sui.io:443/x"),
            "https://fullnode.testnet.sui.io:443"
        );
    }

    #[test]
    fn redact_url_handles_a_bare_host() {
        assert_eq!(redact_url("rpc.example.com/v3/key"), "rpc.example.com");
    }

    #[test]
    fn sanitize_error_redacts_the_reqwest_transport_message() {
        // The exact shape reqwest produces.
        let msg = format!("error sending request for url (https://mainnet.infura.io/v3/{KEY})");
        let out = sanitize_error(&msg);
        assert!(!out.contains(KEY), "api key survived redaction: {out}");
        assert!(
            out.contains("mainnet.infura.io"),
            "host must survive: {out}"
        );
        assert!(
            out.starts_with("error sending request"),
            "prose must survive: {out}"
        );
    }

    #[test]
    fn sanitize_error_redacts_every_url_in_one_message() {
        let msg = format!(
            "primary https://a.io/v3/{KEY} failed, secondary https://b.io/v2/{KEY} failed too"
        );
        let out = sanitize_error(&msg);
        assert!(!out.contains(KEY));
        assert!(out.contains("a.io") && out.contains("b.io"));
    }

    #[test]
    fn sanitize_error_redacts_credentials_in_message_urls() {
        let out = sanitize_error("connect to https://user:hunter2@rpc.example.com/v3/k refused");
        assert!(!out.contains("hunter2"), "credentials survived: {out}");
        assert!(out.contains("rpc.example.com"));
    }

    #[test]
    fn sanitize_error_leaves_plain_prose_untouched() {
        let msg = "Method not found. JSON-RPC on public fullnodes has been deprecated.";
        assert_eq!(sanitize_error(msg), msg);
    }

    #[test]
    fn sanitize_error_is_idempotent() {
        let once = sanitize_error(&format!("url (https://h.io/v3/{KEY})"));
        assert_eq!(sanitize_error(&once), once);
    }

    #[test]
    fn sanitize_error_handles_a_url_with_no_path() {
        assert_eq!(
            sanitize_error("failed https://h.io done"),
            "failed https://h.io done"
        );
    }

    /// Property-ish sweep: no redaction output may contain the secret.
    #[test]
    fn no_shape_of_url_leaks_the_key() {
        let shapes = [
            format!("https://h.io/v3/{KEY}"),
            format!("https://h.io/{KEY}/rpc"),
            format!("https://h.io:8545/v3/{KEY}"),
            format!("http://h.io/v3/{KEY}?x=1"),
            format!("https://u:{KEY}@h.io/"),
            format!("error for url (https://h.io/v3/{KEY}): timed out"),
            format!("[https://h.io/v3/{KEY}]"),
            format!("\"https://h.io/v3/{KEY}\""),
        ];
        for s in shapes {
            let red = redact_url(&s);
            let san = sanitize_error(&s);
            assert!(!red.contains(KEY), "redact_url leaked for {s:?} -> {red}");
            assert!(
                !san.contains(KEY),
                "sanitize_error leaked for {s:?} -> {san}"
            );
        }
    }
}
