/// Normalize a configured DNS name to the lowercase Punycode form used by
/// Cloudflare's API. A wildcard is only valid as the complete leftmost label.
pub fn normalize_name(input: &str) -> Result<String, String> {
    let input = input.trim().trim_end_matches('.');
    let (wildcard, name) = match input.strip_prefix("*.") {
        Some(name) => (true, name),
        None => (false, input),
    };
    if name.is_empty() || name.contains('*') {
        return Err(format!("Invalid domain name '{input}'"));
    }

    let ascii = idna::domain_to_ascii(name)
        .map_err(|error| format!("Invalid domain name '{input}': {error}"))?
        .to_ascii_lowercase();
    if ascii.len() > 253
        || ascii.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(format!("Invalid domain name '{input}'"));
    }

    Ok(if wildcard {
        format!("*.{ascii}")
    } else {
        ascii
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_idn_and_wildcard_names() {
        assert_eq!(normalize_name("例子.COM.").unwrap(), "xn--fsqu00a.com");
        assert_eq!(normalize_name("*.例子.com").unwrap(), "*.xn--fsqu00a.com");
        assert!(normalize_name("bad.*.example.com").is_err());
    }

    /// A wildcard is only meaningful as the whole leftmost label, and names must
    /// survive the label-level checks Cloudflare applies.
    #[test]
    fn rejects_malformed_names() {
        for name in [
            "",
            ".",
            "*",
            "*.",
            "bad.*.example.com",
            "-leading.example.com",
            "trailing-.example.com",
            "under_score.example.com",
            "empty..label.com",
        ] {
            assert!(normalize_name(name).is_err(), "{name:?} should be rejected");
        }
    }
}
