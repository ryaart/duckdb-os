//! Secret redaction for command lines and environment variables.
//!
//! Secrets are replaced with `<redacted:xxxxxxxx>`: a keyed hash, so equal secrets get
//! equal fingerprints (the same password in two processes, or an unchanged token across
//! snapshots) without the value being readable. The key is random per process, so
//! fingerprints can't be brute-forced offline, and only compare within one DuckDB session.
//!
//! Detection is pattern-based and will miss secrets in unusual formats.

use regex::{Captures, Regex};
use sha2::{Digest, Sha256};
use std::{io::Read, sync::LazyLock};

static KEY: LazyLock<[u8; 32]> = LazyLock::new(|| {
    let mut key = [0u8; 32];
    let random = std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut key));
    if random.is_err() {
        // No /dev/urandom: fall back to std's randomly seeded hasher.
        use std::hash::{BuildHasher, RandomState};
        for (i, chunk) in key.chunks_mut(8).enumerate() {
            chunk.copy_from_slice(&RandomState::new().hash_one(i).to_le_bytes());
        }
    }
    key
});

pub fn fingerprint(secret: &str) -> String {
    let digest = Sha256::new().chain_update(*KEY).chain_update(secret).finalize();
    let hex: String = digest[..4].iter().map(|b| format!("{b:02x}")).collect();
    format!("<redacted:{hex}>")
}

/// Names of flags and variables whose values are secrets.
static SENSITIVE_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(password|passwd|passphrase|secret|credential|(api|access|private|signing|client|master)[-_.]?key|authorization|oauth|cookie|signature|connection[-_.]?string|(^|[-_.])(pass|pwd|token|auth|key|dsn|session[-_.]?id)($|[-_.]))",
    )
    .unwrap()
});

/// Names that point at a secret rather than containing it (`--password-file`, `TOKEN_PATH`).
static REFERENCE_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)[-_](file|path|dir|env|var)$").unwrap());

fn is_sensitive_name(name: &str) -> bool {
    SENSITIVE_NAME.is_match(name) && !REFERENCE_NAME.is_match(name)
}

/// Secrets recognisable by their shape, wherever they appear. The secret is the last group.
static VALUE_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        // scheme://user:password@host
        r"([a-zA-Z][a-zA-Z0-9+.-]*://[^:/@\s]*:)([^@\s/]+)@",
        // Authorization: Bearer x, X-Api-Key: x, Cookie: x
        r"(?i)((?:authorization|proxy-authorization|x-api-key|api-key|cookie):\s*)(.+)",
        r"(?i)(\b(?:bearer|basic|token)\s+)([A-Za-z0-9._~+/=-]{8,})",
        r"()(\bgh[pousr]_[A-Za-z0-9]{30,}|\bgithub_pat_[A-Za-z0-9_]{20,})",
        r"()(\bglpat-[A-Za-z0-9_-]{20,})",
        r"()(\bxox[abposr]-[A-Za-z0-9-]{10,})",
        r"()(\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,})",
        r"()(\b(?:AKIA|ASIA)[0-9A-Z]{16}\b)",
        r"()(\bAIza[0-9A-Za-z_-]{35})",
        // JWTs
        r"()(\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})",
        r"()(-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*)",
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

/// Redacts secrets recognisable by shape inside `text`.
pub fn redact_value(text: &str) -> String {
    let mut out = text.to_string();
    for re in VALUE_PATTERNS.iter() {
        if re.is_match(&out) {
            out = re
                .replace_all(&out, |c: &Captures| {
                    let whole = c.get(0).unwrap().as_str();
                    let secret = c.get(2).unwrap();
                    let prefix = &whole[..secret.start() - c.get(0).unwrap().start()];
                    let suffix = &whole[secret.end() - c.get(0).unwrap().start()..];
                    format!("{prefix}{}{suffix}", fingerprint(secret.as_str()))
                })
                .into_owned();
        }
    }
    out
}

/// Redacts an environment variable's value.
pub fn redact_env(key: &str, value: &str) -> String {
    if is_sensitive_name(key) && !value.is_empty() {
        fingerprint(value)
    } else {
        redact_value(value)
    }
}

/// Redacts a command line: `--password=x`, `--token x`, `API_KEY=x`, plus shaped secrets.
pub fn redact_args(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut redact_next = false;
    for arg in args {
        if redact_next && !arg.starts_with('-') {
            out.push(fingerprint(arg));
            redact_next = false;
            continue;
        }
        redact_next = false;
        if let Some((name, value)) = arg.split_once('=') {
            let flag = name.trim_start_matches('-');
            let is_name = !flag.is_empty() && flag.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
            if is_name && is_sensitive_name(flag) && !value.is_empty() {
                out.push(format!("{name}={}", fingerprint(value)));
                continue;
            }
        } else if arg.starts_with("--") || (arg.starts_with('-') && arg.len() > 2) {
            redact_next = is_sensitive_name(arg.trim_start_matches('-'));
        }
        out.push(redact_value(arg));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split(' ').map(String::from).collect()
    }

    fn is_fp(s: &str) -> bool {
        s.starts_with("<redacted:") && s.ends_with('>') && s.len() == "<redacted:12345678>".len()
    }

    #[test]
    fn redacts_flags() {
        let out = redact_args(&args("app --password=hunter2 --token abc123 --port 8080 -v --api-key=k"));
        assert_eq!(out[0], "app");
        assert!(out[1].starts_with("--password=") && is_fp(&out[1]["--password=".len()..]));
        assert_eq!(out[2], "--token");
        assert!(is_fp(&out[3]));
        assert_eq!(&out[4..7], &["--port", "8080", "-v"]);
        assert!(is_fp(&out[7]["--api-key=".len()..]));
    }

    #[test]
    fn keeps_references_and_ordinary_flags() {
        let a = args("app --password-file=/run/secrets/db --token-path /x --author=me --keyboard=us --secret");
        let out = redact_args(&a);
        assert_eq!(out[1], "--password-file=/run/secrets/db");
        assert_eq!(&out[2..4], &["--token-path", "/x"]);
        assert_eq!(out[4], "--author=me");
        assert_eq!(out[5], "--keyboard=us");
        // a trailing flag with no value, and a following flag, are left alone
        assert_eq!(out[6], "--secret");
    }

    #[test]
    fn redacts_assignments_urls_and_tokens() {
        // Built from halves so secret scanners don't flag the fake token.
        let token = format!("{}{}", "ghp_", "0123456789abcdefghijklmnopqrstuvwxyz");
        let out = redact_args(&args(&format!(
            "env AWS_SECRET_ACCESS_KEY=abc PATH=/bin psql postgres://app:s3cret@db:5432/x -H Authorization:Bearer_abcdefghijk {token}"
        )));
        assert!(is_fp(&out[1]["AWS_SECRET_ACCESS_KEY=".len()..]));
        assert_eq!(out[2], "PATH=/bin");
        assert!(out[4].starts_with("postgres://app:<redacted:") && out[4].ends_with(">@db:5432/x"), "{}", out[4]);
        assert!(out[6].starts_with("Authorization:<redacted:"), "{}", out[6]);
        assert!(is_fp(&out[7]));
    }

    #[test]
    fn ignores_lookalike_names() {
        let a = args("app --tokenizer=cl100k --bypass-cache=1 --compass=n --keys=3 --passes=2");
        assert_eq!(redact_args(&a), a);
    }

    #[test]
    fn redacts_env() {
        assert!(is_fp(&redact_env("GITHUB_TOKEN", "x")));
        assert!(is_fp(&redact_env("DB_PASSWORD", "x")));
        assert_eq!(redact_env("HOME", "/Users/me"), "/Users/me");
        assert_eq!(redact_env("TOKEN_FILE", "/run/token"), "/run/token");
        assert!(redact_env("DATABASE_URL", "mysql://u:p4ss@h/db").contains("<redacted:"));
        assert!(is_fp(&redact_env("TLS_KEY", "-----BEGIN RSA PRIVATE KEY-----\nabc")));
        assert_eq!(redact_env("EMPTY_TOKEN", ""), "");
    }

    #[test]
    fn fingerprints_are_stable_and_distinct() {
        assert_eq!(fingerprint("a"), fingerprint("a"));
        assert_ne!(fingerprint("a"), fingerprint("b"));
    }
}
