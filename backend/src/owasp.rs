/// CWE → OWASP Top 10 (2021) mapping for common vulnerability classes.
///
/// Used to enrich ZAP alert data with OWASP category information.

/// Look up the OWASP Top 10 code (e.g. "A01") for a given CWE ID.
pub fn cwe_to_owasp(cweid: &str) -> &'static str {
    match cweid {
        // A01: Broken Access Control
        "285" | "639" | "284" | "352" | "22" | "425" | "538" => "A01",
        // A02: Cryptographic Failures
        "327" | "328" | "310" | "326" | "319" | "311" | "312" | "315" => "A02",
        // A03: Injection
        "79" | "89" | "77" | "78" | "90" | "91" | "564" | "917" => "A03",
        // A04: Insecure Design
        "209" | "256" | "501" => "A04",
        // A05: Security Misconfiguration
        "16" | "2" | "215" | "548" | "611" => "A05",
        // A06: Vulnerable and Outdated Components
        "1104" => "A06",
        // A07: Identification and Authentication Failures
        "287" | "384" | "613" | "620" => "A07",
        // A08: Software and Data Integrity Failures
        "345" | "353" | "829" | "502" => "A08",
        // A09: Security Logging and Monitoring Failures
        "778" | "223" => "A09",
        // A10: Server-Side Request Forgery
        "918" => "A10",
        _ => "",
    }
}

/// Get the human-readable OWASP Top 10 category name for a code.
pub fn owasp_name(code: &str) -> &'static str {
    match code {
        "A01" => "Broken Access Control",
        "A02" => "Cryptographic Failures",
        "A03" => "Injection",
        "A04" => "Insecure Design",
        "A05" => "Security Misconfiguration",
        "A06" => "Vulnerable & Outdated Components",
        "A07" => "Auth Failures",
        "A08" => "Integrity Failures",
        "A09" => "Logging & Monitoring Failures",
        "A10" => "SSRF",
        _ => "",
    }
}
