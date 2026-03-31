/// Malicious package injected as a transitive dependency of axios.
pub const MALICIOUS_PACKAGE: &str = "plain-crypto-js";

/// Known malicious versions of the package.
pub const MALICIOUS_VERSIONS: &[&str] = &["4.2.0", "4.2.1"];

/// npm security placeholder version (known safe).
pub const SECURITY_HOLDER_VERSION: &str = "0.0.1-security";

/// axios version named in the original security advisory.
pub const ALERT_AXIOS_VERSION: &str = "1.14.1";

/// Suspicious patterns found in the malicious payload's JavaScript files.
/// The payload stages a loader via temp directories and `child_process.execSync`.
pub const PAYLOAD_INDICATORS: &[&str] = &[
    "execSync",
    "ProgramData",
    "os.tmpdir",
    "renameSync",
    "unlinkSync",
    "writeFileSync",
    "copyFileSync",
];

/// Minimum number of payload indicators required to classify as compromised.
pub const PAYLOAD_INDICATOR_THRESHOLD: usize = 3;
