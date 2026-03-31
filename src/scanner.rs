use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::ioc::{
    ALERT_AXIOS_VERSION, MALICIOUS_PACKAGE, MALICIOUS_VERSIONS, PAYLOAD_INDICATORS,
    PAYLOAD_INDICATOR_THRESHOLD, SECURITY_HOLDER_VERSION,
};
use crate::json::Json;
use crate::report::{display_relative, Finding, ScanReport, Source, Status};

const SKIP_DIRS: &[&str] = &[
    ".git", ".hg", ".svn", ".idea", ".vscode", "target", "dist", "build", "coverage", ".next",
];

struct ScanState {
    seen: HashSet<String>,
    axios_manifests: Vec<PathBuf>,
    lockfiles: Vec<PathBuf>,
    node_modules: Vec<PathBuf>,
}

impl ScanState {
    fn new() -> Self {
        Self {
            seen: HashSet::new(),
            axios_manifests: Vec::new(),
            lockfiles: Vec::new(),
            node_modules: Vec::new(),
        }
    }
}

/// Scan a repository root for IOCs related to the axios supply-chain incident.
///
/// # Errors
///
/// Returns an I/O error if the root path cannot be canonicalized or any file
/// encountered during the scan cannot be read.
pub fn scan(root: &Path) -> io::Result<ScanReport> {
    let root = fs::canonicalize(root)?;
    let mut report = ScanReport::new(root.clone());
    let mut state = ScanState::new();

    walk(&root, &mut report, &mut state)?;
    finalize(&mut report, &state);

    Ok(report)
}

fn walk(dir: &Path, report: &mut ScanReport, state: &mut ScanState) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        let name = entry.file_name();
        let name = name.to_string_lossy();

        if ft.is_symlink() {
            continue;
        }

        if ft.is_dir() {
            if SKIP_DIRS.contains(&name.as_ref()) {
                continue;
            }
            if name == "node_modules" {
                state.node_modules.push(path.clone());
                inspect_node_modules(&path, report, state)?;
                continue;
            }
            walk(&path, report, state)?;
            continue;
        }

        if !ft.is_file() {
            continue;
        }

        match name.as_ref() {
            "package.json" => inspect_manifest(&path, report, state)?,
            "package-lock.json" | "npm-shrinkwrap.json" => {
                inspect_npm_lockfile(&path, report, state)?;
            }
            "yarn.lock" => inspect_yarn_lockfile(&path, report, state)?,
            "pnpm-lock.yaml" => inspect_pnpm_lockfile(&path, report, state)?,
            "bun.lock" | "bun.lockb" => inspect_bun_lockfile(&path, report, state)?,
            _ => {}
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Manifest (package.json)
// ---------------------------------------------------------------------------

fn inspect_manifest(path: &Path, report: &mut ScanReport, state: &mut ScanState) -> io::Result<()> {
    let content = fs::read_to_string(path)?;
    let Ok(json) = Json::parse(&content) else {
        return Ok(());
    };

    let deps = collect_dependency_specs(&json);

    if let Some(spec) = deps.get("axios") {
        state.axios_manifests.push(path.to_path_buf());
        if spec.contains(ALERT_AXIOS_VERSION) {
            emit(
                report,
                state,
                Finding {
                    status: Status::AtRisk,
                    source: Source::Manifest,
                    path: path.to_path_buf(),
                    detail: format!(
                        "Manifest references axios spec `{spec}`, which includes alert version {ALERT_AXIOS_VERSION}."
                    ),
                },
            );
        }
    }

    if let Some(spec) = deps.get(MALICIOUS_PACKAGE) {
        emit(
            report,
            state,
            Finding {
                status: Status::AtRisk,
                source: Source::Manifest,
                path: path.to_path_buf(),
                detail: format!(
                    "Manifest directly references {MALICIOUS_PACKAGE} with spec `{spec}`."
                ),
            },
        );
    }

    Ok(())
}

fn collect_dependency_specs(json: &Json) -> HashMap<String, String> {
    let mut deps = HashMap::new();
    for key in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        if let Some(obj) = json.get(key).and_then(Json::as_object) {
            for (name, spec) in obj {
                if let Some(s) = spec.as_str() {
                    deps.insert(name.clone(), s.to_string());
                }
            }
        }
    }
    deps
}

// ---------------------------------------------------------------------------
// npm lockfile (package-lock.json, npm-shrinkwrap.json)
// ---------------------------------------------------------------------------

fn inspect_npm_lockfile(
    path: &Path,
    report: &mut ScanReport,
    state: &mut ScanState,
) -> io::Result<()> {
    state.lockfiles.push(path.to_path_buf());
    let content = fs::read_to_string(path)?;
    let Ok(json) = Json::parse(&content) else {
        return Ok(());
    };

    // lockfile v2/v3: "packages" section
    if let Some(packages) = json.get("packages").and_then(Json::as_object) {
        for (key, entry) in packages {
            let pkg_name = key.rsplit('/').next().unwrap_or(key);
            let version = entry
                .get("version")
                .and_then(Json::as_str)
                .unwrap_or_default();
            check_lockfile_entry(pkg_name, version, entry, path, report, state);
        }
    }

    // lockfile v1: "dependencies" section
    if let Some(deps) = json.get("dependencies").and_then(Json::as_object) {
        for (name, entry) in deps {
            let version = entry
                .get("version")
                .and_then(Json::as_str)
                .unwrap_or_default();
            check_lockfile_entry(name, version, entry, path, report, state);
        }
    }

    Ok(())
}

fn check_lockfile_entry(
    name: &str,
    version: &str,
    entry: &Json,
    path: &Path,
    report: &mut ScanReport,
    state: &mut ScanState,
) {
    if name == MALICIOUS_PACKAGE && MALICIOUS_VERSIONS.contains(&version) {
        emit(
            report,
            state,
            Finding {
                status: Status::Compromised,
                source: Source::Lockfile,
                path: path.to_path_buf(),
                detail: format!(
                    "Lockfile resolves {MALICIOUS_PACKAGE}@{version}, a known malicious version."
                ),
            },
        );
    }

    if name == "axios" {
        if version == ALERT_AXIOS_VERSION {
            emit(
                report,
                state,
                Finding {
                    status: Status::AtRisk,
                    source: Source::Lockfile,
                    path: path.to_path_buf(),
                    detail: format!(
                        "Lockfile references axios@{ALERT_AXIOS_VERSION}, the version named in the advisory."
                    ),
                },
            );
        }

        let has_malicious_dep = ["dependencies", "requires"].iter().any(|key| {
            entry
                .get(key)
                .is_some_and(|obj| obj.contains_key(MALICIOUS_PACKAGE))
        });

        if has_malicious_dep {
            emit(
                report,
                state,
                Finding {
                    status: Status::Compromised,
                    source: Source::Lockfile,
                    path: path.to_path_buf(),
                    detail: format!("Lockfile records axios depending on {MALICIOUS_PACKAGE}."),
                },
            );
        }
    }
}

// ---------------------------------------------------------------------------
// yarn lockfile
// ---------------------------------------------------------------------------

fn inspect_yarn_lockfile(
    path: &Path,
    report: &mut ScanReport,
    state: &mut ScanState,
) -> io::Result<()> {
    state.lockfiles.push(path.to_path_buf());
    let content = fs::read_to_string(path)?;

    for block in parse_yarn_blocks(&content) {
        if block.package_matches(MALICIOUS_PACKAGE) {
            if let Some(ver) = &block.version {
                if MALICIOUS_VERSIONS.contains(&ver.as_str()) {
                    emit(
                        report,
                        state,
                        Finding {
                            status: Status::Compromised,
                            source: Source::Lockfile,
                            path: path.to_path_buf(),
                            detail: format!(
                                "Yarn lockfile resolves {MALICIOUS_PACKAGE}@{ver}, a known malicious version."
                            ),
                        },
                    );
                }
            }
        }

        if block.package_matches("axios") {
            if let Some(ver) = &block.version {
                if ver == ALERT_AXIOS_VERSION {
                    emit(
                        report,
                        state,
                        Finding {
                            status: Status::AtRisk,
                            source: Source::Lockfile,
                            path: path.to_path_buf(),
                            detail: format!(
                                "Yarn lockfile resolves axios@{ALERT_AXIOS_VERSION}, the version named in the advisory."
                            ),
                        },
                    );
                }
            }

            if block.has_dependency(MALICIOUS_PACKAGE) {
                emit(
                    report,
                    state,
                    Finding {
                        status: Status::Compromised,
                        source: Source::Lockfile,
                        path: path.to_path_buf(),
                        detail: format!(
                            "Yarn lockfile records axios depending on {MALICIOUS_PACKAGE}."
                        ),
                    },
                );
            }
        }
    }

    Ok(())
}

struct YarnBlock {
    header: String,
    version: Option<String>,
    dependencies: Vec<String>,
}

impl YarnBlock {
    fn package_matches(&self, name: &str) -> bool {
        self.header.contains(&format!("{name}@")) || self.header.contains(&format!("\"{name}@"))
    }

    fn has_dependency(&self, name: &str) -> bool {
        self.dependencies.iter().any(|d| d == name)
    }
}

fn parse_yarn_blocks(content: &str) -> Vec<YarnBlock> {
    let mut blocks = Vec::new();
    let mut header = String::new();
    let mut version: Option<String> = None;
    let mut deps: Vec<String> = Vec::new();
    let mut in_deps = false;

    for line in content.lines() {
        let trimmed = line.trim_end();

        // Header: non-indented, non-empty, non-comment
        let is_header = !trimmed.is_empty() && !line.starts_with(' ') && !line.starts_with('#');

        if is_header {
            if !header.is_empty() {
                blocks.push(YarnBlock {
                    header: header.clone(),
                    version: version.take(),
                    dependencies: std::mem::take(&mut deps),
                });
            }
            header = trimmed.to_string();
            in_deps = false;
            continue;
        }

        if header.is_empty() {
            continue;
        }

        let stripped = trimmed.trim_start();

        // Section headers at 2-space indent
        if stripped.ends_with(':') && !line.starts_with("    ") {
            in_deps = stripped == "dependencies:";
            if stripped.starts_with("version") {
                version = extract_yarn_value(stripped);
            }
            continue;
        }

        // `version "x.y.z"` as a key-value pair (not a section)
        if stripped.starts_with("version ") && version.is_none() {
            version = extract_yarn_value(stripped);
            in_deps = false;
            continue;
        }

        // Dependency entry at 4-space indent
        if in_deps && line.starts_with("    ") {
            let dep_name = stripped
                .split_whitespace()
                .next()
                .or_else(|| stripped.split(':').next())
                .unwrap_or("")
                .trim_matches('"');
            if !dep_name.is_empty() {
                deps.push(dep_name.to_string());
            }
        }
    }

    if !header.is_empty() {
        blocks.push(YarnBlock {
            header,
            version,
            dependencies: deps,
        });
    }

    blocks
}

fn extract_yarn_value(line: &str) -> Option<String> {
    // "version 1.14.1" or "version: 1.14.1" or 'version "1.14.1"'
    let rest = line
        .strip_prefix("version")
        .unwrap_or(line)
        .trim_start_matches([':', ' ']);
    let value = rest.trim().trim_matches('"').trim_matches('\'');
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

// ---------------------------------------------------------------------------
// pnpm lockfile
// ---------------------------------------------------------------------------

fn inspect_pnpm_lockfile(
    path: &Path,
    report: &mut ScanReport,
    state: &mut ScanState,
) -> io::Result<()> {
    state.lockfiles.push(path.to_path_buf());
    let content = fs::read_to_string(path)?;

    for version in MALICIOUS_VERSIONS {
        if pnpm_has_package_version(&content, MALICIOUS_PACKAGE, version) {
            emit(
                report,
                state,
                Finding {
                    status: Status::Compromised,
                    source: Source::Lockfile,
                    path: path.to_path_buf(),
                    detail: format!(
                        "pnpm lockfile resolves {MALICIOUS_PACKAGE}@{version}, a known malicious version."
                    ),
                },
            );
        }
    }

    if pnpm_has_package_version(&content, "axios", ALERT_AXIOS_VERSION) {
        emit(
            report,
            state,
            Finding {
                status: Status::AtRisk,
                source: Source::Lockfile,
                path: path.to_path_buf(),
                detail: format!(
                    "pnpm lockfile resolves axios@{ALERT_AXIOS_VERSION}, the version named in the advisory."
                ),
            },
        );
    }

    Ok(())
}

fn pnpm_has_package_version(content: &str, package: &str, version: &str) -> bool {
    // v5: /package/version:    v6+: package@version:  (optionally quoted)
    let patterns = [
        format!("/{package}/{version}:"),
        format!("/{package}/{version}\n"),
        format!("{package}@{version}:"),
        format!("{package}@{version}\n"),
        format!("'{package}@{version}'"),
        format!("\"{package}@{version}\""),
    ];
    patterns.iter().any(|p| content.contains(p.as_str()))
}

// ---------------------------------------------------------------------------
// bun lockfile
// ---------------------------------------------------------------------------

fn inspect_bun_lockfile(
    path: &Path,
    report: &mut ScanReport,
    state: &mut ScanState,
) -> io::Result<()> {
    state.lockfiles.push(path.to_path_buf());
    let bytes = fs::read(path)?;
    let content = String::from_utf8_lossy(&bytes);

    for version in MALICIOUS_VERSIONS {
        let patterns = [
            format!("{MALICIOUS_PACKAGE}@{version}"),
            format!("\"{MALICIOUS_PACKAGE}\": \"{version}\""),
        ];
        if patterns.iter().any(|p| content.contains(p.as_str())) {
            emit(
                report,
                state,
                Finding {
                    status: Status::Compromised,
                    source: Source::Lockfile,
                    path: path.to_path_buf(),
                    detail: format!(
                        "Bun lockfile references {MALICIOUS_PACKAGE}@{version}, a known malicious version."
                    ),
                },
            );
        }
    }

    let axios_patterns = [
        format!("axios@{ALERT_AXIOS_VERSION}"),
        format!("\"axios\": \"{ALERT_AXIOS_VERSION}\""),
    ];
    if axios_patterns.iter().any(|p| content.contains(p.as_str())) {
        emit(
            report,
            state,
            Finding {
                status: Status::AtRisk,
                source: Source::Lockfile,
                path: path.to_path_buf(),
                detail: format!(
                    "Bun lockfile references axios@{ALERT_AXIOS_VERSION}, the version named in the advisory."
                ),
            },
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// node_modules inspection
// ---------------------------------------------------------------------------

fn inspect_node_modules(
    base: &Path,
    report: &mut ScanReport,
    state: &mut ScanState,
) -> io::Result<()> {
    walk_node_modules(base, base, 0, report, state)
}

fn walk_node_modules(
    base: &Path,
    dir: &Path,
    depth: usize,
    report: &mut ScanReport,
    state: &mut ScanState,
) -> io::Result<()> {
    if depth > 8 {
        return Ok(());
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        let name = entry.file_name();
        let name = name.to_string_lossy();

        if ft.is_symlink() {
            continue;
        }

        if ft.is_dir() {
            if name == ".bin" {
                continue;
            }
            walk_node_modules(base, &path, depth + 1, report, state)?;
            continue;
        }

        if !ft.is_file() || name != "package.json" {
            continue;
        }

        let parent_name = path
            .parent()
            .and_then(Path::file_name)
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        if parent_name == MALICIOUS_PACKAGE || parent_name == "axios" {
            inspect_installed_package(base, &path, report, state)?;
        }
    }

    Ok(())
}

fn inspect_installed_package(
    node_modules_root: &Path,
    path: &Path,
    report: &mut ScanReport,
    state: &mut ScanState,
) -> io::Result<()> {
    let content = fs::read_to_string(path)?;
    let Ok(json) = Json::parse(&content) else {
        return Ok(());
    };

    let name = json.get("name").and_then(Json::as_str).unwrap_or_default();
    let version = json
        .get("version")
        .and_then(Json::as_str)
        .unwrap_or_default();

    if name == "axios" && !version.is_empty() {
        if version == ALERT_AXIOS_VERSION {
            emit(
                report,
                state,
                Finding {
                    status: Status::AtRisk,
                    source: Source::InstalledPackage,
                    path: path.to_path_buf(),
                    detail: format!(
                        "Installed axios version is {version}, the version named in the advisory."
                    ),
                },
            );
        }

        let has_malicious_dep = json
            .get("dependencies")
            .is_some_and(|deps| deps.contains_key(MALICIOUS_PACKAGE));

        if has_malicious_dep {
            emit(
                report,
                state,
                Finding {
                    status: Status::Compromised,
                    source: Source::InstalledPackage,
                    path: path.to_path_buf(),
                    detail: format!(
                        "Installed axios declares {MALICIOUS_PACKAGE} as a dependency."
                    ),
                },
            );
        }
    }

    if name == MALICIOUS_PACKAGE {
        if MALICIOUS_VERSIONS.contains(&version) {
            emit(
                report,
                state,
                Finding {
                    status: Status::Compromised,
                    source: Source::InstalledPackage,
                    path: path.to_path_buf(),
                    detail: format!(
                        "Installed {MALICIOUS_PACKAGE} version is {version}, a known malicious version."
                    ),
                },
            );
        } else if !version.is_empty() && version != SECURITY_HOLDER_VERSION {
            emit(
                report,
                state,
                Finding {
                    status: Status::AtRisk,
                    source: Source::InstalledPackage,
                    path: path.to_path_buf(),
                    detail: format!(
                        "Installed {MALICIOUS_PACKAGE} version is {version}; only {SECURITY_HOLDER_VERSION} is known-safe."
                    ),
                },
            );
        }

        if let Some(pkg_dir) = path.parent() {
            inspect_payload(pkg_dir, node_modules_root, report, state)?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Payload analysis
// ---------------------------------------------------------------------------

fn inspect_payload(
    pkg_dir: &Path,
    node_modules_root: &Path,
    report: &mut ScanReport,
    state: &mut ScanState,
) -> io::Result<()> {
    let mut matched = Vec::new();
    collect_payload_indicators(pkg_dir, 0, &mut matched)?;

    if matched.len() >= PAYLOAD_INDICATOR_THRESHOLD {
        let display = pkg_dir
            .strip_prefix(node_modules_root)
            .map_or_else(|_| pkg_dir.to_path_buf(), Path::to_path_buf);
        emit(
            report,
            state,
            Finding {
                status: Status::Compromised,
                source: Source::InstalledPackage,
                path: display,
                detail: format!(
                    "{MALICIOUS_PACKAGE} package contains multiple loader indicators: {}.",
                    matched.join(", "),
                ),
            },
        );
    }

    Ok(())
}

fn collect_payload_indicators(
    dir: &Path,
    depth: usize,
    matched: &mut Vec<String>,
) -> io::Result<()> {
    if depth > 3 || matched.len() == PAYLOAD_INDICATORS.len() {
        return Ok(());
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;

        if ft.is_symlink() {
            continue;
        }

        if ft.is_dir() {
            collect_payload_indicators(&path, depth + 1, matched)?;
            continue;
        }

        if !ft.is_file() {
            continue;
        }

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        if !matches!(ext, "js" | "cjs" | "mjs") {
            continue;
        }

        let content = fs::read_to_string(&path).unwrap_or_default();
        for &indicator in PAYLOAD_INDICATORS {
            if content.contains(indicator) && !matched.iter().any(|m| m == indicator) {
                matched.push(indicator.to_string());
            }
        }

        if matched.len() == PAYLOAD_INDICATORS.len() {
            break;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Finalization
// ---------------------------------------------------------------------------

fn finalize(report: &mut ScanReport, state: &ScanState) {
    if report.status == Status::NoEvidenceFound
        && !state.axios_manifests.is_empty()
        && state.lockfiles.is_empty()
        && state.node_modules.is_empty()
    {
        let paths: Vec<String> = state
            .axios_manifests
            .iter()
            .take(3)
            .map(|p| display_relative(&report.root, p))
            .collect();
        let suffix = if state.axios_manifests.len() > 3 {
            format!(" and {} more", state.axios_manifests.len() - 3)
        } else {
            String::new()
        };
        let detail = format!(
            "Axios is declared in {}{suffix}, but no lockfile or node_modules tree was found to verify the resolved install.",
            paths.join(", "),
        );
        let path = state.axios_manifests[0].clone();
        report.push_finding(Finding {
            status: Status::AtRisk,
            source: Source::Manifest,
            path,
            detail,
        });
    }

    if !state.axios_manifests.is_empty() {
        report.notes.push(format!(
            "Axios was declared in {} manifest(s).",
            state.axios_manifests.len(),
        ));
    }

    if !state.lockfiles.is_empty() {
        report
            .notes
            .push(format!("Scanned {} lockfile(s).", state.lockfiles.len(),));
    }

    if !state.node_modules.is_empty() {
        report.notes.push(format!(
            "Inspected {} node_modules tree(s).",
            state.node_modules.len(),
        ));
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn emit(report: &mut ScanReport, state: &mut ScanState, finding: Finding) {
    let key = format!(
        "{}|{:?}|{}|{}",
        finding.status,
        finding.source,
        finding.path.display(),
        finding.detail,
    );
    if state.seen.insert(key) {
        report.push_finding(finding);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        path: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let id = format!(
                "{}-{}-{:?}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
            );
            let path = std::env::temp_dir().join(format!("axioscan-test-{id}"));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn write_file(&self, relative: &str, contents: &str) {
            let full = self.path.join(relative);
            if let Some(parent) = full.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            let mut f = File::create(full).unwrap();
            f.write_all(contents.as_bytes()).unwrap();
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    // -- Clean repo --

    #[test]
    fn clean_repo_reports_no_evidence() {
        let fix = Fixture::new();
        fix.write_file(
            "package.json",
            r#"{"name": "app", "dependencies": {"react": "^19.0.0"}}"#,
        );
        fix.write_file(
            "package-lock.json",
            r#"{"name": "app", "lockfileVersion": 3, "packages": {"": {"dependencies": {"react": "^19.0.0"}}}}"#,
        );

        let report = scan(fix.path()).unwrap();
        assert_eq!(report.status, Status::NoEvidenceFound);
        assert!(report.findings.is_empty());
    }

    // -- Manifest-only detection --

    #[test]
    fn axios_in_manifest_without_lockfile_is_at_risk() {
        let fix = Fixture::new();
        fix.write_file(
            "package.json",
            r#"{"name": "app", "dependencies": {"axios": "^1.14.0"}}"#,
        );

        let report = scan(fix.path()).unwrap();
        assert_eq!(report.status, Status::AtRisk);
        assert!(report
            .findings
            .iter()
            .any(|f| f.detail.contains("no lockfile")));
    }

    #[test]
    fn manifest_with_alert_version_is_at_risk() {
        let fix = Fixture::new();
        fix.write_file(
            "package.json",
            r#"{"name": "app", "dependencies": {"axios": "1.14.1"}}"#,
        );

        let report = scan(fix.path()).unwrap();
        assert_eq!(report.status, Status::AtRisk);
    }

    #[test]
    fn manifest_referencing_malicious_package_is_at_risk() {
        let fix = Fixture::new();
        fix.write_file(
            "package.json",
            r#"{"name": "app", "dependencies": {"plain-crypto-js": "^4.2.0"}}"#,
        );

        let report = scan(fix.path()).unwrap();
        assert_eq!(report.status, Status::AtRisk);
        assert!(report
            .findings
            .iter()
            .any(|f| f.detail.contains("plain-crypto-js")));
    }

    // -- npm lockfile detection --

    #[test]
    fn npm_lockfile_v3_with_malicious_package_is_compromised() {
        let fix = Fixture::new();
        fix.write_file(
            "package-lock.json",
            r#"{
                "name": "app",
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"axios": "^1.14.0"}},
                    "node_modules/plain-crypto-js": {"version": "4.2.1"}
                }
            }"#,
        );

        let report = scan(fix.path()).unwrap();
        assert_eq!(report.status, Status::Compromised);
        assert!(report
            .findings
            .iter()
            .any(|f| f.detail.contains("plain-crypto-js@4.2.1")));
    }

    #[test]
    fn npm_lockfile_v1_with_malicious_dependency_is_compromised() {
        let fix = Fixture::new();
        fix.write_file(
            "package-lock.json",
            r#"{
                "name": "app",
                "lockfileVersion": 1,
                "dependencies": {
                    "axios": {
                        "version": "1.14.1",
                        "requires": {"plain-crypto-js": "^4.2.1"}
                    }
                }
            }"#,
        );

        let report = scan(fix.path()).unwrap();
        assert_eq!(report.status, Status::Compromised);
        assert!(report
            .findings
            .iter()
            .any(|f| f.detail.contains("depending on plain-crypto-js")));
    }

    #[test]
    fn npm_lockfile_with_axios_alert_version_is_at_risk() {
        let fix = Fixture::new();
        fix.write_file(
            "package-lock.json",
            r#"{
                "name": "app",
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/axios": {"version": "1.14.1"}
                }
            }"#,
        );

        let report = scan(fix.path()).unwrap();
        assert_eq!(report.status, Status::AtRisk);
    }

    // -- yarn lockfile detection --

    #[test]
    fn yarn_lockfile_with_malicious_version_is_compromised() {
        let fix = Fixture::new();
        fix.write_file(
            "yarn.lock",
            r#"# yarn lockfile v1

plain-crypto-js@^4.2.0:
  version "4.2.0"
  resolved "https://registry.yarnpkg.com/plain-crypto-js/-/plain-crypto-js-4.2.0.tgz#abc"
"#,
        );

        let report = scan(fix.path()).unwrap();
        assert_eq!(report.status, Status::Compromised);
    }

    #[test]
    fn yarn_lockfile_axios_with_malicious_dep_is_compromised() {
        let fix = Fixture::new();
        fix.write_file(
            "yarn.lock",
            r#"# yarn lockfile v1

axios@^1.14.0:
  version "1.14.0"
  dependencies:
    plain-crypto-js "^4.2.1"
"#,
        );

        let report = scan(fix.path()).unwrap();
        assert_eq!(report.status, Status::Compromised);
    }

    // -- pnpm lockfile detection --

    #[test]
    fn pnpm_lockfile_v5_with_malicious_package_is_compromised() {
        let fix = Fixture::new();
        fix.write_file(
            "pnpm-lock.yaml",
            "lockfileVersion: 5.4\npackages:\n  /plain-crypto-js/4.2.1:\n    resolution: {integrity: sha512-abc}\n",
        );

        let report = scan(fix.path()).unwrap();
        assert_eq!(report.status, Status::Compromised);
    }

    #[test]
    fn pnpm_lockfile_v6_with_malicious_package_is_compromised() {
        let fix = Fixture::new();
        fix.write_file(
            "pnpm-lock.yaml",
            "lockfileVersion: '6.0'\npackages:\n  plain-crypto-js@4.2.0:\n    resolution: {integrity: sha512-abc}\n",
        );

        let report = scan(fix.path()).unwrap();
        assert_eq!(report.status, Status::Compromised);
    }

    // -- bun lockfile detection --

    #[test]
    fn bun_lockfile_with_malicious_package_is_compromised() {
        let fix = Fixture::new();
        fix.write_file("bun.lock", "plain-crypto-js@4.2.1\n");

        let report = scan(fix.path()).unwrap();
        assert_eq!(report.status, Status::Compromised);
    }

    // -- node_modules detection --

    #[test]
    fn installed_axios_with_malicious_dep_is_compromised() {
        let fix = Fixture::new();
        fix.write_file(
            "node_modules/axios/package.json",
            r#"{"name": "axios", "version": "1.14.0", "dependencies": {"plain-crypto-js": "^4.2.1"}}"#,
        );

        let report = scan(fix.path()).unwrap();
        assert_eq!(report.status, Status::Compromised);
        assert!(report
            .findings
            .iter()
            .any(|f| f.detail.contains("declares plain-crypto-js")));
    }

    #[test]
    fn installed_malicious_package_is_compromised() {
        let fix = Fixture::new();
        fix.write_file(
            "node_modules/plain-crypto-js/package.json",
            r#"{"name": "plain-crypto-js", "version": "4.2.1"}"#,
        );

        let report = scan(fix.path()).unwrap();
        assert_eq!(report.status, Status::Compromised);
    }

    #[test]
    fn installed_security_holder_version_is_safe() {
        let fix = Fixture::new();
        fix.write_file(
            "node_modules/plain-crypto-js/package.json",
            r#"{"name": "plain-crypto-js", "version": "0.0.1-security"}"#,
        );

        let report = scan(fix.path()).unwrap();
        assert_eq!(report.status, Status::NoEvidenceFound);
    }

    // -- Payload detection --

    #[test]
    fn payload_with_loader_indicators_is_compromised() {
        let fix = Fixture::new();
        fix.write_file(
            "node_modules/plain-crypto-js/package.json",
            r#"{"name": "plain-crypto-js", "version": "4.2.1"}"#,
        );
        fix.write_file(
            "node_modules/plain-crypto-js/index.js",
            r#"
const { execSync } = require('child_process');
const os = require('os');
const tmpDir = os.tmpdir();
const fs = require('fs');
fs.writeFileSync(tmpDir + '/payload', data);
fs.renameSync(tmpDir + '/payload', tmpDir + '/loader');
"#,
        );

        let report = scan(fix.path()).unwrap();
        assert_eq!(report.status, Status::Compromised);
        assert!(report
            .findings
            .iter()
            .any(|f| f.detail.contains("loader indicators")));
    }

    // -- Deduplication --

    #[test]
    fn duplicate_findings_are_deduplicated() {
        let fix = Fixture::new();
        // Create a scenario that could generate duplicates
        fix.write_file(
            "package-lock.json",
            r#"{
                "name": "app",
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/plain-crypto-js": {"version": "4.2.1"}
                }
            }"#,
        );

        let report = scan(fix.path()).unwrap();
        let matching: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.detail.contains("plain-crypto-js@4.2.1"))
            .collect();
        assert_eq!(matching.len(), 1);
    }

    // -- Yarn block parser --

    #[test]
    fn parse_yarn_blocks_extracts_version_and_deps() {
        let content = r#"# yarn lockfile v1

axios@^1.14.0:
  version "1.14.0"
  resolved "https://registry.yarnpkg.com/axios/-/axios-1.14.0.tgz"
  dependencies:
    follow-redirects "^1.15.6"
    plain-crypto-js "^4.2.1"

react@^19.0.0:
  version "19.0.0"
"#;

        let blocks = parse_yarn_blocks(content);
        assert_eq!(blocks.len(), 2);

        assert!(blocks[0].package_matches("axios"));
        assert_eq!(blocks[0].version.as_deref(), Some("1.14.0"));
        assert!(blocks[0].has_dependency("plain-crypto-js"));
        assert!(blocks[0].has_dependency("follow-redirects"));

        assert!(blocks[1].package_matches("react"));
        assert_eq!(blocks[1].version.as_deref(), Some("19.0.0"));
        assert!(blocks[1].dependencies.is_empty());
    }
}
