use std::fmt;
use std::path::{Path, PathBuf};

use crate::json::Json;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Status {
    NoEvidenceFound,
    AtRisk,
    Compromised,
}

impl Status {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoEvidenceFound => "no-evidence-found",
            Self::AtRisk => "at-risk",
            Self::Compromised => "compromised",
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Source {
    Manifest,
    Lockfile,
    InstalledPackage,
}

impl Source {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manifest => "manifest",
            Self::Lockfile => "lockfile",
            Self::InstalledPackage => "installed-package",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub status: Status,
    pub source: Source,
    pub path: PathBuf,
    pub detail: String,
}

pub struct ScanReport {
    pub root: PathBuf,
    pub status: Status,
    pub findings: Vec<Finding>,
    pub notes: Vec<String>,
}

impl ScanReport {
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            status: Status::NoEvidenceFound,
            findings: Vec::new(),
            notes: Vec::new(),
        }
    }

    pub fn push_finding(&mut self, finding: Finding) {
        if finding.status > self.status {
            self.status = finding.status;
        }
        self.findings.push(finding);
        self.findings.sort_by(|a, b| {
            b.status
                .cmp(&a.status)
                .then_with(|| a.path.cmp(&b.path))
                .then_with(|| a.detail.cmp(&b.detail))
        });
    }

    #[must_use]
    pub fn render_human(&self) -> String {
        let mut lines = vec![
            format!("Status: {}", self.status),
            format!("Scanned: {}", self.root.display()),
        ];

        if self.findings.is_empty() {
            lines.push("Findings: none".into());
        } else {
            lines.push("Findings:".into());
            for f in &self.findings {
                lines.push(format!(
                    "  - [{}] {} ({})",
                    f.status,
                    f.detail,
                    display_relative(&self.root, &f.path),
                ));
            }
        }

        if !self.notes.is_empty() {
            lines.push("Notes:".into());
            for note in &self.notes {
                lines.push(format!("  - {note}"));
            }
        }

        lines.push("Recommendations:".into());
        for rec in recommendations(self.status) {
            lines.push(format!("  - {rec}"));
        }

        lines.join("\n")
    }

    #[must_use]
    pub fn render_json(&self) -> String {
        let findings: Vec<Json> = self
            .findings
            .iter()
            .map(|f| {
                Json::object(vec![
                    ("status", Json::string(f.status.as_str())),
                    ("source", Json::string(f.source.as_str())),
                    ("path", Json::string(&display_relative(&self.root, &f.path))),
                    ("detail", Json::string(&f.detail)),
                ])
            })
            .collect();

        let notes: Vec<Json> = self.notes.iter().map(|n| Json::string(n)).collect();

        let report = Json::object(vec![
            ("root", Json::string(&self.root.display().to_string())),
            ("status", Json::string(self.status.as_str())),
            ("findings", Json::array(findings)),
            ("notes", Json::array(notes)),
        ]);

        report.to_pretty_string()
    }
}

impl fmt::Display for ScanReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render_human())
    }
}

#[must_use]
pub fn display_relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map_or_else(|_| path.display().to_string(), |p| p.display().to_string())
}

fn recommendations(status: Status) -> &'static [&'static str] {
    match status {
        Status::Compromised => &[
            "Quarantine the repository, remove node_modules and lockfiles, and reinstall after pinning known-good versions.",
            "Rotate any credentials available to builds or developers who ran npm install against this checkout.",
            "Review CI logs, shell history, and temp directories for unexpected payloads or post-install execution.",
        ],
        Status::AtRisk => &[
            "Verify the resolved dependency graph by checking lockfiles or a clean reinstall against pinned versions.",
            "Pin axios and related packages before running npm install in automation or on developer machines.",
            "If you find a suspicious lockfile diff, treat the checkout as compromised and rebuild from a known-good state.",
        ],
        Status::NoEvidenceFound => &[
            "Keep lockfiles committed and review dependency diffs before upgrading transitive packages.",
            "Rescan after dependency updates or after restoring old lockfiles from branches or CI artifacts.",
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_ordering() {
        assert!(Status::Compromised > Status::AtRisk);
        assert!(Status::AtRisk > Status::NoEvidenceFound);
    }

    #[test]
    fn push_finding_escalates_status() {
        let mut report = ScanReport::new(PathBuf::from("/repo"));
        assert_eq!(report.status, Status::NoEvidenceFound);

        report.push_finding(Finding {
            status: Status::AtRisk,
            source: Source::Manifest,
            path: PathBuf::from("/repo/package.json"),
            detail: "test".into(),
        });
        assert_eq!(report.status, Status::AtRisk);

        report.push_finding(Finding {
            status: Status::Compromised,
            source: Source::Lockfile,
            path: PathBuf::from("/repo/package-lock.json"),
            detail: "test".into(),
        });
        assert_eq!(report.status, Status::Compromised);
    }

    #[test]
    fn findings_sorted_by_severity_then_path() {
        let mut report = ScanReport::new(PathBuf::from("/repo"));
        report.push_finding(Finding {
            status: Status::AtRisk,
            source: Source::Manifest,
            path: PathBuf::from("/repo/b.json"),
            detail: "low".into(),
        });
        report.push_finding(Finding {
            status: Status::Compromised,
            source: Source::Lockfile,
            path: PathBuf::from("/repo/a.json"),
            detail: "high".into(),
        });

        assert_eq!(report.findings[0].status, Status::Compromised);
        assert_eq!(report.findings[1].status, Status::AtRisk);
    }

    #[test]
    fn display_relative_strips_root_prefix() {
        let root = Path::new("/workspace/repo");
        let path = Path::new("/workspace/repo/packages/app/package.json");
        assert_eq!(display_relative(root, path), "packages/app/package.json");
    }

    #[test]
    fn render_json_is_valid_and_reparseable() {
        let mut report = ScanReport::new(PathBuf::from("/repo"));
        report.push_finding(Finding {
            status: Status::AtRisk,
            source: Source::Manifest,
            path: PathBuf::from("/repo/package.json"),
            detail: "test finding".into(),
        });
        report.notes.push("scanned 1 lockfile".into());

        let json_str = report.render_json();
        let parsed = Json::parse(&json_str).expect("render_json must produce valid JSON");
        assert_eq!(parsed.get("status").and_then(Json::as_str), Some("at-risk"),);
        let findings = parsed.get("findings").and_then(Json::as_array).unwrap();
        assert_eq!(
            findings[0].get("path").and_then(Json::as_str),
            Some("package.json"),
        );
    }
}
