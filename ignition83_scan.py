#!/usr/bin/env python3

"""
Ignition 8.1 -> 8.3.8 Compatibility Scanner

Features:
- Accepts the Ignition installation directory as the positional root
- Automatically scans <install>/data/projects
- Attempts to detect the installed Ignition Gateway version from core JAR manifests
- Loads all compatibility rules from CSV
- Skips Ignition's .resources folder and common dev/build folders
- Tracks project name from the first directory below data/projects
- Shows a spinner while scanning so long scans do not appear hung
- Writes findings.csv and rule_summary.csv into one reports directory
- Prints only a concise completion summary with elapsed time and detected Gateway version

Usage:

    python ignition83_scan.py "C:\\Program Files\\Inductive Automation\\Ignition"

    python ignition83_scan.py "C:\\Program Files\\Inductive Automation\\Ignition" \
        --rules ignition83_rules.csv \
        --reports reports
"""

import argparse
import csv
import itertools
import os
import re
import sys
import threading
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set


# ============================================================
# DATA TYPES
# ============================================================

@dataclass
class Finding:
    severity: str
    rule_id: str
    project: str
    file: str
    line: int
    code: str
    message: str
    recommendation: str


@dataclass
class Rule:
    rule_id: str
    severity: str
    category: str
    pattern: str
    description: str
    reason: str
    recommendation: str
    test_procedure: str
    affected_versions: str
    fixed_version: str
    reference: str
    status: str
    notes: str
    enabled: bool = True
    flags: int = 0


# ============================================================
# CONFIG
# ============================================================

SKIP_DIRS = {
    ".git",
    ".resources",
    ".idea",
    ".vs",
    ".vscode",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
}

TEXT_EXTENSIONS = {
    ".py",
    ".txt",
    ".json",
    ".xml",
    ".yaml",
    ".yml",
    ".properties",
    ".md",
    ".sql",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
}

SEVERITY_ORDER = {
    "RED": 0,
    "ORANGE": 1,
    "YELLOW": 2,
    "GREEN": 3,
}

REQUIRED_RULE_FIELDS = {
    "rule_id",
    "severity",
    "category",
    "pattern",
    "description",
    "reason",
    "recommendation",
    "test_procedure",
    "affected_versions",
    "fixed_version",
    "reference",
    "status",
    "notes",
}

VERSION_PATTERN = re.compile(r"\b\d+\.\d+\.\d+(?:[-+._][A-Za-z0-9.-]+)?\b")
VERSION_MANIFEST_KEYS = (
    "Implementation-Version",
    "Bundle-Version",
    "Specification-Version",
)


# ============================================================
# SPINNER
# ============================================================

class Spinner:
    def __init__(self, message: str = "Scanning"):
        self.message = message
        self._stop_event = threading.Event()
        self._thread = None

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def _spin(self) -> None:
        for frame in itertools.cycle("|/-\\"):
            if self._stop_event.is_set():
                break

            sys.stdout.write(f"\r{self.message} {frame}")
            sys.stdout.flush()
            time.sleep(0.1)

    def stop(self) -> None:
        self._stop_event.set()

        if self._thread is not None:
            self._thread.join()

        sys.stdout.write("\r" + " " * (len(self.message) + 4) + "\r")
        sys.stdout.flush()


# ============================================================
# INSTALL / VERSION DETECTION
# ============================================================

def get_projects_root(install_root: Path) -> Path:
    return install_root / "data" / "projects"


def parse_manifest(manifest_text: str) -> Dict[str, str]:
    values = {}
    current_key = None

    for raw_line in manifest_text.splitlines():
        if raw_line.startswith(" ") and current_key:
            values[current_key] += raw_line[1:]
            continue

        if ":" not in raw_line:
            current_key = None
            continue

        key, value = raw_line.split(":", 1)
        current_key = key.strip()
        values[current_key] = value.strip()

    return values


def version_from_jar(path: Path) -> Optional[str]:
    try:
        with zipfile.ZipFile(path, "r") as jar:
            manifest = jar.read("META-INF/MANIFEST.MF").decode(
                "utf-8",
                errors="replace",
            )
    except (OSError, KeyError, zipfile.BadZipFile):
        return None

    values = parse_manifest(manifest)

    for key in VERSION_MANIFEST_KEYS:
        value = values.get(key)

        if not value:
            continue

        match = VERSION_PATTERN.search(value)

        if match:
            return match.group(0)

    return None


def version_from_text_file(path: Path) -> Optional[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    ignition_lines = [
        line
        for line in text.splitlines()
        if "ignition" in line.lower() or "version" in line.lower()
    ]

    for line in ignition_lines:
        match = VERSION_PATTERN.search(line)

        if match:
            return match.group(0)

    return None


def detect_gateway_version(install_root: Path) -> str:
    preferred_jars = [
        install_root / "lib" / "core" / "common" / "common.jar",
        install_root / "lib" / "core" / "gateway" / "gateway.jar",
    ]

    for jar_path in preferred_jars:
        if not jar_path.is_file():
            continue

        version = version_from_jar(jar_path)

        if version:
            return version

    core_root = install_root / "lib" / "core"

    if core_root.is_dir():
        for jar_path in core_root.rglob("*.jar"):
            version = version_from_jar(jar_path)

            if version and version.startswith(("7.", "8.", "9.")):
                return version

    for metadata_file in (
        install_root / "install.log",
        install_root / "data" / "ignition.conf",
    ):
        if not metadata_file.is_file():
            continue

        version = version_from_text_file(metadata_file)

        if version:
            return version

    return "Unknown"


# ============================================================
# RULE LOADING
# ============================================================

def parse_bool(value: str) -> bool:
    if value is None or value == "":
        return True

    return value.strip().lower() not in {
        "0",
        "false",
        "no",
        "n",
        "disabled",
        "off",
    }


def load_rules(path: Path) -> List[Rule]:
    try:
        with path.open("r", newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)

            if reader.fieldnames is None:
                raise ValueError("Rules CSV does not contain a header row.")

            missing = REQUIRED_RULE_FIELDS - set(reader.fieldnames)

            if missing:
                raise ValueError(
                    "Rules CSV is missing required columns: "
                    + ", ".join(sorted(missing))
                )

            rules = []
            seen_ids = set()

            for row_number, row in enumerate(reader, start=2):
                rule_id = (row.get("rule_id") or "").strip()

                if not rule_id:
                    raise ValueError(
                        f"Rules CSV row {row_number} has no rule_id."
                    )

                if rule_id in seen_ids:
                    raise ValueError(
                        f"Duplicate rule_id '{rule_id}' on row {row_number}."
                    )

                seen_ids.add(rule_id)

                severity = (row.get("severity") or "").strip().upper()

                if severity not in SEVERITY_ORDER:
                    raise ValueError(
                        f"Invalid severity '{severity}' "
                        f"for rule {rule_id} on row {row_number}."
                    )

                pattern = row.get("pattern") or ""

                try:
                    re.compile(pattern)
                except re.error as e:
                    raise ValueError(
                        f"Invalid regex for rule {rule_id} "
                        f"on row {row_number}: {e}"
                    )

                rules.append(
                    Rule(
                        rule_id=rule_id,
                        severity=severity,
                        category=(row.get("category") or "").strip(),
                        pattern=pattern,
                        description=(row.get("description") or "").strip(),
                        reason=(row.get("reason") or "").strip(),
                        recommendation=(row.get("recommendation") or "").strip(),
                        test_procedure=(row.get("test_procedure") or "").strip(),
                        affected_versions=(row.get("affected_versions") or "").strip(),
                        fixed_version=(row.get("fixed_version") or "").strip(),
                        reference=(row.get("reference") or "").strip(),
                        status=(row.get("status") or "").strip(),
                        notes=(row.get("notes") or "").strip(),
                        enabled=parse_bool(row.get("enabled", "true")),
                    )
                )

            return rules

    except FileNotFoundError:
        raise ValueError(f"Rules file not found: {path}")


# ============================================================
# FILE HELPERS
# ============================================================

def looks_binary(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            chunk = f.read(4096)

        return b"\x00" in chunk

    except OSError:
        return True


def should_scan(path: Path) -> bool:
    if path.suffix.lower() in TEXT_EXTENSIONS:
        return True

    if not path.suffix:
        return not looks_binary(path)

    return False


def read_text(path: Path) -> Optional[str]:
    encodings = [
        "utf-8",
        "utf-8-sig",
        "cp1252",
        "latin-1",
    ]

    for encoding in encodings:
        try:
            return path.read_text(encoding=encoding)
        except UnicodeDecodeError:
            continue
        except OSError:
            return None

    return None


def line_number(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


def get_line(text: str, number: int) -> str:
    lines = text.splitlines()

    if 1 <= number <= len(lines):
        return lines[number - 1].strip()

    return ""


def get_project_name(root: Path, path: Path) -> str:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return "(unknown)"

    if len(relative.parts) > 1:
        return relative.parts[0]

    return "(gateway)"


# ============================================================
# CSV-BACKED REGEX RULES
# ============================================================

def scan_regex_rules(
    text: str,
    relative_path: str,
    project: str,
    rules: List[Rule],
) -> List[Finding]:

    findings = []

    for rule in rules:
        if not rule.enabled:
            continue

        regex = re.compile(rule.pattern, rule.flags)

        for match in regex.finditer(text):
            line = line_number(text, match.start())

            findings.append(
                Finding(
                    severity=rule.severity,
                    rule_id=rule.rule_id,
                    project=project,
                    file=relative_path,
                    line=line,
                    code=get_line(text, line),
                    message=rule.description,
                    recommendation=rule.recommendation,
                )
            )

    return findings


# ============================================================
# REPOSITORY SCANNING
# ============================================================

def scan_repository(
    root: Path,
    rules: List[Rule],
) -> List[Finding]:

    findings = []

    for current_root, dirs, files in os.walk(root):
        dirs[:] = [
            d
            for d in dirs
            if d not in SKIP_DIRS
        ]

        current_path = Path(current_root)

        for filename in files:
            path = current_path / filename

            if not should_scan(path):
                continue

            text = read_text(path)

            if text is None:
                continue

            relative_path = str(path.relative_to(root))
            project = get_project_name(root, path)

            findings.extend(
                scan_regex_rules(
                    text,
                    relative_path,
                    project,
                    rules,
                )
            )

    return findings


# ============================================================
# SORTING / OUTPUT
# ============================================================

def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 99),
            f.project,
            f.file,
            f.line,
            f.rule_id,
        ),
    )


def write_findings_csv(
    findings: List[Finding],
    filename: Path,
) -> None:

    filename.parent.mkdir(parents=True, exist_ok=True)

    with filename.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:

        writer = csv.writer(f)

        writer.writerow([
            "Severity",
            "Rule ID",
            "Project",
            "File",
            "Line",
            "Code",
            "Issue",
            "Recommendation",
        ])

        for finding in findings:
            writer.writerow([
                finding.severity,
                finding.rule_id,
                finding.project,
                finding.file,
                finding.line,
                finding.code,
                finding.message,
                finding.recommendation,
            ])


def write_rule_summary_csv(
    rules: List[Rule],
    findings: List[Finding],
    filename: Path,
) -> None:

    filename.parent.mkdir(parents=True, exist_ok=True)

    counts: Dict[str, int] = {}
    projects_by_rule: Dict[str, Set[str]] = {}

    for finding in findings:
        counts[finding.rule_id] = counts.get(finding.rule_id, 0) + 1

        projects_by_rule.setdefault(
            finding.rule_id,
            set(),
        ).add(finding.project)

    rule_map = {
        rule.rule_id: rule
        for rule in rules
    }

    ordered_rules = sorted(
        rule_map.values(),
        key=lambda r: (
            SEVERITY_ORDER.get(r.severity, 99),
            r.category,
            r.rule_id,
        ),
    )

    with filename.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:

        writer = csv.writer(f)

        writer.writerow([
            "Rule ID",
            "Severity",
            "Category",
            "Enabled",
            "Occurrences",
            "Projects Affected",
            "Project Count",
            "Description",
            "Reason",
            "Recommendation",
            "Test Procedure",
            "Affected Versions",
            "Fixed Version",
            "Reference",
            "Status",
            "Notes",
            "Pattern",
        ])

        for rule in ordered_rules:
            projects = sorted(
                projects_by_rule.get(
                    rule.rule_id,
                    set(),
                )
            )

            writer.writerow([
                rule.rule_id,
                rule.severity,
                rule.category,
                "Yes" if rule.enabled else "No",
                counts.get(rule.rule_id, 0),
                "; ".join(projects),
                len(projects),
                rule.description,
                rule.reason,
                rule.recommendation,
                rule.test_procedure,
                rule.affected_versions,
                rule.fixed_version,
                rule.reference,
                rule.status,
                rule.notes,
                rule.pattern,
            ])


# ============================================================
# ENTRY POINT
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Scan an Ignition installation for "
            "8.1 -> 8.3.8 compatibility hazards."
        )
    )

    parser.add_argument(
        "root",
        help="Ignition installation directory",
    )

    parser.add_argument(
        "--rules",
        default="ignition83_rules.csv",
        help=(
            "CSV rules file "
            "(default: ignition83_rules.csv)"
        ),
    )

    parser.add_argument(
        "--reports",
        default="reports",
        help=(
            "Directory for generated reports "
            "(default: reports)"
        ),
    )

    args = parser.parse_args()

    install_root = Path(args.root).resolve()
    projects_root = get_projects_root(install_root)
    rules_path = Path(args.rules).resolve()
    reports_path = Path(args.reports).resolve()
    findings_path = reports_path / "findings.csv"
    summary_path = reports_path / "rule_summary.csv"

    if not install_root.is_dir():
        print(
            f"Ignition install directory does not exist: {install_root}",
            file=sys.stderr,
        )
        sys.exit(1)

    if not projects_root.is_dir():
        print(
            f"Ignition projects directory not found: {projects_root}",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        rules = load_rules(rules_path)
    except ValueError as e:
        print(
            f"Rules error: {e}",
            file=sys.stderr,
        )
        sys.exit(1)

    gateway_version = detect_gateway_version(install_root)

    start_time = time.perf_counter()
    spinner = Spinner("Scanning Ignition projects")
    spinner.start()

    try:
        findings = scan_repository(
            projects_root,
            rules,
        )

        findings = sort_findings(
            findings
        )

        write_findings_csv(
            findings,
            findings_path,
        )

        write_rule_summary_csv(
            rules,
            findings,
            summary_path,
        )
    finally:
        spinner.stop()

    elapsed = time.perf_counter() - start_time
    enabled_count = sum(1 for rule in rules if rule.enabled)

    print(f"Gateway version: {gateway_version}")
    print(
        f"Complete in {elapsed:.2f}s | "
        f"{len(findings)} findings | "
        f"{enabled_count}/{len(rules)} rules enabled"
    )
    print(f"Projects: {projects_root}")
    print(f"Reports:  {reports_path}")


if __name__ == "__main__":
    main()
