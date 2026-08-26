#!/usr/bin/env python3

"""
Ignition 8.1 -> 8.3.8 Compatibility Scanner

Features:
- Recursively scans an Ignition projects directory
- Loads simple regex rules from CSV
- Skips Ignition's .resources folder and common dev/build folders
- Tracks project name from the first directory below the scan root
- Writes detailed findings CSV
- Writes rule summary CSV with occurrence/project counts
- All compatibility rules are loaded from CSV; there are no built-in scan rules

Usage:

    python ignition83_scan.py "C:\\Program Files\\Inductive Automation\\Ignition\\data\\projects"

    python ignition83_scan.py "C:\\Program Files\\Inductive Automation\\Ignition\\data\\projects" \
        --rules ignition83_rules.csv \
        --findings reports\\findings.csv \
        --summary reports\\rule_summary.csv
"""

import argparse
import csv
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Dict, Set


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


def print_findings(findings: List[Finding]) -> None:
    if not findings:
        print("No findings.")
        return

    for finding in findings:
        print()
        print("=" * 80)
        print(f"[{finding.severity}] {finding.rule_id}")
        print(f"Project: {finding.project}")
        print(f"{finding.file}:{finding.line}")

        print()
        print(f"  {finding.code}")

        print()
        print("Issue:")
        print(f"  {finding.message}")

        print()
        print("Recommendation:")
        print(f"  {finding.recommendation}")

    print()
    print("=" * 80)
    print("SUMMARY")

    counts = {}

    for finding in findings:
        counts[finding.severity] = (
            counts.get(finding.severity, 0) + 1
        )

    for severity in [
        "RED",
        "ORANGE",
        "YELLOW",
        "GREEN",
    ]:
        print(
            f"  {severity:<7}: "
            f"{counts.get(severity, 0)}"
        )

    print(f"  TOTAL  : {len(findings)}")


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
            "Scan Ignition projects for "
            "8.1 -> 8.3.8 compatibility hazards."
        )
    )

    parser.add_argument(
        "root",
        help="Root directory containing Ignition projects",
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
        "--findings",
        default="reports/findings.csv",
        help=(
            "Detailed findings CSV "
            "(default: reports/findings.csv)"
        ),
    )

    parser.add_argument(
        "--summary",
        default="reports/rule_summary.csv",
        help=(
            "Rule summary CSV "
            "(default: reports/rule_summary.csv)"
        ),
    )

    args = parser.parse_args()

    root = Path(args.root).resolve()
    rules_path = Path(args.rules).resolve()
    findings_path = Path(args.findings).resolve()
    summary_path = Path(args.summary).resolve()

    if not root.exists():
        print(
            f"Path does not exist: {root}",
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

    enabled_count = sum(
        1 for rule in rules if rule.enabled
    )

    print(f"Scanning: {root}")
    print(f"Rules:    {rules_path}")
    print(
        f"Loaded:   {len(rules)} rules "
        f"({enabled_count} enabled)"
    )

    findings = scan_repository(
        root,
        rules,
    )

    findings = sort_findings(
        findings
    )

    print_findings(
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

    print()
    print(
        f"Findings CSV: {findings_path}"
    )
    print(
        f"Rule summary: {summary_path}"
    )


if __name__ == "__main__":
    main()
