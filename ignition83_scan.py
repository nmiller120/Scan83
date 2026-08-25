#!/usr/bin/env python3

"""
Ignition 8.1 -> 8.3.8 Compatibility Scanner

Simple regex rules are loaded from a JSON file.

Usage:

    python ignition83_scan.py C:\\path\\to\\projects

    python ignition83_scan.py C:\\path\\to\\projects \
        --rules ignition83_rules.json

    python ignition83_scan.py C:\\path\\to\\projects \
        --rules ignition83_rules.json \
        --csv findings.csv
"""

import argparse
import csv
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


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
    pattern: str
    message: str
    recommendation: str
    flags: int = 0


# ============================================================
# SCANNER CONFIG
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


# ============================================================
# RULE LOADING
# ============================================================

def load_rules(path: Path) -> List[Rule]:

    try:
        with path.open("r", encoding="utf-8") as f:
            raw_rules = json.load(f)

    except FileNotFoundError:
        print(
            f"Rules file not found: {path}",
            file=sys.stderr,
        )
        sys.exit(1)

    except json.JSONDecodeError as e:
        print(
            f"Invalid JSON in rules file: {e}",
            file=sys.stderr,
        )
        sys.exit(1)

    if not isinstance(raw_rules, list):
        print(
            "Rules file must contain a JSON array.",
            file=sys.stderr,
        )
        sys.exit(1)

    rules = []

    required_fields = {
        "rule_id",
        "severity",
        "pattern",
        "message",
        "recommendation",
    }

    seen_ids = set()

    for index, raw in enumerate(raw_rules, start=1):

        if not isinstance(raw, dict):
            print(
                f"Rule #{index} must be a JSON object.",
                file=sys.stderr,
            )
            sys.exit(1)

        missing = required_fields - raw.keys()

        if missing:
            print(
                f"Rule #{index} is missing fields: "
                f"{', '.join(sorted(missing))}",
                file=sys.stderr,
            )
            sys.exit(1)

        rule_id = raw["rule_id"]

        if rule_id in seen_ids:
            print(
                f"Duplicate rule_id: {rule_id}",
                file=sys.stderr,
            )
            sys.exit(1)

        seen_ids.add(rule_id)

        severity = raw["severity"].upper()

        if severity not in SEVERITY_ORDER:
            print(
                f"Invalid severity '{severity}' "
                f"in rule {rule_id}",
                file=sys.stderr,
            )
            sys.exit(1)

        pattern = raw["pattern"]

        # Validate regex now instead of failing during the scan.
        try:
            re.compile(pattern)
        except re.error as e:
            print(
                f"Invalid regex in rule {rule_id}: {e}",
                file=sys.stderr,
            )
            sys.exit(1)

        rules.append(
            Rule(
                rule_id=rule_id,
                severity=severity,
                pattern=pattern,
                message=raw["message"],
                recommendation=raw["recommendation"],
            )
        )

    return rules


# ============================================================
# HELPERS
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

    # Some Ignition resources may be extensionless but textual.
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
            return path.read_text(
                encoding=encoding
            )

        except UnicodeDecodeError:
            continue

        except OSError:
            return None

    return None


def line_number(
    text: str,
    position: int,
) -> int:

    return (
        text.count(
            "\n",
            0,
            position,
        )
        + 1
    )


def get_line(
    text: str,
    number: int,
) -> str:

    lines = text.splitlines()

    if 1 <= number <= len(lines):
        return lines[number - 1].strip()

    return ""


def get_project_name(
    root: Path,
    path: Path,
) -> str:

    try:
        relative = path.relative_to(root)

    except ValueError:
        return "(unknown)"

    if len(relative.parts) > 1:
        return relative.parts[0]

    return "(gateway)"


# ============================================================
# BASIC RULE SCANNING
# ============================================================

def scan_regex_rules(
    text: str,
    relative_path: str,
    project: str,
    rules: List[Rule],
) -> List[Finding]:

    findings = []

    for rule in rules:

        regex = re.compile(
            rule.pattern,
            rule.flags,
        )

        for match in regex.finditer(text):

            line = line_number(
                text,
                match.start(),
            )

            findings.append(
                Finding(
                    severity=rule.severity,
                    rule_id=rule.rule_id,
                    project=project,
                    file=relative_path,
                    line=line,
                    code=get_line(
                        text,
                        line,
                    ),
                    message=rule.message,
                    recommendation=rule.recommendation,
                )
            )

    return findings


# ============================================================
# CONTEXT-AWARE RULES
# ============================================================

def scan_query_status_getdataset(
    text: str,
    relative_path: str,
    project: str,
    search_window_lines: int = 15,
) -> List[Finding]:

    """
    Detect:

        alarms = system.alarm.queryStatus(...)
        ...
        alarms.getDataset()

    This is not full data-flow analysis. It simply tracks a direct
    assignment for a limited number of subsequent lines.
    """

    findings = []

    lines = text.splitlines()

    assignment_regex = re.compile(
        r"""
        ^\s*
        (?P<variable>[A-Za-z_][A-Za-z0-9_]*)
        \s*=\s*
        system\.alarm\.queryStatus\s*\(
        """,
        re.VERBOSE,
    )

    for index, line in enumerate(lines):

        match = assignment_regex.search(line)

        if not match:
            continue

        variable = match.group("variable")

        get_dataset_regex = re.compile(
            r"\b"
            + re.escape(variable)
            + r"\s*\.\s*getDataset\s*\("
        )

        end = min(
            len(lines),
            index + search_window_lines + 1,
        )

        for later_index in range(
            index + 1,
            end,
        ):

            if get_dataset_regex.search(
                lines[later_index]
            ):

                findings.append(
                    Finding(
                        severity="RED",
                        rule_id="IGN83-ALARM-002",
                        project=project,
                        file=relative_path,
                        line=later_index + 1,
                        code=lines[
                            later_index
                        ].strip(),
                        message=(
                            "Return value from "
                            "system.alarm.queryStatus() "
                            "is later used with "
                            ".getDataset()."
                        ),
                        recommendation=(
                            "Known 8.3 compatibility hazard. "
                            "If the goal is an alarm count, "
                            "use len(alarms). Otherwise review "
                            "the expected return-object behavior."
                        ),
                    )
                )

    return findings


def scan_inline_query_status_getdataset(
    text: str,
    relative_path: str,
    project: str,
) -> List[Finding]:

    """
    Detect:

        system.alarm.queryStatus(...).getDataset()

    DOTALL allows multiline calls.
    """

    regex = re.compile(
        r"""
        system\.alarm\.queryStatus
        \s*\(
        .*?
        \)
        \s*
        \.getDataset
        \s*\(
        """,
        re.VERBOSE | re.DOTALL,
    )

    findings = []

    for match in regex.finditer(text):

        line = line_number(
            text,
            match.start(),
        )

        findings.append(
            Finding(
                severity="RED",
                rule_id="IGN83-ALARM-003",
                project=project,
                file=relative_path,
                line=line,
                code=get_line(
                    text,
                    line,
                ),
                message=(
                    "Direct queryStatus(...).getDataset() "
                    "chain detected."
                ),
                recommendation=(
                    "Known 8.3 compatibility hazard. "
                    "Rewrite based on what the code "
                    "actually needs; for alarm count "
                    "use len(result)."
                ),
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

        # Modify dirs in place so os.walk does not descend
        # into ignored directories.
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

            relative_path = str(
                path.relative_to(root)
            )

            project = get_project_name(
                root,
                path,
            )

            findings.extend(
                scan_regex_rules(
                    text,
                    relative_path,
                    project,
                    rules,
                )
            )

            findings.extend(
                scan_query_status_getdataset(
                    text,
                    relative_path,
                    project,
                )
            )

            findings.extend(
                scan_inline_query_status_getdataset(
                    text,
                    relative_path,
                    project,
                )
            )

    return findings


# ============================================================
# OUTPUT
# ============================================================

def sort_findings(
    findings: List[Finding],
) -> List[Finding]:

    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(
                f.severity,
                99,
            ),
            f.project,
            f.file,
            f.line,
            f.rule_id,
        ),
    )


def print_findings(
    findings: List[Finding],
) -> None:

    if not findings:
        print("No findings.")
        return

    for finding in findings:

        print()
        print("=" * 80)

        print(
            f"[{finding.severity}] "
            f"{finding.rule_id}"
        )

        print(
            f"Project: {finding.project}"
        )

        print(
            f"{finding.file}:{finding.line}"
        )

        print()
        print(
            f"  {finding.code}"
        )

        print()
        print("Issue:")
        print(
            f"  {finding.message}"
        )

        print()
        print("Recommendation:")
        print(
            f"  {finding.recommendation}"
        )

    print()
    print("=" * 80)
    print("SUMMARY")

    counts = {}

    for finding in findings:

        counts[finding.severity] = (
            counts.get(
                finding.severity,
                0,
            )
            + 1
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

    print(
        f"  TOTAL  : {len(findings)}"
    )


def write_csv(
    findings: List[Finding],
    filename: Path,
) -> None:

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
        help=(
            "Root directory containing "
            "Ignition projects"
        ),
    )

    parser.add_argument(
        "--rules",
        default="ignition83_rules.json",
        help=(
            "JSON rules file "
            "(default: ignition83_rules.json)"
        ),
    )

    parser.add_argument(
        "--csv",
        help="Optional CSV output filename",
    )

    args = parser.parse_args()

    root = Path(
        args.root
    ).resolve()

    rules_path = Path(
        args.rules
    ).resolve()

    if not root.exists():

        print(
            f"Path does not exist: {root}",
            file=sys.stderr,
        )

        sys.exit(1)

    rules = load_rules(
        rules_path
    )

    print(
        f"Scanning: {root}"
    )

    print(
        f"Rules:    {rules_path}"
    )

    print(
        f"Loaded:   {len(rules)} rules"
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

    if args.csv:

        csv_path = Path(
            args.csv
        ).resolve()

        write_csv(
            findings,
            csv_path,
        )

        print()
        print(
            f"CSV written to: {csv_path}"
        )


if __name__ == "__main__":
    main()