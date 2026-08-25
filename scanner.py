#!/usr/bin/env python3

"""
Ignition 8.1 -> 8.3.8 Compatibility Scanner
Proof of concept.

Usage:

    python ignition83_scan.py C:\\path\\to\\repo

    python ignition83_scan.py C:\\path\\to\\repo --csv findings.csv

    python ignition83_scan.py . --context 4
"""

import argparse
import csv
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
# RULES
# ============================================================

RULES = [

    Rule(
        rule_id="IGN83-DEP-001",
        severity="YELLOW",
        pattern=r"\bsystem\.dataset\.toPyDataSet\s*\(",
        message="system.dataset.toPyDataSet() is deprecated in Ignition 8.3.",
        recommendation=(
            "Review usage. Dataset objects are directly iterable/indexable "
            "in 8.3, but existing calls may remain compatible."
        ),
    ),

    Rule(
        rule_id="IGN83-DATASET-001",
        severity="ORANGE",
        pattern=r"\bsystem\.dataset\.toDataSet\s*\(",
        message="Legacy dataset constructor spelling detected.",
        recommendation=(
            "Review and test this call in 8.3.8. The current API uses "
            "system.dataset.toDataset()."
        ),
    ),

    Rule(
        rule_id="IGN83-ALARM-001",
        severity="ORANGE",
        pattern=r"\bsystem\.alarm\.queryStatus\s*\(",
        message="system.alarm.queryStatus() usage detected.",
        recommendation=(
            "Inspect how the return value is consumed. In affected 8.3 "
            "versions, return-object behavior has caused compatibility issues, "
            "especially code calling .getDataset()."
        ),
    ),

    Rule(
        rule_id="IGN83-DB-001",
        severity="ORANGE",
        pattern=r"\bsystem\.db\.runNamedQuery\s*\([^;\n]*,\s*None\s*\)",
        message="runNamedQuery() appears to be called with None parameters.",
        recommendation=(
            "Review for 8.3.8 compatibility. Prefer {} when no parameters "
            "are required."
        ),
    ),

    Rule(
        rule_id="IGN83-DB-002",
        severity="YELLOW",
        pattern=r"\bsystem\.db\.(runQuery|runScalarQuery|runUpdateQuery|runNamedQuery)\s*\(",
        message="Deprecated system.db.run* API detected.",
        recommendation=(
            "Generally leave unchanged unless testing reveals a problem. "
            "Record as deprecated-but-supported."
        ),
    ),

    Rule(
        rule_id="IGN83-HIST-001",
        severity="ORANGE",
        pattern=r"\bsystem\.tag\.(queryTagHistory|queryTagCalculations|queryTagDensity)\s*\(",
        message="Deprecated legacy historian API detected.",
        recommendation=(
            "Explicitly regression-test the affected historian workflow "
            "against Ignition 8.3.8."
        ),
    ),

    Rule(
        rule_id="IGN83-HIST-002",
        severity="YELLOW",
        pattern=r"\bsystem\.tag\.(browseHistoricalTags|queryAnnotations)\s*\(",
        message="Deprecated historian-related system.tag API detected.",
        recommendation=(
            "Document and test, but avoid changing solely because it is deprecated."
        ),
    ),

    Rule(
        rule_id="IGN83-HIST-003",
        severity="ORANGE",
        pattern=r"\bsystem\.tag\.(storeTagHistory|storeAnnotations|deleteAnnotations)\s*\(",
        message="Deprecated historian write API detected.",
        recommendation=(
            "Explicitly test because this code writes or deletes historian data."
        ),
    ),

    Rule(
        rule_id="IGN83-DATASET-002",
        severity="ORANGE",
        pattern=r"\bsystem\.dataset\.(toExcel|exportExcel)\s*\(",
        message="Excel export using Dataset API detected.",
        recommendation=(
            "Review arguments carefully. Ignition 8.3.8 has known Dataset "
            "sequence/coercion regressions in this area."
        ),
    ),

    Rule(
        rule_id="IGN83-TAG-001",
        severity="ORANGE",
        pattern=r"\bsystem\.tag\.(writeBlocking|writeAsync)\s*\(",
        message="Tag write API detected.",
        recommendation=(
            "If a Dataset is passed directly as the value/list argument, "
            "explicitly test this in 8.3.8."
        ),
    ),

    Rule(
        rule_id="IGN83-TAG-002",
        severity="YELLOW",
        pattern=r"\bsystem\.tag\.browse\s*\(",
        message="system.tag.browse() usage detected.",
        recommendation=(
            "If relative tag paths such as [.] or [~] are used, explicitly "
            "test behavior in 8.3.8."
        ),
    ),

    Rule(
        rule_id="IGN83-TYPE-001",
        severity="ORANGE",
        pattern=r"\bPyDataSet\b|\bPyDataset\b|DatasetUtilities\.PyDataSet",
        message="Explicit PyDataset type reference detected.",
        recommendation=(
            "Review type checks/imports. Dataset wrapping behavior changed in 8.3."
        ),
    ),

    Rule(
        rule_id="IGN83-TYPE-002",
        severity="YELLOW",
        pattern=r"\bisinstance\s*\(|\btype\s*\(",
        message="Explicit Python type inspection detected.",
        recommendation=(
            "Review if this code checks Dataset/PyDataset, QualifiedValue, "
            "AlarmQueryResult, or other Ignition scripting-object types."
        ),
    ),

    Rule(
        rule_id="IGN83-EXPR-001",
        severity="ORANGE",
        pattern=r"\bforceQuality\s*\(",
        message="Deprecated forceQuality() expression usage detected.",
        recommendation=(
            "Review and migrate to qualifiedValue() if this expression is "
            "part of a critical binding."
        ),
    ),
]


# ============================================================
# SCANNER CONFIG
# ============================================================

SKIP_DIRS = {
    ".git",
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

# Ignition exports may contain scripts inside JSON/XML/resource files,
# so we intentionally scan more than just .py.
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

    # Ignition sometimes stores resource text in extensionless files.
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


# ============================================================
# BASIC RULE SCANNING
# ============================================================

def scan_regex_rules(
    text: str,
    relative_path: str,
) -> List[Finding]:

    findings = []

    for rule in RULES:
        regex = re.compile(rule.pattern, rule.flags)

        for match in regex.finditer(text):

            line = line_number(text, match.start())

            findings.append(
                Finding(
                    severity=rule.severity,
                    rule_id=rule.rule_id,
                    file=relative_path,
                    line=line,
                    code=get_line(text, line),
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
    search_window_lines: int = 15,
) -> List[Finding]:

    """
    Detect:

        alarms = system.alarm.queryStatus(...)
        ...
        alarms.getDataset()

    This is deliberately lightweight. It is not full Python data-flow
    analysis, but it catches the common migration failure.
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
            r"\b" + re.escape(variable) + r"\s*\.\s*getDataset\s*\("
        )

        end = min(
            len(lines),
            index + search_window_lines + 1,
        )

        for later_index in range(index + 1, end):

            if get_dataset_regex.search(lines[later_index]):

                findings.append(
                    Finding(
                        severity="RED",
                        rule_id="IGN83-ALARM-002",
                        file=relative_path,
                        line=later_index + 1,
                        code=lines[later_index].strip(),
                        message=(
                            "Return value from system.alarm.queryStatus() "
                            "is later used with .getDataset()."
                        ),
                        recommendation=(
                            "Known 8.3 compatibility hazard. If the goal is "
                            "an alarm count, use len(alarms). Otherwise review "
                            "the expected return-object behavior."
                        ),
                    )
                )

    return findings


def scan_inline_query_status_getdataset(
    text: str,
    relative_path: str,
) -> List[Finding]:

    """
    Detect direct chains such as:

        system.alarm.queryStatus(...).getDataset()

    DOTALL is intentional so multiline calls are caught.
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

        line = line_number(text, match.start())

        findings.append(
            Finding(
                severity="RED",
                rule_id="IGN83-ALARM-003",
                file=relative_path,
                line=line,
                code=get_line(text, line),
                message=(
                    "Direct queryStatus(...).getDataset() chain detected."
                ),
                recommendation=(
                    "Known 8.3 compatibility hazard. Rewrite based on what "
                    "the code actually needs; for alarm count use len(result)."
                ),
            )
        )

    return findings


# ============================================================
# REPOSITORY SCANNING
# ============================================================

def scan_repository(root: Path) -> List[Finding]:

    findings = []

    for current_root, dirs, files in os.walk(root):

        dirs[:] = [
            d for d in dirs
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

            findings.extend(
                scan_regex_rules(
                    text,
                    relative_path,
                )
            )

            findings.extend(
                scan_query_status_getdataset(
                    text,
                    relative_path,
                )
            )

            findings.extend(
                scan_inline_query_status_getdataset(
                    text,
                    relative_path,
                )
            )

    return findings


# ============================================================
# OUTPUT
# ============================================================

SEVERITY_ORDER = {
    "RED": 0,
    "ORANGE": 1,
    "YELLOW": 2,
    "GREEN": 3,
}


def sort_findings(findings: List[Finding]) -> List[Finding]:

    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 99),
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

        print(
            f"[{finding.severity}] "
            f"{finding.rule_id}"
        )

        print(
            f"{finding.file}:{finding.line}"
        )

        print()
        print(f"  {finding.code}")

        print()
        print(f"Issue:")
        print(f"  {finding.message}")

        print()
        print("Recommendation:")
        print(f"  {finding.recommendation}")

    print()
    print("=" * 80)

    counts = {}

    for finding in findings:
        counts[finding.severity] = (
            counts.get(finding.severity, 0) + 1
        )

    print("SUMMARY")

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
            "Scan an Ignition project repository for "
            "8.1 -> 8.3.8 compatibility hazards."
        )
    )

    parser.add_argument(
        "root",
        help="Root directory of the Git repository",
    )

    parser.add_argument(
        "--csv",
        help="Optional CSV report filename",
    )

    args = parser.parse_args()

    root = Path(args.root).resolve()

    if not root.exists():
        print(
            f"Path does not exist: {root}",
            file=sys.stderr,
        )
        sys.exit(1)

    print(
        f"Scanning: {root}"
    )

    findings = scan_repository(root)

    findings = sort_findings(findings)

    print_findings(findings)

    if args.csv:

        csv_path = Path(args.csv)

        write_csv(
            findings,
            csv_path,
        )

        print()
        print(
            f"CSV written to: {csv_path.resolve()}"
        )


if __name__ == "__main__":
    main()