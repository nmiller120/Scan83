#!/usr/bin/env python3

"""Ignition 8.1 -> 8.3.8 compatibility scanner."""

import argparse
import csv
import itertools
import os
import re
import ssl
import sys
import threading
import time
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

from tag_event_scanner import discover_tag_event_scripts, get_tag_resource_root

DEFAULT_WINDOWS_ROOT = r"C:\Program Files\Inductive Automation\Ignition"
SKIP_DIRS = {".git", ".resources", ".idea", ".vs", ".vscode", "node_modules", "dist", "build", "__pycache__", ".pytest_cache", ".mypy_cache"}
TEXT_EXTENSIONS = {".py", ".txt", ".json", ".xml", ".yaml", ".yml", ".properties", ".md", ".sql", ".js", ".ts", ".tsx", ".jsx"}
SEVERITY_ORDER = {"RED": 0, "ORANGE": 1, "YELLOW": 2, "GREEN": 3}
REQUIRED_RULE_FIELDS = {"rule_id", "severity", "category", "pattern", "description", "reason", "recommendation", "test_procedure", "affected_versions", "fixed_version", "reference", "status", "notes"}
VERSION_PATTERN = re.compile(r"\b\d+\.\d+\.\d+(?:[-+._][A-Za-z0-9.-]+)?\b")
VERSION_MANIFEST_KEYS = ("Implementation-Version", "Bundle-Version", "Specification-Version")

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
    source_type: str = "Project"
    provider: str = ""
    resource: str = ""
    event: str = ""

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

class Spinner:
    def __init__(self, message="Scanning"):
        self.message = message
        self._stop_event = threading.Event()
        self._thread = None
    def start(self):
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
    def _spin(self):
        for frame in itertools.cycle("|/-\\"):
            if self._stop_event.is_set(): break
            sys.stdout.write(f"\r{self.message} {frame}")
            sys.stdout.flush(); time.sleep(0.1)
    def stop(self):
        self._stop_event.set()
        if self._thread: self._thread.join()
        sys.stdout.write("\r" + " " * (len(self.message) + 4) + "\r"); sys.stdout.flush()

def get_projects_root(install_root): return install_root / "data" / "projects"

def parse_gateway_xml(install_root):
    values = {}
    try: root = ET.parse(install_root / "data" / "gateway.xml").getroot()
    except (OSError, ET.ParseError): return values
    for entry in root.iter("entry"):
        key = entry.attrib.get("key")
        if key and entry.text: values[key] = entry.text.strip()
    return values

def parse_gwinfo(text):
    result = {}
    for pair in text.split(";"):
        if "=" in pair:
            key, value = pair.split("=", 1); result[key.strip()] = value.strip()
    return result

def version_from_running_gateway(install_root):
    settings = parse_gateway_xml(install_root)
    try: http_port = int(settings.get("gateway.port", "8088"))
    except ValueError: http_port = 8088
    try: https_port = int(settings.get("gateway.sslport", "8043"))
    except ValueError: https_port = 8043
    urls = [f"http://127.0.0.1:{http_port}/system/gwinfo", f"http://127.0.0.1:{http_port}/main/system/gwinfo", f"https://127.0.0.1:{https_port}/system/gwinfo", f"https://127.0.0.1:{https_port}/main/system/gwinfo"]
    insecure = ssl._create_unverified_context()
    for url in urls:
        try:
            response = urllib.request.urlopen(url, timeout=2.0, context=insecure) if url.startswith("https://") else urllib.request.urlopen(url, timeout=2.0)
            with response: text = response.read().decode("utf-8", errors="replace")
        except Exception: continue
        version = parse_gwinfo(text).get("Version")
        if version and VERSION_PATTERN.fullmatch(version): return version
    return None

def parse_manifest(text):
    values, current = {}, None
    for line in text.splitlines():
        if line.startswith(" ") and current:
            values[current] += line[1:]; continue
        if ":" not in line:
            current = None; continue
        key, value = line.split(":", 1); current = key.strip(); values[current] = value.strip()
    return values

def version_from_jar(path):
    try:
        with zipfile.ZipFile(path, "r") as jar: manifest = jar.read("META-INF/MANIFEST.MF").decode("utf-8", errors="replace")
    except (OSError, KeyError, zipfile.BadZipFile): return None
    values = parse_manifest(manifest)
    for key in VERSION_MANIFEST_KEYS:
        value = values.get(key)
        if value:
            match = VERSION_PATTERN.search(value)
            if match: return match.group(0)
    return None

def detect_gateway_version(install_root):
    version = version_from_running_gateway(install_root)
    if version: return version
    for path in [install_root / "lib/core/common/common.jar", install_root / "lib/core/gateway/gateway.jar"]:
        if path.is_file():
            version = version_from_jar(path)
            if version and version.startswith("8."): return version
    return "Unknown"

def parse_bool(value):
    if value is None or value == "": return True
    return value.strip().lower() not in {"0", "false", "no", "n", "disabled", "off"}

def load_rules(path):
    try:
        with path.open("r", newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames is None: raise ValueError("Rules CSV does not contain a header row.")
            missing = REQUIRED_RULE_FIELDS - set(reader.fieldnames)
            if missing: raise ValueError("Rules CSV is missing required columns: " + ", ".join(sorted(missing)))
            rules, seen = [], set()
            for row_number, row in enumerate(reader, start=2):
                rule_id = (row.get("rule_id") or "").strip()
                if not rule_id: raise ValueError(f"Rules CSV row {row_number} has no rule_id.")
                if rule_id in seen: raise ValueError(f"Duplicate rule_id '{rule_id}' on row {row_number}.")
                seen.add(rule_id)
                severity = (row.get("severity") or "").strip().upper()
                if severity not in SEVERITY_ORDER: raise ValueError(f"Invalid severity '{severity}' for rule {rule_id} on row {row_number}.")
                pattern = row.get("pattern") or ""
                try: re.compile(pattern)
                except re.error as e: raise ValueError(f"Invalid regex for rule {rule_id} on row {row_number}: {e}")
                rules.append(Rule(rule_id, severity, (row.get("category") or "").strip(), pattern, (row.get("description") or "").strip(), (row.get("reason") or "").strip(), (row.get("recommendation") or "").strip(), (row.get("test_procedure") or "").strip(), (row.get("affected_versions") or "").strip(), (row.get("fixed_version") or "").strip(), (row.get("reference") or "").strip(), (row.get("status") or "").strip(), (row.get("notes") or "").strip(), parse_bool(row.get("enabled", "true"))))
            return rules
    except FileNotFoundError: raise ValueError(f"Rules file not found: {path}")

def looks_binary(path):
    try:
        with path.open("rb") as f: return b"\x00" in f.read(4096)
    except OSError: return True

def should_scan(path): return path.suffix.lower() in TEXT_EXTENSIONS or (not path.suffix and not looks_binary(path))
def read_text(path):
    for encoding in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
        try: return path.read_text(encoding=encoding)
        except UnicodeDecodeError: continue
        except OSError: return None
    return None

def line_number(text, position): return text.count("\n", 0, position) + 1
def get_line(text, number):
    lines = text.splitlines(); return lines[number - 1].strip() if 1 <= number <= len(lines) else ""
def get_project_name(root, path):
    try: relative = path.relative_to(root)
    except ValueError: return "(unknown)"
    return relative.parts[0] if len(relative.parts) > 1 else "(gateway)"

def scan_regex_rules(text, relative_path, project, rules, source_type="Project", provider="", resource="", event=""):
    findings = []
    for rule in rules:
        if not rule.enabled: continue
        for match in re.compile(rule.pattern, rule.flags).finditer(text):
            line = line_number(text, match.start())
            findings.append(Finding(rule.severity, rule.rule_id, project, relative_path, line, get_line(text, line), rule.description, rule.recommendation, source_type, provider, resource, event))
    return findings

def scan_repository(root, rules):
    findings = []
    for current_root, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in files:
            path = Path(current_root) / filename
            if not should_scan(path): continue
            text = read_text(path)
            if text is None: continue
            findings.extend(scan_regex_rules(text, str(path.relative_to(root)), get_project_name(root, path), rules))
    return findings

def scan_tag_events(install_root, rules):
    findings = []
    for script in discover_tag_event_scripts(install_root):
        findings.extend(scan_regex_rules(script.script, script.source_file, "(gateway)", rules, source_type="Tag Event", provider=script.provider, resource=script.tag_path, event=script.event))
    return findings

def sort_findings(findings):
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.source_type, f.project, f.provider, f.resource, f.file, f.line, f.rule_id))

def write_findings_csv(findings, filename):
    filename.parent.mkdir(parents=True, exist_ok=True)
    with filename.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Severity", "Rule ID", "Source Type", "Project", "Provider", "Resource", "Event", "File", "Line", "Code", "Issue", "Recommendation"])
        for x in findings: writer.writerow([x.severity, x.rule_id, x.source_type, x.project, x.provider, x.resource, x.event, x.file, x.line, x.code, x.message, x.recommendation])

def write_rule_summary_csv(rules, findings, filename):
    filename.parent.mkdir(parents=True, exist_ok=True)
    counts, scopes = {}, {}
    for finding in findings:
        counts[finding.rule_id] = counts.get(finding.rule_id, 0) + 1
        scope = finding.project if finding.source_type == "Project" else f"[{finding.provider}]"
        scopes.setdefault(finding.rule_id, set()).add(scope)
    ordered = sorted({r.rule_id: r for r in rules}.values(), key=lambda r: (SEVERITY_ORDER.get(r.severity, 99), r.category, r.rule_id))
    with filename.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Rule ID", "Severity", "Category", "Enabled", "Occurrences", "Projects/Providers Affected", "Scope Count", "Description", "Reason", "Recommendation", "Test Procedure", "Affected Versions", "Fixed Version", "Reference", "Status", "Notes", "Pattern"])
        for r in ordered:
            affected = sorted(scopes.get(r.rule_id, set()))
            writer.writerow([r.rule_id, r.severity, r.category, "Yes" if r.enabled else "No", counts.get(r.rule_id, 0), "; ".join(affected), len(affected), r.description, r.reason, r.recommendation, r.test_procedure, r.affected_versions, r.fixed_version, r.reference, r.status, r.notes, r.pattern])

def main():
    parser = argparse.ArgumentParser(description="Scan an upgraded Ignition installation for 8.3 compatibility hazards.")
    parser.add_argument("root", nargs="?", default=DEFAULT_WINDOWS_ROOT, help=f"Ignition installation directory (default: {DEFAULT_WINDOWS_ROOT})")
    parser.add_argument("--rules", default="ignition83_rules.csv", help="CSV rules file (default: ignition83_rules.csv)")
    parser.add_argument("--reports", default="reports", help="Directory for generated reports (default: reports)")
    args = parser.parse_args()
    install_root, rules_path, reports_path = Path(args.root).resolve(), Path(args.rules).resolve(), Path(args.reports).resolve()
    projects_root = get_projects_root(install_root)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    findings_path, summary_path = reports_path / f"findings_{timestamp}.csv", reports_path / f"rule_summary_{timestamp}.csv"
    if not install_root.is_dir(): print(f"Ignition install directory does not exist: {install_root}", file=sys.stderr); sys.exit(1)
    if not projects_root.is_dir(): print(f"Ignition projects directory not found: {projects_root}", file=sys.stderr); sys.exit(1)
    try: rules = load_rules(rules_path)
    except ValueError as e: print(f"Rules error: {e}", file=sys.stderr); sys.exit(1)
    gateway_version = detect_gateway_version(install_root)
    start_time, spinner = time.perf_counter(), Spinner("Scanning Ignition projects and tag events")
    spinner.start()
    try:
        project_findings = scan_repository(projects_root, rules)
        tag_scripts = discover_tag_event_scripts(install_root)
        tag_findings = []
        for script in tag_scripts:
            tag_findings.extend(scan_regex_rules(script.script, script.source_file, "(gateway)", rules, "Tag Event", script.provider, script.tag_path, script.event))
        findings = sort_findings(project_findings + tag_findings)
        write_findings_csv(findings, findings_path); write_rule_summary_csv(rules, findings, summary_path)
    finally: spinner.stop()
    elapsed, enabled_count = time.perf_counter() - start_time, sum(1 for r in rules if r.enabled)
    print(f"Gateway version: {gateway_version}")
    print(f"Complete in {elapsed:.2f}s | {len(findings)} findings | {enabled_count}/{len(rules)} rules enabled")
    print(f"Project findings: {len(project_findings)} | Tag event scripts scanned: {len(tag_scripts)} | Tag findings: {len(tag_findings)}")
    print(f"Tag resources: {get_tag_resource_root(install_root)}")
    print(f"Findings: {findings_path}")
    print(f"Summary:  {summary_path}")

if __name__ == "__main__": main()
