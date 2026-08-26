#!/usr/bin/env python3

"""Ignition 8.1 -> 8.3.8 compatibility scanner."""

import argparse
import csv
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

from tag_event_scanner import discover_tag_event_scripts, get_tag_resource_root

DEFAULT_WINDOWS_ROOT = r"C:\Program Files\Inductive Automation\Ignition"
SKIP_DIRS = {".git", ".resources", ".idea", ".vs", ".vscode", "node_modules", "dist", "build", "__pycache__", ".pytest_cache", ".mypy_cache"}
TEXT_EXTENSIONS = {".py", ".txt", ".json", ".xml", ".yaml", ".yml", ".properties", ".md", ".sql", ".js", ".ts", ".tsx", ".jsx"}
SEVERITY_ORDER = {"RED": 0, "ORANGE": 1, "YELLOW": 2, "GREEN": 3}
REQUIRED_RULE_FIELDS = {"rule_id", "severity", "category", "pattern", "description", "reason", "recommendation", "test_procedure", "affected_versions", "fixed_version", "reference", "status", "notes"}
VERSION_PATTERN = re.compile(r"\b\d+\.\d+\.\d+(?:[-+._][A-Za-z0-9.-]+)?\b")
VERSION_MANIFEST_KEYS = ("Implementation-Version", "Bundle-Version", "Specification-Version")
VISION_RESOURCE_MARKER = "com.inductiveautomation.vision"
VISION_SCRIPT_CONTAINER_NAMES = {"window", "windows", "template", "templates"}


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


@dataclass
class BinaryVisionResource:
    project: str
    resource: str
    file: str
    size_bytes: int


class ProgressReporter:
    def __init__(self, heartbeat_seconds=10):
        self.heartbeat_seconds = heartbeat_seconds
        self.start_time = time.perf_counter()
        self.phase = "Starting"
        self.current = ""
        self.completed = 0
        self.total = 0
        self.files_scanned = 0
        self.findings = 0
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._heartbeat, daemon=True)
        self._thread.start()

    def set_phase(self, phase, total=0):
        with self._lock:
            self.phase, self.current, self.completed, self.total = phase, "", 0, total
        print(f"\n{phase} ({total} items)" if total else f"\n{phase}", flush=True)

    def begin_item(self, name):
        with self._lock:
            self.current = name
            completed, total = self.completed, self.total
        prefix = f"[{completed + 1}/{total}]" if total else "[... ]"
        print(f"  {prefix} {name}", flush=True)

    def finish_item(self, files_scanned=0, findings=0):
        with self._lock:
            self.completed += 1
            self.files_scanned += files_scanned
            self.findings += findings
            self.current = ""

    def _heartbeat(self):
        while not self._stop_event.wait(self.heartbeat_seconds):
            with self._lock:
                phase, current = self.phase, self.current
                completed, total = self.completed, self.total
                files_scanned, findings = self.files_scanned, self.findings
            elapsed = time.perf_counter() - self.start_time
            progress = f"{completed}/{total}" if total else str(completed)
            current_text = f" | current: {current}" if current else ""
            print(f"    ... still working | {phase}: {progress}{current_text} | files: {files_scanned} | findings: {findings} | elapsed: {elapsed:.1f}s", flush=True)

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join()


def get_projects_root(install_root):
    return install_root / "data" / "projects"


def parse_gateway_xml(install_root):
    values = {}
    try:
        root = ET.parse(install_root / "data" / "gateway.xml").getroot()
    except (OSError, ET.ParseError):
        return values
    for entry in root.iter("entry"):
        key = entry.attrib.get("key")
        if key and entry.text:
            values[key] = entry.text.strip()
    return values


def parse_gwinfo(text):
    result = {}
    for pair in text.split(";"):
        if "=" in pair:
            key, value = pair.split("=", 1)
            result[key.strip()] = value.strip()
    return result


def version_from_running_gateway(install_root):
    settings = parse_gateway_xml(install_root)
    try:
        http_port = int(settings.get("gateway.port", "8088"))
    except ValueError:
        http_port = 8088
    try:
        https_port = int(settings.get("gateway.sslport", "8043"))
    except ValueError:
        https_port = 8043
    urls = [
        f"http://127.0.0.1:{http_port}/system/gwinfo",
        f"http://127.0.0.1:{http_port}/main/system/gwinfo",
        f"https://127.0.0.1:{https_port}/system/gwinfo",
        f"https://127.0.0.1:{https_port}/main/system/gwinfo",
    ]
    insecure = ssl._create_unverified_context()
    for url in urls:
        try:
            response = urllib.request.urlopen(url, timeout=2.0, context=insecure) if url.startswith("https://") else urllib.request.urlopen(url, timeout=2.0)
            with response:
                text = response.read().decode("utf-8", errors="replace")
        except Exception:
            continue
        version = parse_gwinfo(text).get("Version")
        if version and VERSION_PATTERN.fullmatch(version):
            return version
    return None


def parse_manifest(text):
    values, current = {}, None
    for line in text.splitlines():
        if line.startswith(" ") and current:
            values[current] += line[1:]
            continue
        if ":" not in line:
            current = None
            continue
        key, value = line.split(":", 1)
        current = key.strip()
        values[current] = value.strip()
    return values


def version_from_jar(path):
    try:
        with zipfile.ZipFile(path, "r") as jar:
            manifest = jar.read("META-INF/MANIFEST.MF").decode("utf-8", errors="replace")
    except (OSError, KeyError, zipfile.BadZipFile):
        return None
    values = parse_manifest(manifest)
    for key in VERSION_MANIFEST_KEYS:
        value = values.get(key)
        if value:
            match = VERSION_PATTERN.search(value)
            if match:
                return match.group(0)
    return None


def detect_gateway_version(install_root):
    version = version_from_running_gateway(install_root)
    if version:
        return version
    for path in [install_root / "lib/core/common/common.jar", install_root / "lib/core/gateway/gateway.jar"]:
        if path.is_file():
            version = version_from_jar(path)
            if version and version.startswith("8."):
                return version
    return "Unknown"


def parse_bool(value):
    if value is None or value == "":
        return True
    return value.strip().lower() not in {"0", "false", "no", "n", "disabled", "off"}


def load_rules(path):
    try:
        with path.open("r", newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames is None:
                raise ValueError("Rules CSV does not contain a header row.")
            missing = REQUIRED_RULE_FIELDS - set(reader.fieldnames)
            if missing:
                raise ValueError("Rules CSV is missing required columns: " + ", ".join(sorted(missing)))
            rules, seen = [], set()
            for row_number, row in enumerate(reader, start=2):
                rule_id = (row.get("rule_id") or "").strip()
                if not rule_id:
                    raise ValueError(f"Rules CSV row {row_number} has no rule_id.")
                if rule_id in seen:
                    raise ValueError(f"Duplicate rule_id '{rule_id}' on row {row_number}.")
                seen.add(rule_id)
                severity = (row.get("severity") or "").strip().upper()
                if severity not in SEVERITY_ORDER:
                    raise ValueError(f"Invalid severity '{severity}' for rule {rule_id} on row {row_number}.")
                pattern = row.get("pattern") or ""
                try:
                    re.compile(pattern)
                except re.error as e:
                    raise ValueError(f"Invalid regex for rule {rule_id} on row {row_number}: {e}")
                rules.append(Rule(
                    rule_id, severity, (row.get("category") or "").strip(), pattern,
                    (row.get("description") or "").strip(), (row.get("reason") or "").strip(),
                    (row.get("recommendation") or "").strip(), (row.get("test_procedure") or "").strip(),
                    (row.get("affected_versions") or "").strip(), (row.get("fixed_version") or "").strip(),
                    (row.get("reference") or "").strip(), (row.get("status") or "").strip(),
                    (row.get("notes") or "").strip(), parse_bool(row.get("enabled", "true")),
                ))
            return rules
    except FileNotFoundError:
        raise ValueError(f"Rules file not found: {path}")


def filter_rules_by_severity(rules, min_severity):
    threshold = SEVERITY_ORDER[min_severity]
    return [rule for rule in rules if SEVERITY_ORDER[rule.severity] <= threshold]


def looks_binary(path):
    try:
        with path.open("rb") as f:
            return b"\x00" in f.read(4096)
    except OSError:
        return True


def should_scan(path):
    return path.suffix.lower() in TEXT_EXTENSIONS or (not path.suffix and not looks_binary(path))


def read_text(path):
    for encoding in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
        try:
            return path.read_text(encoding=encoding)
        except UnicodeDecodeError:
            continue
        except OSError:
            return None
    return None


def line_number(text, position):
    return text.count("\n", 0, position) + 1


def get_line(text, number):
    lines = text.splitlines()
    return lines[number - 1].strip() if 1 <= number <= len(lines) else ""


def scan_regex_rules(text, relative_path, project, rules, source_type="Project", provider="", resource="", event=""):
    findings = []
    for rule in rules:
        if not rule.enabled:
            continue
        for match in re.compile(rule.pattern, rule.flags).finditer(text):
            line = line_number(text, match.start())
            findings.append(Finding(rule.severity, rule.rule_id, project, relative_path, line, get_line(text, line), rule.description, rule.recommendation, source_type, provider, resource, event))
    return findings


def list_projects(projects_root):
    return sorted([p for p in projects_root.iterdir() if p.is_dir() and p.name not in SKIP_DIRS], key=lambda p: p.name.lower())


def scan_project(project_path, projects_root, rules):
    findings, files_scanned = [], 0
    for current_root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in files:
            path = Path(current_root) / filename
            if not should_scan(path):
                continue
            text = read_text(path)
            if text is None:
                continue
            files_scanned += 1
            findings.extend(scan_regex_rules(text, str(path.relative_to(projects_root)), project_path.name, rules))
    return findings, files_scanned


def is_binary_vision_script_candidate(path):
    if path.suffix.lower() != ".bin":
        return False
    parts = [part.lower() for part in path.parts]
    if not any(VISION_RESOURCE_MARKER in part for part in parts):
        return False
    return any(part in VISION_SCRIPT_CONTAINER_NAMES for part in parts)


def vision_resource_name(project_path, path):
    try:
        relative = path.relative_to(project_path)
    except ValueError:
        return path.parent.name
    parts = list(relative.parts)
    if parts and parts[-1].lower().endswith(".bin"):
        parts = parts[:-1]
    marker_index = next((i for i, part in enumerate(parts) if VISION_RESOURCE_MARKER in part.lower()), None)
    if marker_index is not None:
        parts = parts[marker_index + 1:]
    return "/".join(parts) if parts else path.parent.name


def detect_binary_vision_resources_for_project(project, projects_root):
    resources = []
    for current_root, dirs, files in os.walk(project):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in files:
            path = Path(current_root) / filename
            if not is_binary_vision_script_candidate(path):
                continue
            try:
                size = path.stat().st_size
            except OSError:
                size = 0
            resources.append(BinaryVisionResource(
                project=project.name,
                resource=vision_resource_name(project, path),
                file=str(path.relative_to(projects_root)),
                size_bytes=size,
            ))
    return resources


def scan_projects_with_progress(projects_root, rules, progress):
    projects = list_projects(projects_root)
    findings = []
    binary_resources = []
    project_stats = {}
    progress.set_phase("Project script coverage", len(projects))

    for project in projects:
        progress.begin_item(project.name)
        project_findings, file_count = scan_project(project, projects_root, rules)
        project_binary = detect_binary_vision_resources_for_project(project, projects_root)
        findings.extend(project_findings)
        binary_resources.extend(project_binary)
        project_stats[project.name] = {
            "files_scanned": file_count,
            "script_findings": len(project_findings),
            "binary_vision_resources": len(project_binary),
        }
        progress.finish_item(file_count, len(project_findings))
        print(
            f"      files: {file_count} | binary Vision script candidates: {len(project_binary)} | "
            f"script findings: {len(project_findings)}",
            flush=True,
        )

    return findings, binary_resources, project_stats


def scan_tag_events_with_progress(install_root, rules, progress):
    progress.set_phase("Discovering tag event scripts")
    tag_scripts = discover_tag_event_scripts(install_root)
    providers = {}
    for script in tag_scripts:
        providers.setdefault(script.provider or "(unknown provider)", []).append(script)
    provider_names = sorted(providers, key=str.lower)
    progress.set_phase("Tag event scripts", len(provider_names))
    findings = []
    for provider in provider_names:
        scripts = providers[provider]
        progress.begin_item(f"[{provider}] ({len(scripts)} scripts)")
        provider_findings = []
        for script in scripts:
            provider_findings.extend(scan_regex_rules(script.script, script.source_file, "(gateway)", rules, source_type="Tag Event", provider=script.provider, resource=script.tag_path, event=script.event))
        findings.extend(provider_findings)
        progress.finish_item(len(scripts), len(provider_findings))
        print(f"      scripts: {len(scripts)} | findings: {len(provider_findings)}", flush=True)
    return findings, tag_scripts


def sort_findings(findings):
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.source_type, f.project, f.provider, f.resource, f.file, f.line, f.rule_id))


def write_findings_csv(findings, filename):
    filename.parent.mkdir(parents=True, exist_ok=True)
    with filename.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Severity", "Rule ID", "Source Type", "Project", "Provider", "Resource", "Event", "File", "Line", "Code", "Issue", "Recommendation"])
        for x in findings:
            writer.writerow([x.severity, x.rule_id, x.source_type, x.project, x.provider, x.resource, x.event, x.file, x.line, x.code, x.message, x.recommendation])


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


def write_binary_vision_csv(resources, filename):
    filename.parent.mkdir(parents=True, exist_ok=True)
    with filename.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Project", "Resource", "File", "Size Bytes", "Coverage Status", "Recommendation"])
        for resource in sorted(resources, key=lambda x: (x.project.lower(), x.resource.lower(), x.file.lower())):
            writer.writerow([
                resource.project,
                resource.resource,
                resource.file,
                resource.size_bytes,
                "Not statically scanned",
                "Open/modify/save this Vision window/template in an Ignition 8.3 Designer to convert it to XML, then rerun the scanner.",
            ])


def write_scan_summary_csv(project_stats, binary_resources, project_findings, tag_scripts, tag_findings, filename):
    filename.parent.mkdir(parents=True, exist_ok=True)
    global_binary = len(binary_resources)
    global_findings = len(project_findings) + len(tag_findings)
    with filename.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Scope Type", "Scope", "Binary Vision Script Candidates", "Script Findings", "Files/Scripts Scanned"])
        writer.writerow(["Global", "All", global_binary, global_findings, sum(x["files_scanned"] for x in project_stats.values()) + len(tag_scripts)])
        for project in sorted(project_stats, key=str.lower):
            stats = project_stats[project]
            writer.writerow(["Project", project, stats["binary_vision_resources"], stats["script_findings"], stats["files_scanned"]])
        writer.writerow(["Tag Events", "Gateway", 0, len(tag_findings), len(tag_scripts)])


def main():
    parser = argparse.ArgumentParser(description="Scan an upgraded Ignition installation for 8.3 compatibility hazards.")
    parser.add_argument("root", nargs="?", default=DEFAULT_WINDOWS_ROOT, help=f"Ignition installation directory (default: {DEFAULT_WINDOWS_ROOT})")
    parser.add_argument("--rules", default="ignition83_rules.csv", help="CSV rules file (default: ignition83_rules.csv)")
    parser.add_argument("--reports", default="reports", help="Directory for generated reports (default: reports)")
    parser.add_argument("--min-severity", choices=("RED", "ORANGE", "YELLOW", "GREEN"), default="ORANGE", type=str.upper, help="Lowest severity to scan. Includes that severity and all more severe rules (default: ORANGE).")
    args = parser.parse_args()

    install_root = Path(args.root).resolve()
    rules_path = Path(args.rules).resolve()
    reports_path = Path(args.reports).resolve()
    projects_root = get_projects_root(install_root)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    findings_path = reports_path / f"findings_{timestamp}.csv"
    summary_path = reports_path / f"rule_summary_{timestamp}.csv"
    scan_summary_path = reports_path / f"scan_summary_{timestamp}.csv"
    binary_vision_path = reports_path / f"vision_binary_script_candidates_{timestamp}.csv"

    if not install_root.is_dir():
        print(f"Ignition install directory does not exist: {install_root}", file=sys.stderr)
        sys.exit(1)
    if not projects_root.is_dir():
        print(f"Ignition projects directory not found: {projects_root}", file=sys.stderr)
        sys.exit(1)

    try:
        all_rules = load_rules(rules_path)
    except ValueError as e:
        print(f"Rules error: {e}", file=sys.stderr)
        sys.exit(1)

    rules = filter_rules_by_severity(all_rules, args.min_severity)
    gateway_version = detect_gateway_version(install_root)
    print(f"Gateway version:  {gateway_version}", flush=True)
    print(f"Minimum severity: {args.min_severity} (includes more severe rules)", flush=True)
    print(f"Rules selected:   {len(rules)}/{len(all_rules)}", flush=True)
    print(f"Projects root:    {projects_root}", flush=True)
    print(f"Tag resources:    {get_tag_resource_root(install_root)}", flush=True)

    start_time = time.perf_counter()
    progress = ProgressReporter(heartbeat_seconds=10)
    progress.start()
    try:
        project_findings, binary_vision_resources, project_stats = scan_projects_with_progress(projects_root, rules, progress)
        tag_findings, tag_scripts = scan_tag_events_with_progress(install_root, rules, progress)
        findings = sort_findings(project_findings + tag_findings)

        report_count = 4 if binary_vision_resources else 3
        progress.set_phase("Writing reports", report_count)

        progress.begin_item(findings_path.name)
        write_findings_csv(findings, findings_path)
        progress.finish_item(1, 0)

        progress.begin_item(summary_path.name)
        write_rule_summary_csv(rules, findings, summary_path)
        progress.finish_item(1, 0)

        progress.begin_item(scan_summary_path.name)
        write_scan_summary_csv(project_stats, binary_vision_resources, project_findings, tag_scripts, tag_findings, scan_summary_path)
        progress.finish_item(1, 0)

        if binary_vision_resources:
            progress.begin_item(binary_vision_path.name)
            write_binary_vision_csv(binary_vision_resources, binary_vision_path)
            progress.finish_item(1, 0)
    finally:
        progress.stop()

    elapsed = time.perf_counter() - start_time
    enabled_count = sum(1 for r in rules if r.enabled)

    print("\nScan complete")
    print(f"  Time:              {elapsed:.2f}s")
    print(f"  Minimum severity:  {args.min_severity}")
    print(f"  Rules enabled:     {enabled_count}/{len(rules)} selected ({len(all_rules)} total configured)")
    print("\nScript coverage")
    print(f"  Global -> binary Vision script candidates: {len(binary_vision_resources)} -> script findings: {len(findings)}")
    for project in sorted(project_stats, key=str.lower):
        stats = project_stats[project]
        print(f"  {project} -> binary Vision: {stats['binary_vision_resources']} -> script findings: {stats['script_findings']}")
    print(f"  Gateway tag events -> scripts scanned: {len(tag_scripts)} -> script findings: {len(tag_findings)}")
    print("\nReports")
    print(f"  Findings:       {findings_path}")
    print(f"  Rule summary:   {summary_path}")
    print(f"  Scan summary:   {scan_summary_path}")

    if binary_vision_resources:
        print(f"  Vision gaps:    {binary_vision_path}")
        print("\nWARNING: Binary Vision windows/templates remain and may contain embedded scripts that were not statically inspected.")
        print("Open/modify/save those resources in the 8.3 Designer, then rerun the scanner for fuller coverage.")
    else:
        print("  Vision coverage: No binary Vision windows/templates detected")


if __name__ == "__main__":
    main()
