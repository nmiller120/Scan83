# Scan83 - Ignition 8.3 Compatibility Scanner

Scan83 scans an upgraded Ignition installation for known Ignition 8.1 -> 8.3 scripting compatibility hazards and produces CSV reports for review. It is intended as an upgrade-readiness and post-upgrade analysis aid, not a substitute for functional testing.

## Quick Start

1. Run Scan83 on the Ignition Gateway machine after upgrading a development or test Gateway to Ignition 8.3.
2. Keep `Scan83.exe`, `ignition83_rules.csv`, `README.md`, `LICENSE`, and the `_internal` directory together in the Scan83 distribution folder.
3. Double-click `Scan83.exe`. By default, Scan83 looks for Ignition at `C:\Program Files\Inductive Automation\Ignition`.
4. Review the preflight screen. It shows the detected Gateway version, severity threshold, selected rules, project path, tag-resource path, rules file, and report location.
5. At `Continue with scan? [Y/n]`, press Enter or Y to run the scan, or N to cancel.
6. Review the console summary and generated CSV files in the reports folder. Scan83 pauses before closing so results and error messages can be reviewed.

## Reports

Scan83 writes timestamped reports so previous scans are not overwritten:

- `findings_<timestamp>.csv` - individual compatibility findings with source location and recommendation.
- `rule_summary_<timestamp>.csv` - rule-by-rule summary showing occurrences and affected projects/providers. This is intended to be the primary review checklist.
- `scan_summary_<timestamp>.csv` - high-level project and Gateway tag-event coverage summary.
- `untracked_vision_binaries_<timestamp>.csv` - created when binary Vision windows/templates are detected.

## Vision Binary Warning

Ignition Vision windows/templates stored as binary resources cannot be fully inspected by Scan83. For fuller coverage, convert applicable Vision resources to XML by opening/modifying/saving them in an Ignition 8.3 Designer, then rerun the scan.

## Command-Line Usage

```text
Scan83.exe [Ignition install directory] [options]
```

Examples:

```powershell
Scan83.exe
Scan83.exe "D:\Ignition"
Scan83.exe --min-severity RED
Scan83.exe --reports "C:\Scan83Reports"
Scan83.exe --rules "C:\Scan83\custom_rules.csv"
```

When running directly from Python:

```powershell
python .\ignition83_scan.py "C:\Program Files\Inductive Automation\Ignition"
```

### Options

`--rules PATH`
: Use a different compatibility-rules CSV. The default is `ignition83_rules.csv` beside Scan83.

`--reports PATH`
: Directory where CSV reports are written. Default: `reports`.

`--min-severity LEVEL`
: Lowest severity included in the scan. Valid values are RED, ORANGE, YELLOW, and GREEN. The default is ORANGE, which includes RED and ORANGE rules.

## Rules

`ignition83_rules.csv` is intentionally distributed separately so the compatibility rule set can be reviewed or updated without rebuilding Scan83. The default ruleset is deliberately focused on compatibility patterns with meaningful breaking-change risk rather than general deprecation inventory.

The rules CSV can be edited directly in Excel. Set `enabled=No` to retain a rule in a rules file without scanning for it. A different or expanded rules file can be supplied with `--rules`.

## Gateway Detection

The positional root is the Ignition installation directory. Scan83 automatically scans the `data/projects` directory beneath it and attempts to detect the installed Gateway version. If the version cannot be determined reliably, Scan83 reports `Gateway version: Unknown` rather than guessing.

## Limitations

- A clean Scan83 report does not guarantee that every application behavior is compatible with Ignition 8.3.
- Functional testing of upgraded Ignition projects is still required.
- Run the scanner against a development/test upgrade before production rollout.
- Binary Vision resources may contain scripts that cannot be statically inspected until converted to XML-backed resources.

## License

Scan83 is released under the MIT License. See `LICENSE` for details.
