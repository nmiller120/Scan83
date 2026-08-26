Ignition 8.1 -> 8.3.8 Compatibility Audit

Files:
- ignition83_scan.py        Scanner
- ignition83_rules.csv      Source-of-truth rule/checklist file
- .gitignore                Ignores generated reports/

The positional root is now the Ignition installation directory. The scanner automatically scans the data/projects directory beneath it and attempts to detect the installed Gateway version from the installation.

Run from this directory, for example:

python .\ignition83_scan.py ^
  "C:\Program Files\Inductive Automation\Ignition"

PowerShell example:

python .\ignition83_scan.py `
  "C:\Program Files\Inductive Automation\Ignition"

Specify a different reports directory:

python .\ignition83_scan.py `
  "C:\Program Files\Inductive Automation\Ignition" `
  --reports "C:\Temp\Ignition83Reports"

Generated in the reports directory:
- findings.csv
- rule_summary.csv

While scanning, the console displays a spinner. When complete, it prints the detected Gateway version, elapsed execution time, finding count, enabled rule count, projects path, and reports directory. Detailed findings are written to the CSV files rather than dumped to the console.

If the Gateway version cannot be determined reliably from the local installation, the scanner reports Gateway version: Unknown rather than guessing.

findings.csv:
One row per source-code occurrence.

rule_summary.csv:
One row per rule, including occurrence count and affected projects.
This is intended to be the main test/review checklist.

The rules CSV is designed to be edited directly in Excel.
Set enabled=No to retain a rule in the audit checklist without scanning for it.
