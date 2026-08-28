Scan83 - Ignition 8.3 Compatibility Scanner
===========================================

Scan83 scans an upgraded Ignition installation for known Ignition 8.1 -> 8.3
scripting compatibility hazards and produces CSV reports for review.

QUICK START
-----------

1. Run Scan83 on the Ignition Gateway machine after upgrading the development or
   test Gateway to Ignition 8.3.

2. Keep these files together in the Scan83 folder:

       Scan83.exe
       ignition83_rules.csv
       README.txt
       _internal\

3. Double-click Scan83.exe.

   By default, Scan83 looks for Ignition at:

       C:\Program Files\Inductive Automation\Ignition

4. Review the preflight screen. It shows the detected Gateway version, severity
   threshold, selected rules, project path, tag-resource path, rules file, and
   report location.

5. At "Continue with scan? [Y/n]", press Enter or Y to run the scan. Enter N to
   cancel.

6. Review the console summary and the generated CSV files in the reports folder.
   Scan83 pauses before closing so results and error messages can be reviewed.

REPORTS
-------

Scan83 writes timestamped reports so previous scans are not overwritten:

- findings_<timestamp>.csv
  Individual compatibility findings with source location and recommendation.

- rule_summary_<timestamp>.csv
  Rule-by-rule summary showing occurrences and affected projects/providers.

- scan_summary_<timestamp>.csv
  High-level project and Gateway tag-event coverage summary.

- untracked_vision_binaries_<timestamp>.csv
  Created when binary Vision windows/templates are detected. Binary Vision
  resources may contain scripts that Scan83 cannot statically inspect.

VISION BINARY WARNING
---------------------

Ignition Vision windows/templates stored as binary resources cannot be fully
inspected by Scan83. For fuller coverage, convert applicable Vision resources to
XML by opening/modifying/saving them in an Ignition 8.3 Designer, then rerun the
scan.

COMMAND-LINE USAGE
------------------

Scan83.exe [Ignition install directory] [options]

Examples:

    Scan83.exe

    Scan83.exe "D:\Ignition"

    Scan83.exe --min-severity RED

    Scan83.exe --reports "C:\Scan83Reports"

    Scan83.exe --rules "C:\Scan83\custom_rules.csv"

Options:

    --rules PATH
        Use a different compatibility-rules CSV. The default is
        ignition83_rules.csv beside Scan83.exe.

    --reports PATH
        Directory where CSV reports are written. Default: reports

    --min-severity LEVEL
        Lowest severity included in the scan. Valid values:
        RED, ORANGE, YELLOW, GREEN

        The default is ORANGE, which includes RED and ORANGE rules.

RULES FILE
----------

ignition83_rules.csv is intentionally distributed as a separate file so the
compatibility rule set can be reviewed or updated without rebuilding Scan83.exe.
Keep the file beside Scan83.exe unless --rules is used to specify another path.

NOTES
-----

- Scan83 is intended as an upgrade-readiness and post-upgrade analysis aid. A
  clean scan does not guarantee that every application behavior is compatible.
- Functional testing of upgraded Ignition projects is still recommended.
- Run the scanner against a development/test upgrade before production rollout.
