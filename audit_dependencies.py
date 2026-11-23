"""Vulnerable dependencies check (Sreyas Chakka).

Runs pip-audit on the vulnerable and patched package lists and reports PASS or FAIL.
It can also install either list into the active virtual environment so the app
can be run on each set.

Usage:
    python audit_dependencies.py                     scan both lists, print PASS or FAIL
    python audit_dependencies.py --mode vulnerable   scan one list (exit 0 clean, 1 findings, 2 error)
    python audit_dependencies.py --save              also rewrite audit-vuln.txt and audit-patched.txt
    python audit_dependencies.py --switch patched    install a list into the venv (restart the app after)
"""

import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

LISTS = {
    "vulnerable": "requirements-vuln.txt",
    "patched": "requirements.txt",
}
SAVED = {
    "vulnerable": "audit-vuln.txt",
    "patched": "audit-patched.txt",
}
CLEAN_TEXT = "No known vulnerabilities found"


def parse_rows(output):
    """Return the table rows of pip-audit output as (name, version, id, fixes) tuples."""
    rows = []
    in_table = False
    for line in output.splitlines():
        if line.startswith("----"):
            in_table = True
            continue
        if in_table:
            parts = line.split()
            if len(parts) >= 3 and parts[2].startswith(("PYSEC", "GHSA", "CVE")):
                rows.append((parts[0], parts[1], parts[2], parts[3] if len(parts) > 3 else ""))
            elif line.strip() == "":
                break
    return rows


def run_audit(mode):
    """Scan one package list. Status is 'clean', 'findings' or 'error'.

    pip-audit exits with 1 both when it finds vulnerabilities and when it cannot
    run (for example, the module is missing), so the output is checked as well as
    the exit code. A scan that did not finish must never count as a pass.
    """
    path = os.path.join(HERE, LISTS[mode])
    result = {"mode": mode, "file": LISTS[mode], "status": "error", "rows": [], "ids": set(),
              "detail": "", "output": ""}
    try:
        run = subprocess.run(
            [sys.executable, "-m", "pip_audit", "-r", path, "--progress-spinner", "off"],
            capture_output=True, text=True, timeout=600,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        result["detail"] = str(error)
        return result

    rows = parse_rows(run.stdout)
    result["output"] = run.stdout
    result["rows"] = rows
    result["ids"] = {row[2] for row in rows}

    if run.returncode == 0 and CLEAN_TEXT in run.stdout + run.stderr:
        result["status"] = "clean"
    elif run.returncode == 1 and rows:
        result["status"] = "findings"
    else:
        result["detail"] = (run.stderr.strip().splitlines() or ["pip-audit did not finish"])[-1]
    return result


def describe(result):
    if result["status"] == "clean":
        return "No known vulnerabilities"
    if result["status"] == "findings":
        return f"{len(result['ids'])} distinct IDs ({len(result['rows'])} rows)"
    return f"Could not scan: {result['detail']}"


def save(result):
    if result["status"] == "error":
        return
    text = result["output"].strip() if result["status"] == "findings" else CLEAN_TEXT
    with open(os.path.join(HERE, SAVED[result["mode"]]), "w") as f:
        f.write(text + "\n")


def in_venv():
    return sys.prefix != getattr(sys, "base_prefix", sys.prefix)


def switch(mode, force=False):
    if not in_venv() and not force:
        print("Refusing to install outside a virtual environment. Activate your venv first, "
              "or add --force if you are sure.")
        return 2
    path = os.path.join(HERE, LISTS[mode])
    print(f"Installing the {mode} set from {LISTS[mode]} ...")
    run = subprocess.run([sys.executable, "-m", "pip", "install", "-q", "-r", path])
    if run.returncode != 0:
        print("pip install failed.")
        return 2
    from importlib.metadata import version
    for package in ("Flask", "Werkzeug", "Jinja2"):
        print(f"  {package}=={version(package)}")
    print(f"The {mode} set is installed. Restart the app to use it.")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Audit the vulnerable and patched package lists.")
    parser.add_argument("--mode", choices=LISTS, help="scan only one list")
    parser.add_argument("--save", action="store_true", help="rewrite the saved audit files")
    parser.add_argument("--switch", choices=LISTS, help="install one list into the venv")
    parser.add_argument("--force", action="store_true", help="allow --switch outside a venv")
    args = parser.parse_args()

    if args.switch:
        return switch(args.switch, args.force)

    modes = [args.mode] if args.mode else ["vulnerable", "patched"]
    results = {}
    for mode in modes:
        print(f"Scanning {LISTS[mode]} ...")
        results[mode] = run_audit(mode)
        if args.save:
            save(results[mode])

    print()
    print(f"{'Package set':<14}{'File':<24}{'Result'}")
    for mode, result in results.items():
        print(f"{mode:<14}{result['file']:<24}{describe(result)}")

    if any(r["status"] == "error" for r in results.values()):
        print("\nERROR: at least one scan did not run, so nothing was verified.")
        return 2

    if args.mode:
        return 0 if results[args.mode]["status"] == "clean" else 1

    passed = results["vulnerable"]["status"] == "findings" and results["patched"]["status"] == "clean"
    print("\nPASS: the old set has known vulnerabilities and the patched set has none."
          if passed else "\nFAIL: the results do not match what is expected.")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
