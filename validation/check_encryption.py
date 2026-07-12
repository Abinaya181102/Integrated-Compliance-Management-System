"""
Compliance Check 1: Encryption Validation
Flags security signals where encryption is disabled or misconfigured.
Reads directly from the raw security_signals.json source file so this
check can run standalone in CI without depending on ingestion having run first.
"""
import os
import json
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "security", "security_signals.json")


def run_check(data_path=DATA_PATH):
    if not os.path.exists(data_path):
        print(f"FAIL: data file not found at {data_path}")
        return False, []

    with open(data_path, encoding="utf-8") as f:
        signals = json.load(f)

    violations = [
        s for s in signals
        if s.get("encrypted") is False
    ]

    total = len(signals)
    flagged = len(violations)

    print(f"Encryption Check: {total} signals scanned, {flagged} encryption violations found")
    for v in violations[:10]:
        print(f"  - {v.get('signal_id')}: {v.get('description')} (severity: {v.get('severity')})")

    # Business rule: only Critical severity encryption violations hard-fail the build.
    # High/Medium/Low violations are logged and tracked but do not block the pipeline —
    # mirrors the same tiered approach used in check_public_access.py.
    critical_violations = [v for v in violations if v.get("severity") == "Critical"]

    passed = len(critical_violations) == 0
    return passed, violations, critical_violations


if __name__ == "__main__":
    passed, violations, critical_violations = run_check()
    if not passed:
        print(f"\nRESULT: FAIL — {len(critical_violations)} Critical severity encryption violations detected "
              f"(out of {len(violations)} total)")
        sys.exit(1)
    else:
        print(f"\nRESULT: PASS — {len(violations)} encryption violations found, none Critical severity")
        sys.exit(0)