"""
Compliance Check 2: Public Access Validation
Flags security signals where a resource has unintended public access exposure.
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
        if s.get("public_access") is True or s.get("type") == "Public Access Exposure"
    ]

    total = len(signals)
    flagged = len(violations)

    print(f"Public Access Check: {total} signals scanned, {flagged} public access violations found")
    for v in violations[:10]:
        print(f"  - {v.get('signal_id')}: {v.get('description')} (severity: {v.get('severity')})")

    # Business rule: any Critical severity public access violation fails the build outright
    critical_violations = [v for v in violations if v.get("severity") == "Critical"]

    passed = len(critical_violations) == 0
    return passed, violations


if __name__ == "__main__":
    passed, violations = run_check()
    if not passed:
        print(f"\nRESULT: FAIL — {len(violations)} public access violations found (including Critical severity)")
        sys.exit(1)
    else:
        print(f"\nRESULT: PASS — {len(violations)} public access violations found, none Critical severity")
        sys.exit(0)