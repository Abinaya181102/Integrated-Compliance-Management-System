"""
Compliance Check 3: Audit Evidence Validation
Flags governance assets that are missing required audit evidence
(no last_reviewed date on file), which indicates an incomplete or
overdue compliance review.
"""
import os
import csv
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "governance", "governance_records.csv")


def run_check(data_path=DATA_PATH):
    if not os.path.exists(data_path):
        print(f"FAIL: data file not found at {data_path}")
        return False, []

    violations = []
    total = 0

    with open(data_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            total += 1
            if not row.get("last_reviewed", "").strip():
                violations.append(row)

    flagged = len(violations)
    print(f"Audit Evidence Check: {total} assets scanned, {flagged} missing review evidence")
    for v in violations[:10]:
        print(f"  - {v.get('asset_id')}: {v.get('asset_name')} (owner: {v.get('owner')})")

    # Business rule: fail if more than 10% of assets are missing evidence
    threshold = 0.10
    passed = (flagged / total) <= threshold if total > 0 else False
    return passed, violations


if __name__ == "__main__":
    passed, violations = run_check()
    if not passed:
        print(f"\nRESULT: FAIL — {len(violations)} assets missing audit evidence (exceeds 10% threshold)")
        sys.exit(1)
    else:
        print(f"\nRESULT: PASS — {len(violations)} assets missing evidence (within acceptable threshold)")
        sys.exit(0)