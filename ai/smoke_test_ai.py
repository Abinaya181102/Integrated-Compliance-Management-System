"""
Quick manual smoke test for detect_drift() and analyze_audit_gaps().
Run this once to visually confirm both functions return sensible output
before the formal Pytest suite is written.
"""
import os
import sys
import json

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ai.gemini_client import detect_drift, analyze_audit_gaps

print("=" * 60)
print("DRIFT DETECTION TEST")
print("=" * 60)

historical = {
    "encrypted": True,
    "public_access": False,
    "owner": "IT Security",
    "classification": "Confidential",
}
current = {
    "encrypted": False,
    "public_access": True,
    "owner": "IT Security",
    "classification": "Confidential",
}

drift_result = detect_drift(current, historical)
print(json.dumps(drift_result, indent=2))

print()
print("=" * 60)
print("AUDIT GAP ANALYSIS TEST")
print("=" * 60)

evidence_records = [
    {"evidence_id": 1, "file_ref": "audit_2026_q1.pdf", "status": "Submitted"},
    {"evidence_id": 2, "file_ref": None, "status": "Pending"},
    {"evidence_id": 3, "file_ref": "audit_2026_q2.pdf", "status": "Submitted"},
    {"evidence_id": 4, "file_ref": None, "status": "Pending"},
    {"evidence_id": 5, "file_ref": "audit_2026_q3.pdf", "status": "Submitted"},
]

gap_result = analyze_audit_gaps(evidence_records)
print(json.dumps(gap_result, indent=2))