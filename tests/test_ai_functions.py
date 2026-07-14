"""
validate the AI functions (classification, drift
detection, audit gap analysis) against a small labeled sample set, and
confirm the fallback path activates correctly when the API is unavailable.
"""
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai.gemini_client import (
    classify_compliance,
    detect_drift,
    analyze_audit_gaps,
    _rule_based_classify,
    _rule_based_drift,
    _rule_based_gap_analysis,
)

VALID_CLASSIFICATIONS = {"Compliant", "Partially Compliant", "Non-Compliant", "Evidence Missing"}
VALID_RISK_LEVELS = {"Low", "Medium", "High"}
VALID_SEVERITIES = {"Low", "Medium", "High"}


# ---------------------------------------------------------------------------
# Classification tests — labeled sample set
# ---------------------------------------------------------------------------

def test_classify_clearly_non_compliant_record():
    record = {
        "description": "All data at rest must be encrypted",
        "status": "fail",
        "owner": "IT Security",
        "has_evidence": True,
        "notes": "30 unencrypted resources detected in latest scan",
    }
    result = classify_compliance(record)
    assert result["classification"] in VALID_CLASSIFICATIONS
    # Expected label for this labeled sample
    assert result["classification"] == "Non-Compliant"
    assert 0.0 <= result["confidence"] <= 1.0
    assert result["source"] in ("gemini", "fallback")


def test_classify_clearly_compliant_record():
    record = {
        "description": "Confidential and Restricted assets must be reviewed at least annually",
        "status": "pass",
        "owner": "Data Governance Team",
        "has_evidence": True,
        "notes": "Review completed on schedule, evidence attached",
    }
    result = classify_compliance(record)
    assert result["classification"] in VALID_CLASSIFICATIONS
    assert result["classification"] == "Compliant"


def test_classify_missing_evidence_record():
    record = {
        "description": "Audit evidence must be submitted for each compliance review cycle",
        "status": "pending",
        "owner": "Operations",
        "has_evidence": False,
        "notes": "No evidence file on record",
    }
    result = classify_compliance(record)
    assert result["classification"] in VALID_CLASSIFICATIONS
    assert result["classification"] == "Evidence Missing"


def test_classification_response_has_required_fields():
    record = {"description": "Test control", "status": "pass", "owner": "Test", "has_evidence": True}
    result = classify_compliance(record)
    for key in ("classification", "confidence", "reasoning", "source"):
        assert key in result


# ---------------------------------------------------------------------------
# Drift detection tests
# ---------------------------------------------------------------------------

def test_detect_drift_when_encryption_disabled():
    historical = {"encrypted": True, "public_access": False}
    current = {"encrypted": False, "public_access": False}
    result = detect_drift(current, historical)
    assert result["drift_detected"] is True
    assert "encrypted" in result["changed_fields"]
    assert result["risk_level"] in VALID_RISK_LEVELS


def test_no_drift_when_states_identical():
    state = {"encrypted": True, "public_access": False, "owner": "IT Security"}
    result = detect_drift(state, state)
    assert result["drift_detected"] is False
    assert result["changed_fields"] == []


# ---------------------------------------------------------------------------
# Audit gap analysis tests
# ---------------------------------------------------------------------------

def test_gap_analysis_flags_missing_evidence():
    records = [
        {"evidence_id": 1, "file_ref": "doc1.pdf", "status": "Submitted"},
        {"evidence_id": 2, "file_ref": None, "status": "Pending"},
    ]
    result = analyze_audit_gaps(records)
    assert result["gaps_found"] >= 1
    assert 2 in result["flagged_evidence_ids"]
    assert result["severity"] in VALID_SEVERITIES


def test_gap_analysis_no_gaps_when_all_submitted():
    records = [
        {"evidence_id": 1, "file_ref": "doc1.pdf", "status": "Submitted"},
        {"evidence_id": 2, "file_ref": "doc2.pdf", "status": "Submitted"},
    ]
    result = analyze_audit_gaps(records)
    assert result["gaps_found"] == 0
    assert result["flagged_evidence_ids"] == []


# ---------------------------------------------------------------------------
# Fallback path tests — confirm resilience without calling the real API
# ---------------------------------------------------------------------------

def test_fallback_classifier_works_standalone():
    record = {"status": "fail", "has_evidence": True}
    result = _rule_based_classify(record)
    assert result["classification"] == "Non-Compliant"
    assert result["source"] == "fallback"


def test_fallback_drift_works_standalone():
    historical = {"a": 1, "b": 2}
    current = {"a": 1, "b": 3}
    result = _rule_based_drift(current, historical)
    assert result["drift_detected"] is True
    assert "b" in result["changed_fields"]
    assert result["source"] == "fallback"


def test_fallback_gap_analysis_works_standalone():
    records = [
        {"evidence_id": 1, "file_ref": None, "status": "Pending"},
        {"evidence_id": 2, "file_ref": "doc.pdf", "status": "Submitted"},
    ]
    result = _rule_based_gap_analysis(records)
    assert result["gaps_found"] == 1
    assert 1 in result["flagged_evidence_ids"]
    assert result["source"] == "fallback"