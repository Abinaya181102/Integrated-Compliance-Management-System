"""
Gemini AI Integration

Three core AI functions for the compliance platform:
  1. classify_compliance()  - classifies a control's compliance status
  2. detect_drift()         - flags configuration/state changes vs a prior snapshot
  3. analyze_audit_gaps()   - flags missing/incomplete audit evidence

Each function calls Gemini for the primary classification, and falls back
to a rule-based classifier if the API call fails, times out, or returns
output that can't be parsed. This satisfies the Week 8 resilience requirement
(AI must never be a hard dependency for the pipeline to produce a result).
"""
import os
import json
import re

from google import genai
from google.genai import types

MODEL_NAME = "gemini-flash-latest"

_client = None


def get_client():
    """Lazily create the Gemini client so import doesn't fail if the key isn't set yet."""
    global _client
    if _client is None:
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError(
                "GEMINI_API_KEY environment variable is not set. "
                "Set it before calling any AI function."
            )
        _client = genai.Client(api_key=api_key)
    return _client


def _extract_json(text: str):
    """Gemini sometimes wraps JSON in markdown fences — strip those before parsing."""
    cleaned = re.sub(r"^```(json)?|```$", "", text.strip(), flags=re.MULTILINE).strip()
    return json.loads(cleaned)


# ---------------------------------------------------------------------------
# 1. Compliance Classification
# ---------------------------------------------------------------------------

def _rule_based_classify(control_record: dict) -> dict:
    """Fallback classifier: simple heuristic based on control status and evidence fields."""
    status = (control_record.get("status") or "").lower()
    has_evidence = control_record.get("has_evidence", False)

    if not has_evidence:
        classification = "Evidence Missing"
    elif status in ("pass", "compliant", "approved"):
        classification = "Compliant"
    elif status in ("fail", "non-compliant", "rejected"):
        classification = "Non-Compliant"
    else:
        classification = "Partially Compliant"

    return {
        "classification": classification,
        "confidence": 0.5,
        "reasoning": "Rule-based fallback classification (AI unavailable).",
        "source": "fallback",
    }


def classify_compliance(control_record: dict) -> dict:
    """
    Classifies a control as Compliant / Partially Compliant / Non-Compliant / Evidence Missing.
    control_record should contain keys like: description, status, owner, has_evidence, notes.
    """
    prompt = f"""You are a compliance analyst. Classify the following control record into
exactly one of these categories: "Compliant", "Partially Compliant", "Non-Compliant", "Evidence Missing".

Control record:
{json.dumps(control_record, indent=2, default=str)}

Respond with ONLY a JSON object, no markdown, no extra text, in this exact format:
{{"classification": "<one of the 4 categories>", "confidence": <float 0-1>, "reasoning": "<one sentence>"}}
"""
    try:
        client = get_client()
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=prompt,
            config=types.GenerateContentConfig(temperature=0.1),
        )
        result = _extract_json(response.text)
        result["source"] = "gemini"
        return result
    except Exception as e:
        fallback = _rule_based_classify(control_record)
        fallback["error"] = str(e)
        return fallback


# ---------------------------------------------------------------------------
# 2. Drift Detection
# ---------------------------------------------------------------------------

def _rule_based_drift(current_state: dict, historical_state: dict) -> dict:
    """Fallback drift detector: simple key-by-key diff."""
    changed_keys = [
        k for k in current_state
        if current_state.get(k) != historical_state.get(k)
    ]
    return {
        "drift_detected": len(changed_keys) > 0,
        "changed_fields": changed_keys,
        "risk_level": "Medium" if changed_keys else "Low",
        "reasoning": "Rule-based fallback diff (AI unavailable).",
        "source": "fallback",
    }


def detect_drift(current_state: dict, historical_state: dict) -> dict:
    """
    Compares a control's current state to a prior snapshot and flags drift.
    """
    prompt = f"""You are a compliance analyst detecting configuration drift.
Compare the CURRENT state to the HISTORICAL state below and identify any
meaningful compliance-relevant changes.

CURRENT state:
{json.dumps(current_state, indent=2, default=str)}

HISTORICAL state:
{json.dumps(historical_state, indent=2, default=str)}

Respond with ONLY a JSON object, no markdown, no extra text, in this exact format:
{{"drift_detected": <true/false>, "changed_fields": [<list of field names>], "risk_level": "<Low/Medium/High>", "reasoning": "<one sentence>"}}
"""
    try:
        client = get_client()
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=prompt,
            config=types.GenerateContentConfig(temperature=0.1),
        )
        result = _extract_json(response.text)
        result["source"] = "gemini"
        return result
    except Exception as e:
        fallback = _rule_based_drift(current_state, historical_state)
        fallback["error"] = str(e)
        return fallback


# ---------------------------------------------------------------------------
# 3. Audit Gap Analysis
# ---------------------------------------------------------------------------

def _rule_based_gap_analysis(evidence_records: list) -> dict:
    """Fallback gap analyzer: flags records missing file_ref or with Pending status."""
    gaps = [
        r for r in evidence_records
        if not r.get("file_ref") or r.get("status") == "Pending"
    ]
    return {
        "gaps_found": len(gaps),
        "flagged_evidence_ids": [r.get("evidence_id") for r in gaps],
        "severity": "High" if len(gaps) > len(evidence_records) * 0.3 else "Low",
        "reasoning": "Rule-based fallback gap scan (AI unavailable).",
        "source": "fallback",
    }


def analyze_audit_gaps(evidence_records: list) -> dict:
    """
    Reviews a list of audit evidence records and flags missing or incomplete submissions.
    """
    prompt = f"""You are a compliance auditor. Review the following audit evidence records
and identify gaps — missing evidence, incomplete submissions, or records stuck in a
pending state for too long.

Evidence records:
{json.dumps(evidence_records, indent=2, default=str)}

Respond with ONLY a JSON object, no markdown, no extra text, in this exact format:
{{"gaps_found": <int>, "flagged_evidence_ids": [<list>], "severity": "<Low/Medium/High>", "reasoning": "<one sentence>"}}
"""
    try:
        client = get_client()
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=prompt,
            config=types.GenerateContentConfig(temperature=0.1),
        )
        result = _extract_json(response.text)
        result["source"] = "gemini"
        return result
    except Exception as e:
        fallback = _rule_based_gap_analysis(evidence_records)
        fallback["error"] = str(e)
        return fallback


if __name__ == "__main__":
    # Quick manual smoke test
    sample_control = {
        "description": "All data at rest must be encrypted",
        "status": "fail",
        "owner": "IT Security",
        "has_evidence": True,
        "notes": "30 unencrypted resources detected in latest scan",
    }
    print("Classification result:")
    print(json.dumps(classify_compliance(sample_control), indent=2))