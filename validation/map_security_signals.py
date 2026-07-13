"""
Security Signal to Control Mapping + Risk Scoring

Links each ingested security_signals row to the most relevant control
in the controls table, based on the signal type, then computes a
risk score per control based on the severity and count of mapped signals.

Run this AFTER db/seed_controls.py and AFTER security signals have been
ingested via /ingest/json.
"""
import os
import sys

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from db.models import Base, Control, SecuritySignal

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "db", "compliance.db")

engine = create_engine(f"sqlite:///{DB_PATH}")
Base.metadata.create_all(engine)
SessionLocal = sessionmaker(bind=engine)

# Maps each security signal "type" to a keyword that should appear in a
# control's description — this is how a signal gets linked to a control.
SIGNAL_TYPE_TO_CONTROL_KEYWORD = {
    "Encryption Misconfiguration": "encrypted",
    "Public Access Exposure": "public network access",
    "Malware Alert": "patched",
    "Access Control Drift": "approval workflow",
    "Anomalous Login": "anomalous locations",
    "Weak Password Policy": "password policies",
    "Unpatched Vulnerability": "patched",
    "Firewall Rule Violation": "public network access",
    "Data Exfiltration Attempt": "approval workflow",
    "Privilege Escalation": "approval workflow",
}

# Severity weights used to compute a numeric risk score per control
SEVERITY_WEIGHTS = {
    "Low": 1,
    "Medium": 3,
    "High": 6,
    "Critical": 10,
}


def build_control_lookup(session):
    """Build a dict of {keyword: control_id} from the controls table."""
    controls = session.query(Control).all()
    lookup = {}
    for control in controls:
        for signal_type, keyword in SIGNAL_TYPE_TO_CONTROL_KEYWORD.items():
            if keyword.lower() in control.description.lower():
                lookup[signal_type] = control.control_id
    return lookup, controls


def map_signals_to_controls():
    session = SessionLocal()
    try:
        keyword_lookup, controls = build_control_lookup(session)
        signals = session.query(SecuritySignal).all()

        if not signals:
            print("No security signals found — run /ingest/json first.")
            return

        mapped, unmapped = 0, 0
        risk_scores = {control.control_id: 0 for control in controls}
        signal_counts = {control.control_id: 0 for control in controls}

        for signal in signals:
            control_id = keyword_lookup.get(signal.type)
            if control_id:
                signal.related_control_id = control_id
                weight = SEVERITY_WEIGHTS.get(signal.severity, 1)
                risk_scores[control_id] += weight
                signal_counts[control_id] += 1
                mapped += 1
            else:
                unmapped += 1

        session.commit()

        print(f"Mapping complete: {mapped} signals mapped, {unmapped} unmapped\n")
        print("Risk scores by control:")
        print(f"{'Control ID':<12}{'Domain':<14}{'Signals':<10}{'Risk Score':<12}Description")
        for control in controls:
            score = risk_scores.get(control.control_id, 0)
            count = signal_counts.get(control.control_id, 0)
            if count > 0:
                print(f"{control.control_id:<12}{control.domain:<14}{count:<10}{score:<12}{control.description[:60]}")

    finally:
        session.close()


if __name__ == "__main__":
    map_signals_to_controls()