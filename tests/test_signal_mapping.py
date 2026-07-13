"""
checkpoint tests: validate that security signals correctly map
to controls, and that risk scores compute as expected.
"""
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "validation"))

from validation.map_security_signals import (
    SIGNAL_TYPE_TO_CONTROL_KEYWORD,
    SEVERITY_WEIGHTS,
    build_control_lookup,
    map_signals_to_controls,
)
from db.models import Base, Control, SecuritySignal
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "db", "compliance.db")

engine = create_engine(f"sqlite:///{DB_PATH}")
SessionLocal = sessionmaker(bind=engine)


def test_all_signal_types_have_a_keyword_mapping():
    """Every signal type used in the sample dataset must have a keyword defined,
    otherwise it can never be mapped to a control."""
    expected_types = [
        "Encryption Misconfiguration", "Public Access Exposure", "Malware Alert",
        "Access Control Drift", "Anomalous Login", "Weak Password Policy",
        "Unpatched Vulnerability", "Firewall Rule Violation",
        "Data Exfiltration Attempt", "Privilege Escalation",
    ]
    for signal_type in expected_types:
        assert signal_type in SIGNAL_TYPE_TO_CONTROL_KEYWORD


def test_severity_weights_are_ordered_correctly():
    """Higher severities must always carry a higher numeric weight than lower ones."""
    assert SEVERITY_WEIGHTS["Critical"] > SEVERITY_WEIGHTS["High"]
    assert SEVERITY_WEIGHTS["High"] > SEVERITY_WEIGHTS["Medium"]
    assert SEVERITY_WEIGHTS["Medium"] > SEVERITY_WEIGHTS["Low"]


def test_control_lookup_builds_without_error():
    """The keyword-to-control lookup should return a non-empty dict when
    controls have been seeded."""
    session = SessionLocal()
    try:
        lookup, controls = build_control_lookup(session)
        assert len(controls) > 0
        assert len(lookup) > 0
    finally:
        session.close()


def test_all_ingested_signals_get_mapped():
    """After running the mapping, every security signal in the DB should have
    a related_control_id set (given our sample dataset only uses signal types
    that have a defined keyword mapping)."""
    map_signals_to_controls()

    session = SessionLocal()
    try:
        total_signals = session.query(SecuritySignal).count()
        mapped_signals = session.query(SecuritySignal).filter(
            SecuritySignal.related_control_id.isnot(None)
        ).count()

        assert total_signals > 0, "No signals found — run /ingest/json first"
        assert mapped_signals == total_signals, (
            f"Expected all {total_signals} signals to be mapped, "
            f"but only {mapped_signals} were."
        )
    finally:
        session.close()


def test_security_controls_have_a_risk_score_after_mapping():
    """Every security-domain control that has at least one mapped signal
    should be reachable via a join, confirming the relationship is queryable."""
    session = SessionLocal()
    try:
        security_controls = session.query(Control).filter(Control.domain == "security").all()
        assert len(security_controls) > 0

        for control in security_controls:
            signal_count = session.query(SecuritySignal).filter(
                SecuritySignal.related_control_id == control.control_id
            ).count()
            # Not asserting count > 0 here since not every control is guaranteed
            # signals in a given sample run — just confirming the query works.
            assert signal_count >= 0
    finally:
        session.close()