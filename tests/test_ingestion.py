import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ingestion"))

from ingestion.ingest import app

client = TestClient(app)


def test_root_status():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "Ingestion API running"


def test_ingest_csv_success():
    response = client.post(
        "/ingest/csv",
        params={"filepath": "data/governance/governance_records.csv"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["inserted"] > 0
    assert "skipped" in body


def test_ingest_csv_missing_file():
    response = client.post(
        "/ingest/csv",
        params={"filepath": "data/governance/does_not_exist.csv"},
    )
    assert response.status_code == 404


def test_ingest_json_success():
    response = client.post(
        "/ingest/json",
        params={"filepath": "data/security/security_signals.json"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["inserted"] > 0


def test_ingest_json_missing_file():
    response = client.post(
        "/ingest/json",
        params={"filepath": "data/security/does_not_exist.json"},
    )
    assert response.status_code == 404


def test_ingest_logs_success():
    response = client.post(
        "/ingest/logs",
        params={"filepath": "data/operational/operational_logs.log"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["inserted"] > 0


def test_ingest_logs_missing_file():
    response = client.post(
        "/ingest/logs",
        params={"filepath": "data/operational/does_not_exist.log"},
    )
    assert response.status_code == 404