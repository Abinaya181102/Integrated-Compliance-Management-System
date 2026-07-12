import os
import csv
import json
import re
from datetime import datetime

from fastapi import FastAPI, UploadFile, File, HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from db.models import Base, GovernanceAsset, SecuritySignal, ComplianceCheck, Control

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "db", "compliance.db")

engine = create_engine(f"sqlite:///{DB_PATH}")
Base.metadata.create_all(engine)
SessionLocal = sessionmaker(bind=engine)

app = FastAPI(title="Compliance Ingestion API")


def get_session():
    return SessionLocal()


@app.get("/")
def root():
    return {"status": "Ingestion API running"}


@app.post("/ingest/csv")
def ingest_csv(filepath: str = "data/governance/governance_records.csv"):
    """Ingest governance records from a CSV file into governance_assets table."""
    full_path = os.path.join(BASE_DIR, filepath)
    if not os.path.exists(full_path):
        raise HTTPException(status_code=404, detail=f"File not found: {full_path}")

    session = get_session()
    inserted, skipped = 0, 0
    try:
        with open(full_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Basic validation: required fields must be non-empty
                if not row.get("asset_id") or not row.get("asset_name") or not row.get("owner"):
                    skipped += 1
                    continue
                asset = GovernanceAsset(
                    name=row["asset_name"],
                    asset_type=row.get("asset_type", ""),
                    owner=row["owner"],
                    classification=row.get("classification", ""),
                    related_control_id=None,
                )
                session.add(asset)
                inserted += 1
            session.commit()
    finally:
        session.close()

    return {"file": filepath, "inserted": inserted, "skipped": skipped}


@app.post("/ingest/json")
def ingest_json(filepath: str = "data/security/security_signals.json"):
    """Ingest security signals from a JSON file into security_signals table."""
    full_path = os.path.join(BASE_DIR, filepath)
    if not os.path.exists(full_path):
        raise HTTPException(status_code=404, detail=f"File not found: {full_path}")

    session = get_session()
    inserted, skipped = 0, 0
    try:
        with open(full_path, encoding="utf-8") as f:
            records = json.load(f)

        for rec in records:
            if not rec.get("type") or not rec.get("severity"):
                skipped += 1
                continue
            try:
                ts = datetime.strptime(rec["timestamp"], "%Y-%m-%dT%H:%M:%SZ")
            except (KeyError, ValueError):
                ts = datetime.utcnow()

            signal = SecuritySignal(
                type=rec["type"],
                severity=rec["severity"],
                timestamp=ts,
                related_control_id=None,
            )
            session.add(signal)
            inserted += 1
        session.commit()
    finally:
        session.close()

    return {"file": filepath, "inserted": inserted, "skipped": skipped}


@app.post("/ingest/logs")
def ingest_logs(filepath: str = "data/operational/operational_logs.log"):
    """Ingest operational compliance events from a pipe-delimited log file
    into compliance_checks table."""
    full_path = os.path.join(BASE_DIR, filepath)
    if not os.path.exists(full_path):
        raise HTTPException(status_code=404, detail=f"File not found: {full_path}")

    session = get_session()
    inserted, skipped = 0, 0

    line_pattern = re.compile(
        r"^(?P<timestamp>\S+) \| (?P<event_id>\S+) \| ASSET=(?P<asset>\S+) \| "
        r"TYPE=(?P<type>\S+) \| RESULT=(?P<result>\S+) \| OWNER=(?P<owner>[^|]+) \| NOTE=(?P<note>.+)$"
    )

    try:
        with open(full_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                match = line_pattern.match(line)
                if not match:
                    skipped += 1
                    continue

                data = match.groupdict()
                try:
                    run_date = datetime.strptime(data["timestamp"], "%Y-%m-%dT%H:%M:%SZ")
                except ValueError:
                    run_date = datetime.utcnow()

                check = ComplianceCheck(
                    control_id=1,  # placeholder link; refined once controls are seeded
                    run_date=run_date,
                    result=data["result"],
                    source="Operational Log Ingestion",
                )
                session.add(check)
                inserted += 1
        session.commit()
    finally:
        session.close()

    return {"file": filepath, "inserted": inserted, "skipped": skipped}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("ingest:app", host="127.0.0.1", port=8000, reload=True)