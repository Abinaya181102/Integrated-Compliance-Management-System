"""
Seeds the controls table with a baseline set of compliance controls
across the governance, security, and operational domains.
Safe to re-run: checks for existing controls before inserting to avoid duplicates.
"""
import os
import sys

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from db.models import Base, Control

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "db", "compliance.db")

engine = create_engine(f"sqlite:///{DB_PATH}")
Base.metadata.create_all(engine)
SessionLocal = sessionmaker(bind=engine)

CONTROLS = [
    # Governance domain
    {"domain": "governance", "description": "Data assets must have an assigned owner and department", "owner": "Data Governance Team"},
    {"domain": "governance", "description": "Confidential and Restricted assets must be reviewed at least annually", "owner": "Data Governance Team"},
    {"domain": "governance", "description": "All assets must be classified (Public, Internal, Confidential, Restricted)", "owner": "Data Governance Team"},
    {"domain": "governance", "description": "Asset metadata tags must be maintained for lineage tracking", "owner": "Data Governance Team"},

    # Security domain
    {"domain": "security", "description": "All data at rest must be encrypted", "owner": "IT Security"},
    {"domain": "security", "description": "No resource may have unauthenticated public network access", "owner": "IT Security"},
    {"domain": "security", "description": "Systems must be patched against known critical CVEs within 30 days", "owner": "IT Security"},
    {"domain": "security", "description": "Access control changes must go through an approval workflow", "owner": "IT Security"},
    {"domain": "security", "description": "Login attempts from anomalous locations must be flagged and reviewed", "owner": "IT Security"},
    {"domain": "security", "description": "Password policies must enforce minimum complexity requirements", "owner": "IT Security"},

    # Operational domain
    {"domain": "operational", "description": "SLA-bound processes must complete within their defined time window", "owner": "Operations"},
    {"domain": "operational", "description": "Changes to payroll, finance, or contracts require documented approval", "owner": "Operations"},
    {"domain": "operational", "description": "Audit evidence must be submitted for each compliance review cycle", "owner": "Operations"},
    {"domain": "operational", "description": "Missing or overdue evidence submissions must be escalated to asset owner", "owner": "Operations"},
]


def seed_controls():
    session = SessionLocal()
    try:
        existing_count = session.query(Control).count()
        if existing_count > 0:
            print(f"Controls table already has {existing_count} rows — skipping seed to avoid duplicates.")
            print("Delete db/compliance.db and re-run db/models.py first if you want a clean reseed.")
            return

        for c in CONTROLS:
            control = Control(
                domain=c["domain"],
                description=c["description"],
                owner=c["owner"],
                status="Not Reviewed",
            )
            session.add(control)
        session.commit()
        print(f"Seeded {len(CONTROLS)} controls successfully.")
    finally:
        session.close()


if __name__ == "__main__":
    seed_controls()