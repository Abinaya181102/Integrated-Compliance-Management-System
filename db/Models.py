import os
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float, ForeignKey
from sqlalchemy.orm import declarative_base
from datetime import datetime

Base = declarative_base()

# Build an absolute path to db/compliance.db based on this file's own location,
# so it works no matter what directory the script is run from.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "compliance.db")


class Control(Base):
    __tablename__ = "controls"
    control_id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(String(100), nullable=False)  # governance, security, operational
    description = Column(Text, nullable=False)
    owner = Column(String(100), nullable=False)
    status = Column(String(50), default="Not Reviewed")


class AuditEvidence(Base):
    __tablename__ = "audit_evidence"
    evidence_id = Column(Integer, primary_key=True, autoincrement=True)
    control_id = Column(Integer, ForeignKey("controls.control_id"), nullable=False)
    file_ref = Column(String(255), nullable=False)
    submitted_date = Column(DateTime, default=datetime.utcnow)
    status = Column(String(50), default="Pending")


class ComplianceCheck(Base):
    __tablename__ = "compliance_checks"
    check_id = Column(Integer, primary_key=True, autoincrement=True)
    control_id = Column(Integer, ForeignKey("controls.control_id"), nullable=False)
    run_date = Column(DateTime, default=datetime.utcnow)
    result = Column(String(50), nullable=False)  # Pass, Fail, Warning
    source = Column(String(100), nullable=False)  # e.g. GitHub Actions, Manual


class SecuritySignal(Base):
    __tablename__ = "security_signals"
    signal_id = Column(Integer, primary_key=True, autoincrement=True)
    type = Column(String(100), nullable=False)
    severity = Column(String(50), nullable=False)  # Low, Medium, High, Critical
    timestamp = Column(DateTime, default=datetime.utcnow)
    related_control_id = Column(Integer, ForeignKey("controls.control_id"))


class AIResult(Base):
    __tablename__ = "ai_results"
    result_id = Column(Integer, primary_key=True, autoincrement=True)
    control_id = Column(Integer, ForeignKey("controls.control_id"), nullable=False)
    analysis_type = Column(String(100), nullable=False)  # classification, drift, gap_analysis
    ai_output = Column(Text, nullable=False)  # raw or structured JSON response
    confidence_score = Column(Float)
    run_date = Column(DateTime, default=datetime.utcnow)


class GovernanceAsset(Base):
    __tablename__ = "governance_assets"
    asset_id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(150), nullable=False)
    asset_type = Column(String(100))  # dataset, system, process
    owner = Column(String(100))
    classification = Column(String(50))  # e.g. Confidential, Internal
    related_control_id = Column(Integer, ForeignKey("controls.control_id"))


# Create SQLite DB
engine = create_engine(f"sqlite:///{DB_PATH}")
Base.metadata.create_all(engine)

if __name__ == "__main__":
    print(f"Database and tables created successfully at {DB_PATH}")
    print("Tables: controls, audit_evidence, compliance_checks, security_signals, ai_results, governance_assets")