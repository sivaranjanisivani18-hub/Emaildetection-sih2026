import os
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, Text, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./email_forensic.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    role = Column(String, default="Senior Forensic Analyst")
    badge_id = Column(String, default="SOC-IR-8821")
    created_at = Column(DateTime, default=datetime.utcnow)

class Investigation(Base):
    __tablename__ = "investigations"
    id = Column(Integer, primary_key=True, index=True)
    case_number = Column(String, unique=True, index=True)
    title = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="OPEN")  # OPEN, UNDER REVIEW, ESCALATED, RESOLVED
    threat_score = Column(Float, default=0.0)
    threat_level = Column(String, default="LOW")  # LOW, MEDIUM, HIGH, CRITICAL
    phishing_prob = Column(Float, default=0.0)
    spoofing_prob = Column(Float, default=0.0)
    social_eng_prob = Column(Float, default=0.0)
    infra_risk = Column(Float, default=0.0)
    url_risk = Column(Float, default=0.0)
    confidence = Column(Float, default=0.85)
    subject = Column(String, nullable=True)
    sender = Column(String, nullable=True)
    reply_to = Column(String, nullable=True)
    recipient = Column(String, nullable=True)
    summary = Column(Text, nullable=True)
    analyst_notes = Column(Text, nullable=True)
    
    # JSON payload caches for advanced visualization
    timeline_json = Column(Text, nullable=True)
    graph_json = Column(Text, nullable=True)
    geolocation_json = Column(Text, nullable=True)
    dna_json = Column(Text, nullable=True)

    # Relationships
    evidence = relationship("Evidence", back_populates="investigation", cascade="all, delete-orphan")
    threat_findings = relationship("ThreatFinding", back_populates="investigation", cascade="all, delete-orphan")
    timeline_events = relationship("TimelineEvent", back_populates="investigation", cascade="all, delete-orphan")
    dna_records = relationship("EmailDNA", back_populates="investigation", cascade="all, delete-orphan")
    geo_signals = relationship("GeolocationSignal", back_populates="investigation", cascade="all, delete-orphan")
    reports = relationship("InvestigationReport", back_populates="investigation", cascade="all, delete-orphan")

class EmailRecord(Base):
    __tablename__ = "emails"
    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id"), nullable=True)
    raw_source = Column(Text, nullable=True)
    body_plain = Column(Text, nullable=True)
    body_html = Column(Text, nullable=True)
    sha256_hash = Column(String, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class EmailHeader(Base):
    __tablename__ = "email_headers"
    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id"))
    header_name = Column(String, index=True)
    header_value = Column(Text)
    is_anomalous = Column(Boolean, default=False)
    anomaly_detail = Column(String, nullable=True)

class ThreatFinding(Base):
    __tablename__ = "threat_findings"
    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id"))
    category = Column(String)  # Header, Content, URL, Auth, Infrastructure
    evidence = Column(Text)
    reason = Column(Text)
    risk = Column(String)  # Low, Medium, High, Critical
    confidence = Column(Float)
    investigation = relationship("Investigation", back_populates="threat_findings")

class ThreatIndicator(Base):
    __tablename__ = "indicators"
    id = Column(Integer, primary_key=True, index=True)
    indicator = Column(String, unique=True, index=True)
    type = Column(String)  # Domain, URL, IP, Hash, Subnet
    risk = Column(String)  # Low, Medium, High, Critical
    source = Column(String)
    confidence = Column(Float)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    category = Column(String, default="Credential Phishing")

class Evidence(Base):
    __tablename__ = "evidence"
    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id"))
    evidence_type = Column(String, nullable=False)  # Email, Header, URL, Domain, IP, Attachment, Timeline, AI Finding, Geo Signal
    description = Column(Text, nullable=False)
    source = Column(String, nullable=True)
    evidence_hash = Column(String, nullable=True)
    confidence = Column(Float, default=0.9)
    status = Column(String, default="VERIFIED")
    timestamp = Column(DateTime, default=datetime.utcnow)
    detail = Column(Text, nullable=True)
    investigation = relationship("Investigation", back_populates="evidence")

class TimelineEvent(Base):
    __tablename__ = "timeline_events"
    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id"))
    event_name = Column(String)
    event_timestamp = Column(DateTime)
    hop_number = Column(Integer, nullable=True)
    source_node = Column(String, nullable=True)
    dest_node = Column(String, nullable=True)
    delay_seconds = Column(Float, default=0.0)
    is_anomaly = Column(Boolean, default=False)
    notes = Column(Text, nullable=True)
    investigation = relationship("Investigation", back_populates="timeline_events")

class EmailDNA(Base):
    __tablename__ = "email_dna"
    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id"))
    dna_fingerprint = Column(String, index=True)  # e.g., FE-DNA:A7F3-92C1-81B4
    structural_hash = Column(String)
    linguistic_hash = Column(String)
    infra_hash = Column(String)
    auth_vector = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    investigation = relationship("Investigation", back_populates="dna_records")

class GeolocationSignal(Base):
    __tablename__ = "geolocation_signals"
    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id"))
    signal_type = Column(String)  # OBSERVED, ESTIMATED, UNKNOWN
    target = Column(String)  # IP / Mailserver / ASN
    country = Column(String, nullable=True)
    region = Column(String, nullable=True)
    city = Column(String, nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    asn = Column(String, nullable=True)
    isp = Column(String, nullable=True)
    confidence = Column(Float, default=0.7)
    disclaimer = Column(String, default="Evidence-based infrastructure signal. Does not prove physical location of individual.")
    investigation = relationship("Investigation", back_populates="geo_signals")

class Relationship(Base):
    __tablename__ = "relationships"
    id = Column(Integer, primary_key=True, index=True)
    source_type = Column(String)
    source_id = Column(String)
    target_type = Column(String)
    target_id = Column(String)
    relationship_type = Column(String)  # RESOLVES_TO, SENDS_FROM, CONTAINS_LINK, ROUTED_THROUGH
    confidence = Column(Float, default=0.85)

class InvestigationReport(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id"))
    report_title = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    executive_summary = Column(Text)
    threat_level = Column(String)
    report_json = Column(Text)
    investigation = relationship("Investigation", back_populates="reports")

def get_session():
    return SessionLocal()

def init_db():
    Base.metadata.create_all(bind=engine)
