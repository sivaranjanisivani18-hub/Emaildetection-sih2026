from pydantic import BaseModel, Field
from typing import List, Optional, Any, Dict

class HealthResponse(BaseModel):
    status: str = "ONLINE"
    service: str = "AI-Powered Email Forensic Intelligence Platform"
    version: str = "2.4.0-hackathon-soc"
    database: str = "CONNECTED"

class ThreatFindingItem(BaseModel):
    category: str
    evidence: str
    reason: str
    risk: str
    confidence: float

class EvidenceItem(BaseModel):
    id: Optional[int] = None
    investigation_id: Optional[int] = None
    evidence_type: str
    description: Optional[str] = None
    source: Optional[str] = None
    evidence_hash: Optional[str] = None
    confidence: Optional[float] = 0.9
    detail: Optional[str] = None
    timestamp: Optional[str] = None

class InvestigationData(BaseModel):
    subject: Optional[str] = None
    sender: Optional[str] = None
    reply_to: Optional[str] = None
    threat_score: Optional[float] = None
    threat_level: Optional[str] = None
    phishing_prob: Optional[float] = None
    spoofing_prob: Optional[float] = None
    social_eng_prob: Optional[float] = None
    infra_risk: Optional[float] = None
    url_risk: Optional[float] = None
    confidence: Optional[float] = None
    summary: Optional[str] = None

class AnalyzeResponse(BaseModel):
    investigation_id: Optional[int] = None
    case_number: Optional[str] = None
    investigation_data: InvestigationData
    threat_score: float
    threat_level: str
    confidence: float
    findings: List[ThreatFindingItem] = Field(default_factory=list)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    explanation: List[str] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    graph: Dict[str, Any] = Field(default_factory=dict)
    geolocation: Dict[str, Any] = Field(default_factory=dict)
    dna: Optional[str] = None
    dna_details: Optional[Dict[str, Any]] = None
    dna_similarity: List[Dict[str, Any]] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    headers: Dict[str, Any] = Field(default_factory=dict)
    recommendations: List[str] = Field(default_factory=list)

class InvestigationSummary(BaseModel):
    id: int
    case_number: Optional[str] = None
    title: str
    created_at: str
    status: str
    threat_score: float
    threat_level: str
    confidence: float
    sender: Optional[str] = None
    subject: Optional[str] = None
    summary: Optional[str] = None

class InvestigationUpdate(BaseModel):
    status: Optional[str] = None
    analyst_notes: Optional[str] = None

class CreateInvestigationRequest(BaseModel):
    title: str
    subject: Optional[str] = None
    sender: Optional[str] = None
    notes: Optional[str] = None

class ThreatIndicatorItem(BaseModel):
    id: int
    indicator: str
    type: str
    risk: str
    source: str
    confidence: float
    first_seen: str
    last_seen: str
    category: str

class DashboardStats(BaseModel):
    total_investigations: int
    high_risk: int
    medium_risk: int
    low_risk: int
    critical_risk: int
    suspicious_domains: int
    suspicious_urls: int
    suspicious_infrastructure: int
    threat_distribution: List[Dict[str, Any]]
    threat_trend: List[Dict[str, Any]]
    threat_categories: List[Dict[str, Any]]
    recent_investigations: List[InvestigationSummary]

class CreateEvidenceRequest(BaseModel):
    investigation_id: int
    evidence_type: str
    description: str
    source: Optional[str] = "Manual Analyst Submission"
    detail: Optional[str] = None
    confidence: Optional[float] = 0.9
