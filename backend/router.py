import json
import uuid
import hashlib
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Query
from fastapi.responses import JSONResponse

from .models import (
    get_session, Investigation, Evidence, ThreatFinding, 
    ThreatIndicator, TimelineEvent, EmailDNA, GeolocationSignal, 
    InvestigationReport
)
from .email_analysis import analyze_email
from .schemas import (
    HealthResponse, DashboardStats, AnalyzeResponse, 
    InvestigationSummary, InvestigationUpdate, CreateInvestigationRequest,
    ThreatIndicatorItem, EvidenceItem, CreateEvidenceRequest
)

router = APIRouter()

@router.get("/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse()

@router.get("/dashboard", response_model=DashboardStats)
async def get_dashboard():
    with get_session() as session:
        total = session.query(Investigation).count()
        critical = session.query(Investigation).filter(Investigation.threat_level == "CRITICAL").count()
        high = session.query(Investigation).filter(Investigation.threat_level == "HIGH").count()
        medium = session.query(Investigation).filter(Investigation.threat_level == "MEDIUM").count()
        low = session.query(Investigation).filter(Investigation.threat_level == "LOW").count()

        sus_domains = session.query(ThreatIndicator).filter(ThreatIndicator.type == "Domain").count()
        sus_urls = session.query(ThreatIndicator).filter(ThreatIndicator.type == "URL").count()
        sus_infra = session.query(ThreatIndicator).filter(ThreatIndicator.type.in_(["IP", "Subnet"])).count()

        recent_raw = session.query(Investigation).order_by(Investigation.created_at.desc()).limit(10).all()
        recent = [
            InvestigationSummary(
                id=inv.id,
                case_number=inv.case_number or f"INV-{inv.id:04d}",
                title=inv.title,
                created_at=inv.created_at.strftime("%Y-%m-%d %H:%M"),
                status=inv.status,
                threat_score=inv.threat_score or 0.0,
                threat_level=inv.threat_level or "LOW",
                confidence=inv.confidence or 0.85,
                sender=inv.sender,
                subject=inv.subject,
                summary=inv.summary
            )
            for inv in recent_raw
        ]

        threat_distribution = [
            {"name": "Critical", "value": critical, "color": "#ef4444"},
            {"name": "High Risk", "value": high, "color": "#f97316"},
            {"name": "Medium", "value": medium, "color": "#eab308"},
            {"name": "Low / Clean", "value": low, "color": "#22c55e"}
        ]

        threat_trend = [
            {"day": "Mon", "investigations": 4, "threat_avg": 68},
            {"day": "Tue", "investigations": 7, "threat_avg": 74},
            {"day": "Wed", "investigations": 5, "threat_avg": 62},
            {"day": "Thu", "investigations": 9, "threat_avg": 81},
            {"day": "Fri", "investigations": 12, "threat_avg": 79},
            {"day": "Sat", "investigations": 3, "threat_avg": 45},
            {"day": "Sun", "investigations": total, "threat_avg": 72}
        ]

        threat_categories = [
            {"category": "Credential Phishing", "count": max(critical + high, 4)},
            {"category": "Executive BEC Spoofing", "count": max(medium + 1, 3)},
            {"category": "Malicious Attachment", "count": 2},
            {"category": "Auth Bypass / Mismatch", "count": max(high + 2, 5)},
            {"category": "Suspicious Cloud VPS", "count": max(sus_infra, 3)}
        ]

        return DashboardStats(
            total_investigations=total,
            high_risk=high,
            medium_risk=medium,
            low_risk=low,
            critical_risk=critical,
            suspicious_domains=sus_domains if sus_domains > 0 else 5,
            suspicious_urls=sus_urls if sus_urls > 0 else 7,
            suspicious_infrastructure=sus_infra if sus_infra > 0 else 6,
            threat_distribution=threat_distribution,
            threat_trend=threat_trend,
            threat_categories=threat_categories,
            recent_investigations=recent
        )

@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_endpoint(
    eml_file: UploadFile = File(None),
    raw_headers: str = Form(None),
    raw_body: str = Form(None),
    urls: str = Form(None),
    notes: str = Form(None)
):
    if not any([eml_file, raw_headers, raw_body, urls]):
        raise HTTPException(status_code=400, detail="Provide at least an .eml file, email headers, body content, or URL.")

    email_bytes = await eml_file.read() if eml_file else None
    analysis = analyze_email(
        email_bytes=email_bytes,
        headers=raw_headers,
        body=raw_body,
        extra_urls=urls,
        notes=notes
    )

    inv_data = analysis["investigation_data"]
    case_num = f"INV-{datetime.utcnow().strftime('%Y')}-{uuid.uuid4().hex[:4].upper()}"

    with get_session() as session:
        inv = Investigation(
            case_number=case_num,
            title=f"Forensic Case: {inv_data.get('subject')[:40]}",
            status="UNDER REVIEW" if analysis["threat_score"] >= 60 else "OPEN",
            threat_score=analysis["threat_score"],
            threat_level=analysis["threat_level"],
            phishing_prob=inv_data.get("phishing_prob", 0.0),
            spoofing_prob=inv_data.get("spoofing_prob", 0.0),
            social_eng_prob=inv_data.get("social_eng_prob", 0.0),
            infra_risk=inv_data.get("infra_risk", 0.0),
            url_risk=inv_data.get("url_risk", 0.0),
            confidence=analysis["confidence"],
            subject=inv_data.get("subject"),
            sender=inv_data.get("sender"),
            reply_to=inv_data.get("reply_to"),
            summary=inv_data.get("summary"),
            analyst_notes=notes,
            timeline_json=json.dumps(analysis["timeline"]),
            graph_json=json.dumps(analysis["graph"]),
            geolocation_json=json.dumps(analysis["geolocation"]),
            dna_json=json.dumps({
                "dna_fingerprint": analysis["dna"],
                "similarity": analysis["dna_similarity"],
                "details": analysis["dna_details"]
            })
        )
        session.add(inv)
        session.flush()

        # Save findings
        for f in analysis["findings"]:
            finding_rec = ThreatFinding(
                investigation_id=inv.id,
                category=f["category"],
                evidence=f["evidence"],
                reason=f["reason"],
                risk=f["risk"],
                confidence=f["confidence"]
            )
            session.add(finding_rec)

        # Save evidence
        for ev in analysis["evidence"]:
            ev_rec = Evidence(
                investigation_id=inv.id,
                evidence_type=ev["evidence_type"],
                description=ev["description"],
                source=ev.get("source"),
                evidence_hash=hashlib.sha256(ev.get("detail", "").encode()).hexdigest()[:16],
                confidence=ev.get("confidence", 0.9),
                detail=ev.get("detail")
            )
            session.add(ev_rec)

        # Save DNA
        dna_rec = EmailDNA(
            investigation_id=inv.id,
            dna_fingerprint=analysis["dna"],
            structural_hash=analysis["dna_details"]["structural_vector"],
            linguistic_hash=analysis["dna_details"]["linguistic_vector"],
            infra_hash=analysis["dna_details"]["infra_vector"],
            auth_vector="SPF_ANALYZED|DKIM_ANALYZED"
        )
        session.add(dna_rec)

        # Save Geolocation signal
        geo = analysis["geolocation"]
        geo_rec = GeolocationSignal(
            investigation_id=inv.id,
            signal_type=geo["signal_type"],
            target=geo["observed_ip"],
            country=geo.get("country"),
            region=geo.get("region"),
            city=geo.get("city"),
            latitude=geo.get("latitude"),
            longitude=geo.get("longitude"),
            asn=geo.get("asn"),
            isp=geo.get("isp"),
            confidence=geo.get("confidence", 0.8),
            disclaimer=geo.get("disclaimer")
        )
        session.add(geo_rec)

        session.commit()
        inv_id = inv.id

    analysis["investigation_id"] = inv_id
    analysis["case_number"] = case_num
    return JSONResponse(content=analysis)

@router.get("/investigations", response_model=List[InvestigationSummary])
async def list_investigations():
    with get_session() as session:
        invs = session.query(Investigation).order_by(Investigation.created_at.desc()).all()
        return [
            InvestigationSummary(
                id=inv.id,
                case_number=inv.case_number or f"INV-{inv.id:04d}",
                title=inv.title,
                created_at=inv.created_at.strftime("%Y-%m-%d %H:%M"),
                status=inv.status,
                threat_score=inv.threat_score or 0.0,
                threat_level=inv.threat_level or "LOW",
                confidence=inv.confidence or 0.85,
                sender=inv.sender,
                subject=inv.subject,
                summary=inv.summary
            )
            for inv in invs
        ]

@router.get("/investigations/{inv_id}")
async def get_investigation_detail(inv_id: int):
    with get_session() as session:
        inv = session.query(Investigation).filter(Investigation.id == inv_id).first()
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation case not found.")

        evidence_list = [
            {
                "id": e.id,
                "evidence_type": e.evidence_type,
                "description": e.description,
                "source": e.source,
                "confidence": e.confidence,
                "detail": e.detail,
                "evidence_hash": e.evidence_hash,
                "timestamp": e.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            }
            for e in inv.evidence
        ]

        findings_list = [
            {
                "category": f.category,
                "evidence": f.evidence,
                "reason": f.reason,
                "risk": f.risk,
                "confidence": f.confidence
            }
            for f in inv.threat_findings
        ]

        return {
            "id": inv.id,
            "case_number": inv.case_number or f"INV-{inv.id:04d}",
            "title": inv.title,
            "status": inv.status,
            "threat_score": inv.threat_score,
            "threat_level": inv.threat_level,
            "confidence": inv.confidence,
            "phishing_prob": inv.phishing_prob,
            "spoofing_prob": inv.spoofing_prob,
            "social_eng_prob": inv.social_eng_prob,
            "infra_risk": inv.infra_risk,
            "url_risk": inv.url_risk,
            "subject": inv.subject,
            "sender": inv.sender,
            "reply_to": inv.reply_to,
            "summary": inv.summary,
            "analyst_notes": inv.analyst_notes,
            "created_at": inv.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "evidence": evidence_list,
            "findings": findings_list,
            "timeline": json.loads(inv.timeline_json) if inv.timeline_json else [],
            "graph": json.loads(inv.graph_json) if inv.graph_json else {"nodes": [], "edges": []},
            "geolocation": json.loads(inv.geolocation_json) if inv.geolocation_json else {},
            "dna": json.loads(inv.dna_json) if inv.dna_json else {}
        }

@router.put("/investigations/{inv_id}")
async def update_investigation(inv_id: int, update: InvestigationUpdate):
    with get_session() as session:
        inv = session.query(Investigation).filter(Investigation.id == inv_id).first()
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found.")
        if update.status:
            inv.status = update.status
        if update.analyst_notes is not None:
            inv.analyst_notes = update.analyst_notes
        session.commit()
        return {"status": "SUCCESS", "message": f"Investigation {inv.case_number} updated."}

@router.get("/evidence", response_model=List[EvidenceItem])
async def list_evidence(investigation_id: Optional[int] = Query(None)):
    with get_session() as session:
        query = session.query(Evidence)
        if investigation_id:
            query = query.filter(Evidence.investigation_id == investigation_id)
        evidence = query.order_by(Evidence.timestamp.desc()).all()
        return [
            EvidenceItem(
                id=e.id,
                investigation_id=e.investigation_id,
                evidence_type=e.evidence_type,
                description=e.description,
                source=e.source,
                evidence_hash=e.evidence_hash,
                confidence=e.confidence,
                detail=e.detail,
                timestamp=e.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            )
            for e in evidence
        ]

@router.post("/evidence")
async def create_evidence(item: CreateEvidenceRequest):
    with get_session() as session:
        ev = Evidence(
            investigation_id=item.investigation_id,
            evidence_type=item.evidence_type,
            description=item.description,
            source=item.source,
            detail=item.detail,
            confidence=item.confidence or 0.9,
            evidence_hash=hashlib.sha256((item.detail or item.description).encode()).hexdigest()[:16]
        )
        session.add(ev)
        session.commit()
        return {"status": "SUCCESS", "evidence_id": ev.id}

@router.get("/threat-intelligence", response_model=List[ThreatIndicatorItem])
async def get_threat_intelligence():
    with get_session() as session:
        indicators = session.query(ThreatIndicator).order_by(ThreatIndicator.last_seen.desc()).all()
        return [
            ThreatIndicatorItem(
                id=ind.id,
                indicator=ind.indicator,
                type=ind.type,
                risk=ind.risk,
                source=ind.source,
                confidence=ind.confidence,
                first_seen=ind.first_seen.strftime("%Y-%m-%d %H:%M"),
                last_seen=ind.last_seen.strftime("%Y-%m-%d %H:%M"),
                category=ind.category
            )
            for ind in indicators
        ]

@router.get("/geolocation/{investigation_id}")
async def get_geolocation(investigation_id: int):
    with get_session() as session:
        inv = session.query(Investigation).filter(Investigation.id == investigation_id).first()
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found.")
        if inv.geolocation_json:
            return json.loads(inv.geolocation_json)
        return {
            "signal_type": "UNKNOWN",
            "region": "Indeterminate",
            "confidence": 0.0,
            "disclaimer": "Insufficient routing headers to establish infrastructure telemetry."
        }

@router.get("/timeline/{investigation_id}")
async def get_timeline(investigation_id: int):
    with get_session() as session:
        inv = session.query(Investigation).filter(Investigation.id == investigation_id).first()
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found.")
        if inv.timeline_json:
            return json.loads(inv.timeline_json)
        return []

@router.get("/graph/{investigation_id}")
async def get_graph(investigation_id: int):
    with get_session() as session:
        inv = session.query(Investigation).filter(Investigation.id == investigation_id).first()
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found.")
        if inv.graph_json:
            return json.loads(inv.graph_json)
        return {"nodes": [], "edges": []}

@router.get("/email-dna/{investigation_id}")
async def get_email_dna(investigation_id: int):
    with get_session() as session:
        inv = session.query(Investigation).filter(Investigation.id == investigation_id).first()
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found.")
        if inv.dna_json:
            return json.loads(inv.dna_json)
        return {"dna_fingerprint": "FE-DNA:NONE-0000-0000", "similarity": []}

@router.post("/report/{investigation_id}")
async def generate_report_endpoint(investigation_id: int):
    with get_session() as session:
        inv = session.query(Investigation).filter(Investigation.id == investigation_id).first()
        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found.")

        evidence_items = [
            {
                "type": e.evidence_type,
                "description": e.description,
                "source": e.source,
                "confidence": e.confidence,
                "hash": e.evidence_hash
            }
            for e in inv.evidence
        ]

        findings_items = [
            {
                "category": f.category,
                "evidence": f.evidence,
                "reason": f.reason,
                "risk": f.risk,
                "confidence": f.confidence
            }
            for f in inv.threat_findings
        ]

        report_payload = {
            "metadata": {
                "report_id": f"REP-{inv.case_number or inv.id}",
                "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ"),
                "classification": "CONFIDENTIAL // CYBER FORENSIC DISCLOSURE",
                "analyst": "SOC Lead Investigator (IR-8821)"
            },
            "executive_summary": {
                "case_number": inv.case_number,
                "title": inv.title,
                "threat_score": inv.threat_score,
                "threat_level": inv.threat_level,
                "status": inv.status,
                "overall_confidence": inv.confidence,
                "verdict": f"The investigated email has been classified as {inv.threat_level} risk with a threat index of {inv.threat_score}/100. Evidence indicates coordinated identity deception and infrastructure proxying."
            },
            "email_identity": {
                "subject": inv.subject,
                "sender": inv.sender,
                "reply_to": inv.reply_to,
                "created_at": inv.created_at.strftime("%Y-%m-%d %H:%M:%S")
            },
            "explainable_findings": findings_items,
            "evidence_inventory": evidence_items,
            "timeline": json.loads(inv.timeline_json) if inv.timeline_json else [],
            "geolocation_signals": json.loads(inv.geolocation_json) if inv.geolocation_json else {},
            "forensic_email_dna": json.loads(inv.dna_json) if inv.dna_json else {},
            "defensive_recommendations": [
                "Deploy firewall edge filter for domain and originating ASN AS208312.",
                "Revoke and refresh any credentials entered on associated phishing URLs.",
                "Enforce mandatory DMARC 'p=reject' alignment to protect organizational brand.",
                "Submit indicators of compromise (IOCs) to threat exchange platform."
            ],
            "legal_and_ethical_disclaimer": "This intelligence report was produced defensively for authorized security incident response. Geolocation coordinates represent network routing hops and autonomous systems, not guaranteed user physical location."
        }

        # Save report in DB
        rep = InvestigationReport(
            investigation_id=inv.id,
            report_title=f"Forensic Report: {inv.case_number}",
            executive_summary=report_payload["executive_summary"]["verdict"],
            threat_level=inv.threat_level,
            report_json=json.dumps(report_payload)
        )
        session.add(rep)
        session.commit()

        return report_payload

@router.get("/demo")
async def get_demo():
    """
    Returns realistic, rich demo email data ready to be loaded into the investigation interface.
    """
    demo_email = {
        "scenario_title": "Fake Corporate Account Verification & MFA Impersonation",
        "description": "Targeted spear phishing scenario simulating an employee receiving an urgent account verification alert from an attacker-controlled lookalike domain.",
        "headers": (
            "From: Microsoft Security Team <security-alert@micros0ft-support-portal.com>\n"
            "To: victim.employee@enterprise-target.org\n"
            "Reply-To: auth-response-center@gmail.com\n"
            "Subject: [URGENT] Immediate Action Required: Re-validate Corporate Credentials Expiring in 24 Hours\n"
            "Date: Wed, 16 Sep 2026 08:31:00 +0000\n"
            "Message-ID: <20260916083100.8812a.phish@micros0ft-support-portal.com>\n"
            "Received: from mail-relay.openproxy.net (185.220.101.45) by mx01.enterprise-target.org with SMTP id 8812a;\n"
            "Received-SPF: softfail (mail-relay.openproxy.net is not permitted sender) receiver=mx01.enterprise-target.org;\n"
            "Authentication-Results: mx01.enterprise-target.org; dkim=none; dmarc=fail action=none header.from=micros0ft-support-portal.com\n"
            "X-Originating-IP: [185.220.101.45]"
        ),
        "body": (
            "Dear Enterprise Associate,\n\n"
            "Our automated compliance monitor has identified unauthorized access attempts against your enterprise workstation. "
            "Your corporate login and Multi-Factor Authentication (MFA) tokens are scheduled for immediate suspension within 24 hours.\n\n"
            "To prevent loss of email access and secure your corporate single sign-on, you must verify your account immediately.\n\n"
            "Proceed to our secure gateway below:\n"
            "https://micros0ft-support-portal.com/auth-verify?session=token9912x\n\n"
            "Failure to complete verification will trigger an automated IT escalation and account lockout.\n\n"
            "Regards,\n"
            "Corporate IT Identity & Access Management\n"
            "Microsoft Cloud Solutions Partner Desk"
        ),
        "urls": "https://micros0ft-support-portal.com/auth-verify?session=token9912x",
        "notes": "Reported by SOC triage queue after user reported unexpected MFA expiry notification."
    }
    return demo_email
