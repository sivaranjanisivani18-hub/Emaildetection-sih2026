import json
from datetime import datetime, timedelta
from .models import (
    get_session, init_db, User, Investigation, Evidence, 
    ThreatFinding, ThreatIndicator, TimelineEvent, EmailDNA, 
    GeolocationSignal, InvestigationReport
)

def seed_database():
    init_db()
    with get_session() as session:
        # Check if already seeded
        if session.query(Investigation).count() > 0:
            return

        # 1. Create Default User
        user = User(
            username="analyst_lead",
            role="Principal Cyber Threat Investigator",
            badge_id="SOC-ALPHA-09"
        )
        session.add(user)

        # 2. Seed Threat Indicators (for Threat Intelligence page)
        indicators = [
            ThreatIndicator(
                indicator="security-update-portal-auth.com",
                type="Domain",
                risk="Critical",
                source="Global Threat Feed & Passive DNS",
                confidence=0.96,
                first_seen=datetime.utcnow() - timedelta(days=12),
                last_seen=datetime.utcnow() - timedelta(hours=3),
                category="Credential Harvesting"
            ),
            ThreatIndicator(
                indicator="185.220.101.45",
                type="IP",
                risk="High",
                source="AbuseIPDB & Honeynet Observation",
                confidence=0.91,
                first_seen=datetime.utcnow() - timedelta(days=20),
                last_seen=datetime.utcnow() - timedelta(hours=1),
                category="Bulletproof Hosting / Tor Relay"
            ),
            ThreatIndicator(
                indicator="https://security-update-portal-auth.com/login?token=8812a",
                type="URL",
                risk="Critical",
                source="Internal Sandbox & VirusTotal",
                confidence=0.98,
                first_seen=datetime.utcnow() - timedelta(days=4),
                last_seen=datetime.utcnow() - timedelta(minutes=45),
                category="Corporate Impersonation"
            ),
            ThreatIndicator(
                indicator="194.26.29.112",
                type="IP",
                risk="High",
                source="Shadowserver & DNSBL",
                confidence=0.88,
                first_seen=datetime.utcnow() - timedelta(days=35),
                last_seen=datetime.utcnow() - timedelta(days=2),
                category="Spam Botnet Node"
            ),
            ThreatIndicator(
                indicator="payroll-direct-verify.net",
                type="Domain",
                risk="Medium",
                source="Newly Registered Domains (NRD) Monitor",
                confidence=0.74,
                first_seen=datetime.utcnow() - timedelta(days=6),
                last_seen=datetime.utcnow() - timedelta(hours=18),
                category="Financial BEC Spoofing"
            ),
            ThreatIndicator(
                indicator="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                type="Hash",
                risk="Critical",
                source="Malware Analysis Pipeline",
                confidence=0.95,
                first_seen=datetime.utcnow() - timedelta(days=15),
                last_seen=datetime.utcnow() - timedelta(days=1),
                category="Trojan Dropper (Macro-enabled Doc)"
            ),
            ThreatIndicator(
                indicator="mail-gateway-relay04.biz",
                type="Domain",
                risk="Medium",
                source="MTA Flow Anomaly Engine",
                confidence=0.78,
                first_seen=datetime.utcnow() - timedelta(days=18),
                last_seen=datetime.utcnow() - timedelta(hours=8),
                category="Open Relay Abuse"
            ),
            ThreatIndicator(
                indicator="91.240.118.172",
                type="IP",
                risk="High",
                source="Darknet C2 Sensor",
                confidence=0.89,
                first_seen=datetime.utcnow() - timedelta(days=9),
                last_seen=datetime.utcnow() - timedelta(hours=4),
                category="C2 Fast-Flux Infrastructure"
            )
        ]
        for ind in indicators:
            session.add(ind)

        # 3. Seed Existing Investigations for DNA matching and historical stats
        now = datetime.utcnow()
        inv1 = Investigation(
            case_number="INV-2026-0891",
            title="Executive Spear Phishing & M365 Credential Harvest",
            created_at=now - timedelta(days=3, hours=5),
            status="ESCALATED",
            threat_score=94.0,
            threat_level="CRITICAL",
            phishing_prob=0.96,
            spoofing_prob=0.88,
            social_eng_prob=0.92,
            infra_risk=0.90,
            url_risk=0.95,
            confidence=0.93,
            subject="[URGENT] Immediate Security Action: Multi-Factor Authentication Expiring in 24 Hours",
            sender="Microsoft Security Team <security-alert@micros0ft-support-portal.com>",
            reply_to="auth-response-center@gmail.com",
            recipient="cfo-finance@enterprise-target.org",
            summary="Targeted spear-phishing attempt leveraging lookalike punycode domain, reply-to mismatch to webmail address, and urgency markers to intercept executive credentials.",
            analyst_notes="Identified campaign infrastructure linked to known threat cluster UNC-4819. Domain blocked at perimeter firewall.",
            timeline_json=json.dumps([
                {"event": "Threat Actor Server Initiated", "time": (now - timedelta(days=3, hours=5, minutes=10)).isoformat() + "Z", "hop": 1, "node": "185.220.101.45 (Netherlands)", "delay": "0s"},
                {"event": "Open Relay Hop Relay-01", "time": (now - timedelta(days=3, hours=5, minutes=8)).isoformat() + "Z", "hop": 2, "node": "mail-relay.openproxy.net", "delay": "120s"},
                {"event": "Enterprise Perimeter Ingestion", "time": (now - timedelta(days=3, hours=5, minutes=4)).isoformat() + "Z", "hop": 3, "node": "mx01.enterprise-target.org", "delay": "240s"},
                {"event": "DKIM/SPF Failure Flagged", "time": (now - timedelta(days=3, hours=5, minutes=2)).isoformat() + "Z", "hop": 4, "node": "Internal Security Gateway", "delay": "120s"},
                {"event": "Automated Case Ingestion", "time": (now - timedelta(days=3, hours=5)).isoformat() + "Z", "hop": 5, "node": "Email Forensic Platform", "delay": "0s"}
            ]),
            graph_json=json.dumps({
                "nodes": [
                    {"id": "email", "label": "Email: MFA Expiry Alert", "type": "EMAIL", "risk": "CRITICAL"},
                    {"id": "sender", "label": "security-alert@micros0ft-support-portal.com", "type": "SENDER", "risk": "CRITICAL"},
                    {"id": "reply_to", "label": "auth-response-center@gmail.com", "type": "REPLY-TO", "risk": "HIGH"},
                    {"id": "domain", "label": "micros0ft-support-portal.com", "type": "DOMAIN", "risk": "CRITICAL"},
                    {"id": "url", "label": "https://micros0ft-support-portal.com/auth-verify", "type": "URL", "risk": "CRITICAL"},
                    {"id": "ip", "label": "185.220.101.45", "type": "IP", "risk": "HIGH"},
                    {"id": "mailserver", "label": "mail.micros0ft-support-portal.com", "type": "MAIL SERVER", "risk": "HIGH"},
                    {"id": "infra", "label": "ASN-208312 (Offshore VPS)", "type": "INFRASTRUCTURE", "risk": "HIGH"},
                    {"id": "geo", "label": "Western Europe (Proxy Cluster)", "type": "GEOGRAPHIC SIGNAL", "risk": "MEDIUM"},
                    {"id": "evidence1", "label": "Header: SPF SoftFail & DMARC Reject", "type": "EVIDENCE", "risk": "HIGH"}
                ],
                "edges": [
                    {"from": "email", "to": "sender", "label": "Headers From"},
                    {"from": "email", "to": "reply_to", "label": "Headers Reply-To Mismatch"},
                    {"from": "sender", "to": "domain", "label": "Belongs To"},
                    {"from": "domain", "to": "ip", "label": "A Record"},
                    {"from": "email", "to": "url", "label": "Embedded Link"},
                    {"from": "url", "to": "domain", "label": "Hosted On"},
                    {"from": "ip", "to": "infra", "label": "Autonomous System"},
                    {"from": "infra", "to": "geo", "label": "IP Routing Signal"},
                    {"from": "email", "to": "mailserver", "label": "Received Header MTA"},
                    {"from": "email", "to": "evidence1", "label": "Cryptographic Proof"}
                ]
            }),
            geolocation_json=json.dumps({
                "region": "Western Europe / Data Center Node",
                "country": "Netherlands",
                "city": "Amsterdam",
                "latitude": 52.3702,
                "longitude": 4.8952,
                "asn": "AS208312 - Offshore Cloud Technologies",
                "isp": "Private VPS Network",
                "confidence": 0.88,
                "signal_type": "ESTIMATED",
                "notes": "Evidence shows IP belongs to a VPS hosting range frequently abused for staging phishing kits. Sender physical origin remains UNKNOWN due to MTA proxy hops."
            }),
            dna_json=json.dumps({
                "dna_fingerprint": "FE-DNA:A7F3-92C1-81B4",
                "similarity_baseline": 0.94,
                "structural_vector": "MultiPart-HTML-HiddenText-Base64Font",
                "linguistic_vector": "Urgency-CredentialAction-PenaltyDeadline",
                "infra_vector": "VPS-EphemeralDomain-MissingDMARC"
            })
        )
        session.add(inv1)
        session.flush()

        # Evidence for inv1
        session.add(Evidence(
            investigation_id=inv1.id,
            evidence_type="Header",
            description="Reply-To address differs significantly from From address",
            source="Email Header 'Reply-To'",
            evidence_hash="hsh_8192_replyto_mismatch",
            confidence=0.95,
            detail="From: micros0ft-support-portal.com | Reply-To: auth-response-center@gmail.com"
        ))
        session.add(Evidence(
            investigation_id=inv1.id,
            evidence_type="Authentication",
            description="SPF alignment failed and DMARC enforcement triggered",
            source="Authentication-Results Header",
            evidence_hash="hsh_spf_fail_dkim_none",
            confidence=0.98,
            detail="Received-SPF: softfail (mail-relay.openproxy.net not designated). dkim=none."
        ))
        session.add(Evidence(
            investigation_id=inv1.id,
            evidence_type="URL",
            description="Punycode/Typosquatting credential harvesting link identified",
            source="Email Body Extracted Hyperlink",
            evidence_hash="hsh_url_micros0ft_puny",
            confidence=0.96,
            detail="https://micros0ft-support-portal.com/auth-verify (Domain registered 3 days ago)"
        ))
        session.add(Evidence(
            investigation_id=inv1.id,
            evidence_type="AI Finding",
            description="High linguistic manipulation and psychological pressure index",
            source="NLP Heuristic Core",
            evidence_hash="hsh_nlp_urgency_92",
            confidence=0.92,
            detail="Detected urgency keywords: 'immediate action', 'expiring in 24 hours', 'account termination'."
        ))
        session.add(Evidence(
            investigation_id=inv1.id,
            evidence_type="Geospatial Signal",
            description="Infrastructure IP mapped to bulletproof offshore hosting provider",
            source="BGP Routing & Whois Intelligence",
            evidence_hash="hsh_geo_as208312",
            confidence=0.86,
            detail="AS208312 - Amsterdam Hosting Node. Geolocation reflects routing gateway, not user device."
        ))

        # DNA Record for inv1
        session.add(EmailDNA(
            investigation_id=inv1.id,
            dna_fingerprint="FE-DNA:A7F3-92C1-81B4",
            structural_hash="c8d20e981ba3",
            linguistic_hash="f109ae443c21",
            infra_hash="8812cba945f0",
            auth_vector="SPF_FAIL|DKIM_NONE|DMARC_NONE"
        ))

        # Investigation 2: BEC / Financial Fraud
        inv2 = Investigation(
            case_number="INV-2026-0884",
            title="CEO Impersonation Wire Transfer Fraud",
            created_at=now - timedelta(days=6, hours=2),
            status="RESOLVED",
            threat_score=68.0,
            threat_level="HIGH",
            phishing_prob=0.72,
            spoofing_prob=0.85,
            social_eng_prob=0.91,
            infra_risk=0.55,
            url_risk=0.40,
            confidence=0.88,
            subject="Urgent: Outstanding Vendor Settlement - Re-routing Account Verification",
            sender="David Chen <ceo-executive-desk@fastmail-direct.co>",
            reply_to="corporate-settlements-audit@protonmail.com",
            recipient="accounts-payable@enterprise-target.org",
            summary="Business Email Compromise (BEC) attempt impersonating chief executive, requesting revised banking instructions prior to payroll cycle.",
            analyst_notes="Case resolved. Security awareness notification dispatched to finance department. Domain submitted to registrar abuse desk.",
            timeline_json=json.dumps([
                {"event": "Webmail Client Dispatch", "time": (now - timedelta(days=6, hours=2, minutes=15)).isoformat() + "Z", "hop": 1, "node": "mail.fastmail-direct.co", "delay": "0s"},
                {"event": "Inbound MX Scanning", "time": (now - timedelta(days=6, hours=2, minutes=11)).isoformat() + "Z", "hop": 2, "node": "mx-inbound.enterprise-target.org", "delay": "240s"},
                {"event": "Flagged by Social Engineering Classifier", "time": (now - timedelta(days=6, hours=2, minutes=10)).isoformat() + "Z", "hop": 3, "node": "AI Filter Module", "delay": "60s"}
            ]),
            graph_json=json.dumps({
                "nodes": [
                    {"id": "email", "label": "Email: Vendor Settlement", "type": "EMAIL", "risk": "HIGH"},
                    {"id": "sender", "label": "ceo-executive-desk@fastmail-direct.co", "type": "SENDER", "risk": "HIGH"},
                    {"id": "reply_to", "label": "corporate-settlements-audit@protonmail.com", "type": "REPLY-TO", "risk": "HIGH"},
                    {"id": "domain", "label": "fastmail-direct.co", "type": "DOMAIN", "risk": "MEDIUM"},
                    {"id": "ip", "label": "194.26.29.112", "type": "IP", "risk": "MEDIUM"},
                    {"id": "geo", "label": "Eastern Europe (Hosting ASN)", "type": "GEOGRAPHIC SIGNAL", "risk": "LOW"}
                ],
                "edges": [
                    {"from": "email", "to": "sender", "label": "Sender Address"},
                    {"from": "email", "to": "reply_to", "label": "Reply Redirection"},
                    {"from": "sender", "to": "domain", "label": "Domain Host"},
                    {"from": "domain", "to": "ip", "label": "MTA Resolution"},
                    {"from": "ip", "to": "geo", "label": "Network Route"}
                ]
            }),
            geolocation_json=json.dumps({
                "region": "Eastern Europe",
                "country": "Romania",
                "city": "Bucharest",
                "latitude": 44.4268,
                "longitude": 26.1025,
                "asn": "AS41231 - Global Transit Server",
                "isp": "Commercial Datacenter",
                "confidence": 0.72,
                "signal_type": "ESTIMATED",
                "notes": "Infrastructure signals point to commercial transit node. Physical sender coordinates cannot be established."
            }),
            dna_json=json.dumps({
                "dna_fingerprint": "FE-DNA:B281-44E2-90A7",
                "similarity_baseline": 0.73,
                "structural_vector": "PlainText-MinimalHeaders-NoAttachments",
                "linguistic_vector": "Financial-Urgency-SecrecyRequest",
                "infra_vector": "SharedWebmail-DiscrepantMX"
            })
        )
        session.add(inv2)
        session.flush()

        session.add(EmailDNA(
            investigation_id=inv2.id,
            dna_fingerprint="FE-DNA:B281-44E2-90A7",
            structural_hash="a104f49b1192",
            linguistic_hash="d776be202e09",
            infra_hash="332190bb4c1a",
            auth_vector="SPF_PASS|DKIM_NONE|DMARC_NONE"
        ))

        # Investigation 3: Low Risk Baseline / False Positive
        inv3 = Investigation(
            case_number="INV-2026-0879",
            title="Legitimate Quarterly Benefits Enrollment Notification",
            created_at=now - timedelta(days=9, hours=8),
            status="RESOLVED",
            threat_score=14.0,
            threat_level="LOW",
            phishing_prob=0.08,
            spoofing_prob=0.02,
            social_eng_prob=0.15,
            infra_risk=0.10,
            url_risk=0.05,
            confidence=0.96,
            subject="Action Required: 2026 Benefits Open Enrollment Window Now Open",
            sender="Human Resources <benefits@enterprise-target.org>",
            reply_to="benefits@enterprise-target.org",
            recipient="all-employees@enterprise-target.org",
            summary="Internal benefits newsletter containing external links to authorized benefit plan administrator. Cryptographic signatures valid.",
            analyst_notes="Verified against corporate DKIM selector 202601. DMARC pass with strict alignment.",
            timeline_json=json.dumps([
                {"event": "Internal Mail Relay Sent", "time": (now - timedelta(days=9, hours=8, minutes=10)).isoformat() + "Z", "hop": 1, "node": "internal-smtp.enterprise-target.org", "delay": "0s"},
                {"event": "Authentication Validated", "time": (now - timedelta(days=9, hours=8, minutes=8)).isoformat() + "Z", "hop": 2, "node": "gatekeeper.enterprise-target.org", "delay": "120s"}
            ]),
            graph_json=json.dumps({
                "nodes": [
                    {"id": "email", "label": "Email: Benefits Enrollment", "type": "EMAIL", "risk": "LOW"},
                    {"id": "sender", "label": "benefits@enterprise-target.org", "type": "SENDER", "risk": "LOW"},
                    {"id": "domain", "label": "enterprise-target.org", "type": "DOMAIN", "risk": "LOW"},
                    {"id": "auth", "label": "SPF Pass & DKIM Valid", "type": "EVIDENCE", "risk": "LOW"}
                ],
                "edges": [
                    {"from": "email", "to": "sender", "label": "From"},
                    {"from": "sender", "to": "domain", "label": "Corporate Domain"},
                    {"from": "email", "to": "auth", "label": "Validated"}
                ]
            }),
            geolocation_json=json.dumps({
                "region": "North America",
                "country": "United States",
                "city": "Reston",
                "latitude": 38.9586,
                "longitude": -77.3570,
                "asn": "AS14618 - Corporate Datacenter",
                "isp": "Enterprise Dedicated Transit",
                "confidence": 0.95,
                "signal_type": "OBSERVED",
                "notes": "Internal enterprise mail exchange. All hops within authorized company autonomous system."
            }),
            dna_json=json.dumps({
                "dna_fingerprint": "FE-DNA:C011-88F4-2109",
                "similarity_baseline": 0.15,
                "structural_vector": "CleanMIME-DKIMSigned-CorporateDisclaimer",
                "linguistic_vector": "Informational-Policy-NoUrgency",
                "infra_vector": "DedicatedInternalMTA"
            })
        )
        session.add(inv3)
        session.flush()

        session.add(EmailDNA(
            investigation_id=inv3.id,
            dna_fingerprint="FE-DNA:C011-88F4-2109",
            structural_hash="b5541098ec11",
            linguistic_hash="8901be33ff41",
            infra_hash="1199aacc0045",
            auth_vector="SPF_PASS|DKIM_PASS|DMARC_PASS"
        ))

        session.commit()
