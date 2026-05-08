"""
CrewAI Autonomous Agent System for Cyber Global Shield.

Four specialized agents work together:
1. Triage Agent - Evaluates alerts, assigns severity & priority
2. Investigation Agent - Deep-dives logs, correlates events, traces kill chain
3. Response Agent - Decides and executes automated responses via SOAR
4. Threat Intel Agent - Enriches with MISP, VirusTotal, Cortex
"""

import json
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
import structlog

from crewai import Agent, Task, Crew, Process
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from app.core.config import settings

logger = structlog.get_logger(__name__)


# ---- Pydantic output schemas for structured agent reasoning ----

class TriageAssessment(BaseModel):
    alert_id: str
    severity: str
    confidence: float
    priority: int = Field(ge=1, le=10)
    is_false_positive: bool
    requires_immediate_action: bool
    reasoning: str
    recommended_next_step: str


class InvestigationReport(BaseModel):
    alert_id: str
    root_cause: str
    attack_vector: str
    affected_assets: List[str]
    mitre_tactic: Optional[str]
    mitre_technique: Optional[str]
    kill_chain_phase: Optional[str]
    iocs_found: Dict[str, List[str]]
    timeline: List[Dict[str, Any]]
    lateral_movement_detected: bool
    data_exfiltration_detected: bool
    confidence: float
    summary: str


class ResponseDecision(BaseModel):
    alert_id: str
    decision_type: str  # block_ip, isolate_host, quarantine_file, escalate, ignore, monitor
    confidence: float
    actions: List[Dict[str, Any]]
    playbook_name: Optional[str]
    requires_human_approval: bool
    reasoning: str
    risk_assessment: str


class ThreatIntelEnrichment(BaseModel):
    alert_id: str
    indicator_type: str
    indicator_value: str
    threat_actor: Optional[str]
    campaign: Optional[str]
    first_seen: Optional[str]
    last_seen: Optional[str]
    confidence: float
    sources: List[str]
    related_iocs: List[Dict[str, str]]
    recommendation: str


# ---- CrewAI System ----

class CyberShieldCrew:
    """
    CrewAI orchestration for autonomous cybersecurity operations.
    """

    def __init__(
        self,
        model_name: Optional[str] = None,
        temperature: Optional[float] = None,
        verbose: bool = False,
    ):
        self.model_name = model_name or settings.CREWAI_MODEL
        self.temperature = temperature or settings.CREWAI_TEMPERATURE
        self.verbose = verbose

        # Initialize LLM
        self.llm = ChatOpenAI(
            model=self.model_name,
            temperature=self.temperature,
            max_tokens=settings.CREWAI_MAX_TOKENS,
            api_key=settings.OPENAI_API_KEY or "sk-placeholder",
        )

        # Create agents
        self.triage_agent = self._create_triage_agent()
        self.investigation_agent = self._create_investigation_agent()
        self.response_agent = self._create_response_agent()
        self.threat_intel_agent = self._create_threat_intel_agent()

        # Create crews for different workflows
        self._alert_crew = self._create_alert_crew()
        self._investigation_crew = self._create_investigation_crew()

        logger.info("cyber_shield_crew_initialized", model=self.model_name)

    def _create_triage_agent(self) -> Agent:
        return Agent(
            role="Senior SOC Triage Analyst",
            goal="Rapidly evaluate incoming security alerts, determine true/false positives, "
                 "assign accurate severity and priority, and route to appropriate investigation queue.",
            backstory="""You are a battle-hardened SOC analyst with 15 years of experience in 
                incident triage across Fortune 500 companies and government agencies. You've seen 
                every type of alert - from noisy false positives to sophisticated APT attacks. 
                You can spot patterns instantly and know exactly which alerts need immediate attention. 
                Your decisions have prevented breaches that would have caused billions in damages.""",
            llm=self.llm,
            verbose=self.verbose,
            allow_delegation=True,
            tools=[],  # Tools added dynamically
        )

    def _create_investigation_agent(self) -> Agent:
        return Agent(
            role="Senior Threat Investigator",
            goal="Conduct deep-dive forensic investigations on security alerts, trace the kill chain, "
                 "identify root causes, map to MITRE ATT&CK, and produce actionable intelligence reports.",
            backstory="""You are a world-class digital forensics expert and threat hunter. You've 
                tracked nation-state APT groups, dismantled ransomware operations, and your 
                investigations have been cited in INTERPOL reports. You understand network protocols 
                at the packet level, can reverse engineer malware in your sleep, and know the MITRE 
                ATT&CK framework better than its creators. Your investigations are thorough, 
                evidence-based, and always lead to the truth.""",
            llm=self.llm,
            verbose=self.verbose,
            allow_delegation=True,
            tools=[],
        )

    def _create_response_agent(self) -> Agent:
        return Agent(
            role="Autonomous Incident Response Commander",
            goal="Make rapid, confident decisions on incident response actions. Execute automated "
                 "containment, eradication, and recovery playbooks. Minimize dwell time and blast radius.",
            backstory="""You are an elite incident response commander who has led response efforts 
                for the world's largest data breaches. You've designed IR playbooks used by major 
                MSSPs and have automated response at scale. You know that in cybersecurity, 
                seconds matter - a ransomware encrypts in 45 seconds, and your decisions must be 
                faster. You balance aggressive containment with business continuity, always 
                prioritizing patient zero isolation and lateral movement prevention. You never 
                hesitate when action is needed, but you know when to escalate to humans for 
                critical decisions.""",
            llm=self.llm,
            verbose=self.verbose,
            allow_delegation=False,
            tools=[],
        )

    def _create_threat_intel_agent(self) -> Agent:
        return Agent(
            role="Threat Intelligence Fusion Analyst",
            goal="Enrich alerts with external threat intelligence from MISP, VirusTotal, Cortex, "
                 "AlienVault, and OSINT sources. Identify threat actors, campaigns, and related IOCs.",
            backstory="""You are a threat intelligence expert with deep connections across the 
                global CTI community. You've mapped APT group infrastructure, uncovered zero-day 
                exploitation campaigns, and your threat reports are read by CISOs worldwide. 
                You speak STIX/TAXII fluently and can pivot from a single IOC to a full threat 
                actor profile in minutes. You understand the geopolitical context of cyber threats 
                and can distinguish between criminal, hacktivist, and nation-state activity.""",
            llm=self.llm,
            verbose=self.verbose,
            allow_delegation=True,
            tools=[],
        )

    def _create_alert_crew(self) -> Crew:
        """Create crew for alert triage workflow."""
        return Crew(
            agents=[self.triage_agent],
            tasks=[],
            process=Process.sequential,
            verbose=self.verbose,
        )

    def _create_investigation_crew(self) -> Crew:
        """Create crew for full investigation workflow."""
        return Crew(
            agents=[
                self.triage_agent,
                self.investigation_agent,
                self.threat_intel_agent,
                self.response_agent,
            ],
            tasks=[],
            process=Process.sequential,
            verbose=self.verbose,
        )

    async def triage_alert(
        self, alert: Dict[str, Any], context: Optional[Dict[str, Any]] = None
    ) -> TriageAssessment:
        """
        Triage a single alert.
        Returns a structured TriageAssessment.
        """
        context = context or {}
        task = Task(
            description=f"""
                Triage this security alert and provide a structured assessment.

                ALERT:
                - ID: {alert.get('id')}
                - Type: {alert.get('alert_type')}
                - Title: {alert.get('title')}
                - Source: {alert.get('source')}
                - Raw Data: {json.dumps(alert.get('raw_data', {}), default=str)[:2000]}
                - MITRE: {alert.get('mitre_tactic', 'N/A')}/{alert.get('mitre_technique', 'N/A')}

                CONTEXT:
                - Organization: {context.get('org_id')}
                - Hour: {datetime.now(timezone.utc).hour}
                - Recent Alerts: {context.get('recent_alert_count', 0)}
                - Network Baseline: {json.dumps(context.get('baseline', {}))[:500]}

                Triage Checklist:
                1. Is this a true positive or false positive? Why?
                2. What is the appropriate severity (info/low/medium/high/critical)?
                3. Confidence level (0.0-1.0)?
                4. Priority (1-10, 10 highest)?
                5. Does this require immediate automated response?
                6. What should be the next step?

                Return as structured JSON matching TriageAssessment schema.
            """,
            expected_output="TriageAssessment as JSON",
            agent=self.triage_agent,
        )

        result = await task.execute()
        return self._parse_result(result, TriageAssessment)

    async def investigate(
        self, alert: Dict[str, Any], logs: List[Dict[str, Any]], iocs: Optional[Dict[str, Any]] = None
    ) -> InvestigationReport:
        """
        Perform deep investigation on an alert.
        """
        task = Task(
            description=f"""
                Investigate this security alert thoroughly. Correlate across all available data.

                ALERT:
                - ID: {alert.get('id')}
                - Type: {alert.get('alert_type')}
                - Title: {alert.get('title')}
                - Source IPs: {alert.get('src_ips', [])}
                - Destination IPs: {alert.get('dst_ips', [])}
                - Raw Alert: {json.dumps(alert, default=str)[:3000]}

                RELATED LOGS (last {len(logs)} events):
                {json.dumps(logs[:20], default=str)[:5000]}

                KNOWN IOCs:
                {json.dumps(iocs or {}, default=str)[:1000]}

                Investigation Mandate:
                1. Identify the root cause and attack vector
                2. Map the kill chain phase (Recon, Weaponization, Delivery, Exploitation, 
                   Installation, C2, Actions on Objectives)
                3. Map to MITRE ATT&CK (Tactic TAxxxx + Technique Txxxx)
                4. List ALL affected assets
                5. Extract IOCs (IPs, domains, hashes, URLs, email addresses)
                6. Determine if lateral movement occurred
                7. Determine if data exfiltration occurred
                8. Build a timeline of events
                9. Confidence level (0.0-1.0)

                Return as structured JSON matching InvestigationReport schema.
            """,
            expected_output="InvestigationReport as JSON",
            agent=self.investigation_agent,
        )

        result = await task.execute()
        return self._parse_result(result, InvestigationReport)

    async def decide_response(
        self,
        investigation: InvestigationReport,
        alert: Dict[str, Any],
        available_playbooks: List[str],
    ) -> ResponseDecision:
        """
        Decide and plan automated response actions.
        """
        task = Task(
            description=f"""
                Based on the investigation, decide the appropriate response actions.

                INVESTIGATION SUMMARY: {investigation.summary}
                ROOT CAUSE: {investigation.root_cause}
                ATTACK VECTOR: {investigation.attack_vector}
                AFFECTED ASSETS: {investigation.affected_assets}
                MITRE MAPPING: {investigation.mitre_tactic}/{investigation.mitre_technique}
                IOCs: {json.dumps(investigation.iocs_found, default=str)[:2000]}
                LATERAL MOVEMENT: {investigation.lateral_movement_detected}
                DATA EXFILTRATION: {investigation.data_exfiltration_detected}

                AVAILABLE PLAYBOOKS: {available_playbooks}

                Response Decision Framework:
                1. If ransomware activity detected → IMMEDIATE isolation of patient zero
                2. If lateral movement detected → Segment network, block IOCs, revoke credentials
                3. If data exfiltration detected → Block egress, snapshot for forensic
                4. If C2 communication → Block IOC, sinkhole DNS
                5. If false positive → Close alert, ignore

                IMPORTANT: Always specify if human approval is required.
                Only skip approval for high-confidence (>0.9), well-practiced responses.

                Return as structured JSON matching ResponseDecision schema.
            """,
            expected_output="ResponseDecision as JSON",
            agent=self.response_agent,
        )

        result = await task.execute()
        return self._parse_result(result, ResponseDecision)

    async def enrich_threat_intel(
        self, alert: Dict[str, Any], iocs: Dict[str, Any]
    ) -> ThreatIntelEnrichment:
        """
        Enrich an alert with external threat intelligence.
        """
        task = Task(
            description=f"""
                Enrich the following IOCs with external threat intelligence.

                ALERT ID: {alert.get('id')}
                IOCs to investigate:
                {json.dumps(iocs, default=str)[:3000]}

                For EACH IOC:
                1. Query threat intel sources (MISP, VirusTotal, AlienVault, Shodan)
                2. Identify if linked to known threat actors or campaigns
                3. Determine first/last seen dates
                4. Find related IOCs
                5. Confidence level (0.0-1.0)
                6. Provide actionable recommendation

                Return as structured JSON matching ThreatIntelEnrichment schema.
            """,
            expected_output="ThreatIntelEnrichment as JSON",
            agent=self.threat_intel_agent,
        )

        result = await task.execute()
        return self._parse_result(result, ThreatIntelEnrichment)

    async def run_full_pipeline(
        self, alert: Dict[str, Any], logs: List[Dict[str, Any]], context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute the complete autonomous SOC pipeline:
        Triage → Investigation → Threat Intel → Response Decision
        """
        start_time = datetime.now(timezone.utc)
        context = context or {}

        logger.info("full_pipeline_started", alert_id=alert.get("id"))

        # Stage 1: Triage
        triage = await self.triage_alert(alert, context)
        logger.info("pipeline_triage_complete", alert_id=alert.get("id"), severity=triage.severity)

        if triage.is_false_positive:
            return {
                "alert_id": alert.get("id"),
                "stage": "triaged",
                "is_false_positive": True,
                "triage": triage.model_dump(),
                "duration_seconds": (datetime.now(timezone.utc) - start_time).total_seconds(),
            }

        # Stage 2: Threat Intel Enrichment
        iocs = alert.get("iocs", {})
        enrichment = None
        if iocs:
            enrichment = await self.enrich_threat_intel(alert, iocs)
            logger.info("pipeline_enrichment_complete", alert_id=alert.get("id"))

        # Stage 3: Investigation
        investigation = await self.investigate(alert, logs, iocs)
        logger.info("pipeline_investigation_complete", alert_id=alert.get("id"))

        # Stage 4: Response Decision
        available_playbooks = [
            "isolate_host", "block_ip", "quarantine_file",
            "disable_user", "segment_network", "snapshot_forensic",
            "sinkhole_dns", "revoke_credentials", "escalate_to_human",
        ]
        decision = await self.decide_response(investigation, alert, available_playbooks)
        logger.info(
            "pipeline_decision_complete",
            alert_id=alert.get("id"),
            decision=decision.decision_type,
        )

        duration = (datetime.now(timezone.utc) - start_time).total_seconds()

        return {
            "alert_id": alert.get("id"),
            "stage": "completed",
            "duration_seconds": duration,
            "triage": triage.model_dump(),
            "enrichment": enrichment.model_dump() if enrichment else None,
            "investigation": investigation.model_dump(),
            "decision": decision.model_dump(),
        }

    def _parse_result(self, result: Any, model_class):
        """Parse agent output into structured Pydantic model."""
        if isinstance(result, model_class):
            return result
        if isinstance(result, str):
            try:
                data = json.loads(result)
                return model_class(**data)
            except (json.JSONDecodeError, Exception) as e:
                logger.error("crew_output_parse_error", error=str(e), raw=result[:500])
                # Create default with error info
                return model_class(
                    **{k: "parse_error" if v == "" else v for k, v in model_class.__fields__.items()}
                )
        if isinstance(result, dict):
            return model_class(**result)
        return result


# Global CrewAI instance
crew_ai = CyberShieldCrew()


def get_crew() -> CyberShieldCrew:
    return crew_ai
