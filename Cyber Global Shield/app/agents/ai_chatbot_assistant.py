"""
Cyber Global Shield — AI Chatbot Security Assistant
Assistant IA conversationnel pour la sécurité.
Répond aux questions, analyse les incidents, et guide les analystes.
"""

import json
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ChatMessage:
    """A chat message."""
    message_id: str
    role: str  # user, assistant, system
    content: str
    timestamp: datetime
    context: Optional[Dict] = None


class AIChatbotSecurityAssistant:
    """
    Assistant IA conversationnel de sécurité.
    
    Capacités:
    - Répondre aux questions de sécurité
    - Analyser des incidents
    - Expliquer des vulnérabilités
    - Guider la remédiation
    - Rechercher des IoCs
    - Expliquer des concepts MITRE ATT&CK
    - Générer des rapports
    """

    def __init__(self):
        self._conversations: Dict[str, List[ChatMessage]] = {}
        self._knowledge_base = self._load_knowledge_base()
        self._responses = self._load_responses()

    def _load_knowledge_base(self) -> Dict[str, str]:
        """Load security knowledge base."""
        return {
            "ransomware": (
                "Ransomware is a type of malware that encrypts files and demands payment. "
                "Key indicators: file extensions changed, ransom notes, encrypted files. "
                "Response: isolate affected systems, identify variant, check for decryptors, "
                "restore from backups, report to authorities."
            ),
            "phishing": (
                "Phishing attacks use social engineering to steal credentials. "
                "Indicators: suspicious sender, urgent language, fake URLs, poor grammar. "
                "Response: report to security team, scan for similar emails, "
                "check if credentials were entered, reset passwords if needed."
            ),
            "ddos": (
                "DDoS attacks overwhelm systems with traffic. "
                "Types: volumetric, protocol, application layer. "
                "Mitigation: enable DDoS protection, rate limiting, WAF, "
                "scale resources, use CDN, implement blackhole routing."
            ),
            "data_breach": (
                "A data breach involves unauthorized access to sensitive data. "
                "Response: identify scope, contain the breach, notify affected parties, "
                "preserve evidence, conduct forensic analysis, implement remediation."
            ),
            "zero_day": (
                "A zero-day exploit targets unknown vulnerabilities. "
                "Protection: keep systems updated, use behavioral detection, "
                "implement virtual patching, monitor for anomalous behavior, "
                "use sandboxing for suspicious files."
            ),
            "mitre_attack": (
                "MITRE ATT&CK is a knowledge base of adversary tactics and techniques. "
                "It covers 14 tactics: Reconnaissance, Resource Development, "
                "Initial Access, Execution, Persistence, Privilege Escalation, "
                "Defense Evasion, Credential Access, Discovery, Lateral Movement, "
                "Collection, Command and Control, Exfiltration, Impact."
            ),
            "incident_response": (
                "Incident Response follows NIST framework: "
                "1. Preparation - build IR plan and team\n"
                "2. Detection & Analysis - identify and validate incidents\n"
                "3. Containment, Eradication & Recovery - stop and remove threats\n"
                "4. Post-Incident Activity - lessons learned and improvements"
            ),
            "compliance": (
                "Major compliance frameworks:\n"
                "- GDPR: EU data protection\n"
                "- PCI-DSS: Payment card security\n"
                "- SOC 2: Service organization controls\n"
                "- HIPAA: Healthcare data privacy\n"
                "- ISO 27001: Information security management"
            ),
        }

    def _load_responses(self) -> Dict[str, str]:
        """Load predefined responses."""
        return {
            "greeting": (
                "Hello! I'm your AI Security Assistant. I can help you with:\n"
                "🔍 Threat analysis and investigation\n"
                "📋 Incident response guidance\n"
                "🛡️ Security best practices\n"
                "📊 Compliance and regulations\n"
                "🔐 Vulnerability explanations\n"
                "What security topic can I help you with?"
            ),
            "help": (
                "I can assist with:\n"
                "- Explain security concepts (ransomware, phishing, etc.)\n"
                "- Guide incident response procedures\n"
                "- Analyze security alerts\n"
                "- Provide remediation steps\n"
                "- Explain MITRE ATT&CK techniques\n"
                "- Answer compliance questions\n"
                "Just ask me anything about cybersecurity!"
            ),
            "unknown": (
                "I'm not sure about that specific topic. I specialize in:\n"
                "cybersecurity threats, incident response, compliance frameworks, "
                "vulnerability analysis, and security best practices. "
                "Could you rephrase your question or ask about a security topic?"
            ),
        }

    def process_message(self, conversation_id: str, message: str) -> ChatMessage:
        """Process a user message and generate response."""
        # Create user message
        user_msg = ChatMessage(
            message_id=f"MSG-{int(datetime.utcnow().timestamp())}",
            role="user",
            content=message,
            timestamp=datetime.utcnow(),
        )

        # Initialize conversation if needed
        if conversation_id not in self._conversations:
            self._conversations[conversation_id] = []
            # Add greeting
            greeting = ChatMessage(
                message_id=f"MSG-{int(datetime.utcnow().timestamp())}-sys",
                role="assistant",
                content=self._responses["greeting"],
                timestamp=datetime.utcnow(),
            )
            self._conversations[conversation_id].append(greeting)

        self._conversations[conversation_id].append(user_msg)

        # Generate response
        response_content = self._generate_response(message, conversation_id)
        
        assistant_msg = ChatMessage(
            message_id=f"MSG-{int(datetime.utcnow().timestamp())}-resp",
            role="assistant",
            content=response_content,
            timestamp=datetime.utcnow(),
            context={"conversation_id": conversation_id},
        )

        self._conversations[conversation_id].append(assistant_msg)
        
        logger.info(f"💬 AI Assistant: processed message in conversation {conversation_id}")
        return assistant_msg

    def _generate_response(self, message: str, conversation_id: str) -> str:
        """Generate AI response based on message."""
        message_lower = message.lower()

        # Check for greetings
        if any(word in message_lower for word in ["hello", "hi", "hey", "bonjour", "salut"]):
            return self._responses["greeting"]

        # Check for help
        if any(word in message_lower for word in ["help", "what can you", "capabilities"]):
            return self._responses["help"]

        # Check knowledge base
        for topic, response in self._knowledge_base.items():
            if topic in message_lower:
                return self._generate_detailed_response(topic, response, message)

        # Check for specific queries
        if "incident" in message_lower or "attack" in message_lower:
            return self._handle_incident_query(message)
        
        if "vulnerability" in message_lower or "cve" in message_lower:
            return self._handle_vulnerability_query(message)
        
        if "report" in message_lower or "summary" in message_lower:
            return self._handle_report_query(conversation_id)

        # Default response
        return self._responses["unknown"]

    def _generate_detailed_response(self, topic: str, base_response: str, message: str) -> str:
        """Generate a detailed response with context."""
        response = f"📚 **{topic.upper()}**\n\n{base_response}\n\n"
        
        # Add follow-up suggestions
        response += "💡 **Follow-up questions you can ask:**\n"
        suggestions = {
            "ransomware": "- How do I detect ransomware?\n- What are ransomware indicators?\n- How to prevent ransomware?",
            "phishing": "- How to report phishing?\n- What are phishing red flags?\n- How to train users?",
            "ddos": "- How to mitigate DDoS?\n- What DDoS protection services exist?\n- How to detect DDoS early?",
            "data_breach": "- What are breach notification requirements?\n- How to conduct forensic analysis?\n- How to prevent breaches?",
            "zero_day": "- How to protect against zero-days?\n- What is virtual patching?\n- How to detect zero-day exploits?",
            "mitre_attack": "- What are the most common techniques?\n- How to map detections to MITRE?\n- How to use MITRE for threat hunting?",
            "incident_response": "- What is the first step in IR?\n- How to build an IR team?\n- What tools are needed for IR?",
            "compliance": "- What are GDPR requirements?\n- How to achieve PCI compliance?\n- What is SOC 2 audit?",
        }
        
        response += suggestions.get(topic, "")
        return response

    def _handle_incident_query(self, message: str) -> str:
        """Handle incident-related queries."""
        return (
            "🔴 **Incident Analysis**\n\n"
            "To analyze a security incident, I need:\n"
            "1. **Type of incident** (ransomware, phishing, data breach, etc.)\n"
            "2. **Timeline** - When did it start?\n"
            "3. **Scope** - What systems are affected?\n"
            "4. **Indicators** - What evidence do you have?\n\n"
            "**Immediate steps:**\n"
            "• Isolate affected systems from the network\n"
            "• Preserve logs and evidence\n"
            "• Activate incident response team\n"
            "• Document all actions taken\n"
            "• Notify relevant stakeholders\n\n"
            "Would you like guidance on a specific incident type?"
        )

    def _handle_vulnerability_query(self, message: str) -> str:
        """Handle vulnerability-related queries."""
        return (
            "🔍 **Vulnerability Information**\n\n"
            "To analyze a vulnerability, please provide:\n"
            "• CVE ID (if known)\n"
            "• Affected software/version\n"
            "• CVSS score (if available)\n\n"
            "**Common vulnerability types:**\n"
            "• SQL Injection (CWE-89)\n"
            "• XSS (CWE-79)\n"
            "• Buffer Overflow (CWE-120)\n"
            "• Insecure Deserialization (CWE-502)\n"
            "• Broken Authentication (CWE-287)\n\n"
            "**Remediation priority:**\n"
            "• Critical (CVSS 9-10): Patch within 24h\n"
            "• High (CVSS 7-8.9): Patch within 7 days\n"
            "• Medium (CVSS 4-6.9): Patch within 30 days\n"
            "• Low (CVSS 0-3.9): Patch within 90 days"
        )

    def _handle_report_query(self, conversation_id: str) -> str:
        """Generate a report based on conversation history."""
        conversation = self._conversations.get(conversation_id, [])
        
        if len(conversation) < 2:
            return "I need more context to generate a report. Please ask specific security questions first."

        return (
            "📊 **Security Conversation Summary**\n\n"
            f"• Messages exchanged: {len(conversation)}\n"
            f"• Topics discussed: Multiple security topics\n\n"
            "**Key points covered:**\n"
            "• Security threats and mitigation strategies\n"
            "• Incident response procedures\n"
            "• Security best practices\n\n"
            "**Recommendations:**\n"
            "1. Implement defense-in-depth strategy\n"
            "2. Regular security awareness training\n"
            "3. Maintain incident response plan\n"
            "4. Conduct regular vulnerability assessments\n"
            "5. Monitor for emerging threats\n\n"
            "Would you like a detailed report on a specific topic?"
        )

    def get_conversation_history(self, conversation_id: str) -> List[ChatMessage]:
        """Get conversation history."""
        return self._conversations.get(conversation_id, [])

    def get_stats(self) -> Dict[str, Any]:
        """Get chatbot statistics."""
        return {
            "total_conversations": len(self._conversations),
            "total_messages": sum(len(msgs) for msgs in self._conversations.values()),
            "avg_messages_per_conversation": (
                sum(len(msgs) for msgs in self._conversations.values()) / len(self._conversations)
                if self._conversations else 0
            ),
            "status": "READY",
        }


ai_chatbot_assistant = AIChatbotSecurityAssistant()
