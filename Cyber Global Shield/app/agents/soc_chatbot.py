"""
Cyber Global Shield — SOC Chatbot Assistant
Assistant IA pour les analystes SOC. Répond aux questions sur les logs,
alertes, anomalies, et guide les actions de réponse aux incidents.
"""

import json
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class ChatMessage(BaseModel):
    """A chat message in the conversation."""
    role: str  # "user", "assistant", "system"
    content: str
    timestamp: datetime = datetime.utcnow()
    metadata: Dict[str, Any] = {}


class ChatSession(BaseModel):
    """A chat session with context."""
    id: str
    org_id: str
    user_id: str
    messages: List[ChatMessage] = []
    context: Dict[str, Any] = {}
    created_at: datetime = datetime.utcnow()
    updated_at: datetime = datetime.utcnow()


class SOCQueryResult(BaseModel):
    """Result of a SOC data query."""
    query_type: str  # "logs", "alerts", "anomalies", "soar", "stats"
    data: List[Dict[str, Any]]
    summary: str
    sql_query: Optional[str] = None


class SOCAssistant:
    """
    SOC AI Assistant that can query data and provide analysis.
    Uses intent classification to route queries to the right data source.
    """

    def __init__(self, clickhouse_client=None, ml_model=None):
        self._client = clickhouse_client
        self._ml_model = ml_model
        self._sessions: Dict[str, ChatSession] = {}

        # Intent patterns
        self._intents = {
            "show_logs": ["show logs", "list logs", "recent logs", "view logs", "logs from"],
            "show_alerts": ["show alerts", "list alerts", "recent alerts", "view alerts", "alerts from"],
            "show_anomalies": ["show anomalies", "list anomalies", "recent anomalies", "anomalies detected"],
            "search_ip": ["search ip", "find ip", "lookup ip", "ip address", "what about"],
            "search_port": ["search port", "port scan", "connections on port"],
            "block_ip": ["block ip", "block this ip", "block address"],
            "investigate": ["investigate", "analyze", "tell me about", "what happened"],
            "stats": ["stats", "statistics", "summary", "overview", "dashboard"],
            "help": ["help", "what can you do", "commands", "capabilities"],
            "status": ["status", "health", "system status", "is everything ok"],
        }

    def create_session(self, org_id: str, user_id: str) -> str:
        """Create a new chat session."""
        session_id = f"chat_{org_id}_{user_id}_{datetime.utcnow().timestamp()}"
        self._sessions[session_id] = ChatSession(
            id=session_id,
            org_id=org_id,
            user_id=user_id,
        )
        return session_id

    def get_session(self, session_id: str) -> Optional[ChatSession]:
        """Get a chat session."""
        return self._sessions.get(session_id)

    def _classify_intent(self, message: str) -> str:
        """Classify the intent of a user message."""
        message_lower = message.lower()

        for intent, patterns in self._intents.items():
            for pattern in patterns:
                if pattern in message_lower:
                    return intent

        return "unknown"

    def _extract_entities(self, message: str) -> Dict[str, Any]:
        """Extract entities from a message (IPs, ports, dates, etc.)."""
        import re
        entities = {}

        # Extract IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, message)
        if ips:
            entities["ips"] = ips

        # Extract ports
        port_pattern = r'\bport\s+(\d+)\b'
        ports = re.findall(port_pattern, message.lower())
        if ports:
            entities["ports"] = [int(p) for p in ports]

        # Extract time ranges
        time_patterns = {
            "last_hour": r'\b(last\s+hour|past\s+hour|1h)\b',
            "last_24h": r'\b(last\s+24\s*hours|past\s+day|today|24h)\b',
            "last_7d": r'\b(last\s+7\s*days|past\s+week|this\s+week|7d)\b',
            "last_30d": r'\b(last\s+30\s*days|past\s+month|this\s+month|30d)\b',
        }

        for time_range, pattern in time_patterns.items():
            if re.search(pattern, message.lower()):
                entities["time_range"] = time_range
                break

        # Extract severity
        severity_patterns = {
            "critical": r'\b(critical|emergency|severe)\b',
            "high": r'\b(high|major)\b',
            "medium": r'\b(medium|moderate|warning)\b',
            "low": r'\b(low|minor|info)\b',
        }

        for severity, pattern in severity_patterns.items():
            if re.search(pattern, message.lower()):
                entities["severity"] = severity
                break

        return entities

    def _get_time_filter(self, time_range: Optional[str]) -> str:
        """Get SQL time filter from time range."""
        if time_range == "last_hour":
            return "timestamp > NOW() - INTERVAL 1 HOUR"
        elif time_range == "last_24h":
            return "timestamp > NOW() - INTERVAL 24 HOUR"
        elif time_range == "last_7d":
            return "timestamp > NOW() - INTERVAL 7 DAY"
        elif time_range == "last_30d":
            return "timestamp > NOW() - INTERVAL 30 DAY"
        return ""

    async def process_message(
        self,
        session_id: str,
        message: str,
    ) -> str:
        """Process a user message and return a response."""
        session = self._sessions.get(session_id)
        if not session:
            return "Session not found. Please start a new conversation."

        # Add user message to history
        session.messages.append(ChatMessage(role="user", content=message))

        # Classify intent
        intent = self._classify_intent(message)
        entities = self._extract_entities(message)

        # Process based on intent
        try:
            if intent == "show_logs":
                response = await self._handle_show_logs(session, entities)
            elif intent == "show_alerts":
                response = await self._handle_show_alerts(session, entities)
            elif intent == "show_anomalies":
                response = await self._handle_show_anomalies(session, entities)
            elif intent == "search_ip":
                response = await self._handle_search_ip(session, entities)
            elif intent == "search_port":
                response = await self._handle_search_port(session, entities)
            elif intent == "block_ip":
                response = await self._handle_block_ip(session, entities)
            elif intent == "investigate":
                response = await self._handle_investigate(session, entities)
            elif intent == "stats":
                response = await self._handle_stats(session, entities)
            elif intent == "help":
                response = self._handle_help()
            elif intent == "status":
                response = await self._handle_status()
            else:
                response = self._handle_unknown(message)
        except Exception as e:
            logger.error(f"Chatbot error: {e}")
            response = f"Désolé, une erreur s'est produite: {str(e)}"

        # Add assistant response to history
        session.messages.append(ChatMessage(role="assistant", content=response))
        session.updated_at = datetime.utcnow()

        return response

    async def _handle_show_logs(
        self, session: ChatSession, entities: Dict[str, Any],
    ) -> str:
        """Handle 'show logs' intent."""
        if not self._client:
            return "Base de données non connectée."

        time_filter = self._get_time_filter(entities.get("time_range"))
        where_clause = f"WHERE org_id = '{session.org_id}'"
        if time_filter:
            where_clause += f" AND {time_filter}"

        query = f"""
            SELECT timestamp, src_ip, dst_ip, event_type, severity, action
            FROM logs
            {where_clause}
            ORDER BY timestamp DESC
            LIMIT 10
        """

        try:
            results = self._client.execute(query)
            if not results:
                return "Aucun log trouvé pour cette période."

            response = "📋 **Derniers logs:**\n\n"
            for row in results:
                response += (
                    f"• `{row[0]}` | {row[1]} → {row[2]} | "
                    f"{row[3]} | [{row[4]}] | {row[5]}\n"
                )
            return response
        except Exception as e:
            return f"Erreur lors de la récupération des logs: {e}"

    async def _handle_show_alerts(
        self, session: ChatSession, entities: Dict[str, Any],
    ) -> str:
        """Handle 'show alerts' intent."""
        if not self._client:
            return "Base de données non connectée."

        time_filter = self._get_time_filter(entities.get("time_range", "last_24h"))
        severity_filter = ""
        if entities.get("severity"):
            severity_filter = f"AND severity = '{entities['severity']}'"

        query = f"""
            SELECT created_at, type, severity, source, status, description
            FROM alerts
            WHERE org_id = '{session.org_id}'
            AND {time_filter}
            {severity_filter}
            ORDER BY created_at DESC
            LIMIT 10
        """

        try:
            results = self._client.execute(query)
            if not results:
                return "Aucune alerte trouvée."

            response = "🚨 **Alertes récentes:**\n\n"
            for row in results:
                severity_icon = {
                    "critical": "🔴", "high": "🟠",
                    "medium": "🟡", "low": "🟢",
                }.get(row[2], "⚪")
                response += (
                    f"{severity_icon} `{row[0]}` | **{row[1]}** | "
                    f"[{row[2]}] | {row[3]} | {row[4]}\n"
                    f"   {row[5][:100]}\n"
                )
            return response
        except Exception as e:
            return f"Erreur lors de la récupération des alertes: {e}"

    async def _handle_show_anomalies(
        self, session: ChatSession, entities: Dict[str, Any],
    ) -> str:
        """Handle 'show anomalies' intent."""
        if not self._client:
            return "Base de données non connectée."

        time_filter = self._get_time_filter(entities.get("time_range", "last_24h"))

        query = f"""
            SELECT timestamp, score, threshold, prediction, model_version
            FROM anomalies
            WHERE org_id = '{session.org_id}'
            AND {time_filter}
            ORDER BY score DESC
            LIMIT 10
        """

        try:
            results = self._client.execute(query)
            if not results:
                return "Aucune anomalie détectée récemment. ✅"

            response = "🧠 **Anomalies détectées:**\n\n"
            for row in results:
                is_anomaly = "🔴 ANOMALIE" if row[3] == 1 else "✅ Normal"
                response += (
                    f"• `{row[0]}` | Score: `{row[1]:.4f}` "
                    f"(seuil: {row[2]:.4f}) | {is_anomaly}\n"
                )
            return response
        except Exception as e:
            return f"Erreur lors de la récupération des anomalies: {e}"

    async def _handle_search_ip(
        self, session: ChatSession, entities: Dict[str, Any],
    ) -> str:
        """Handle 'search IP' intent."""
        if not self._client:
            return "Base de données non connectée."

        ips = entities.get("ips", [])
        if not ips:
            return "Veuillez spécifier une adresse IP à rechercher."

        results_text = []
        for ip in ips:
            query = f"""
                SELECT timestamp, src_ip, dst_ip, event_type, action, severity
                FROM logs
                WHERE org_id = '{session.org_id}'
                AND (src_ip = '{ip}' OR dst_ip = '{ip}')
                ORDER BY timestamp DESC
                LIMIT 5
            """

            try:
                results = self._client.execute(query)
                if results:
                    text = f"🔍 **Activité pour {ip}:**\n"
                    for row in results:
                        text += (
                            f"• `{row[0]}` | {row[1]} → {row[2]} | "
                            f"{row[3]} | {row[4]} | [{row[5]}]\n"
                        )
                    results_text.append(text)
                else:
                    results_text.append(f"✅ Aucune activité trouvée pour {ip}.")

            except Exception as e:
                results_text.append(f"Erreur pour {ip}: {e}")

        return "\n".join(results_text)

    async def _handle_search_port(
        self, session: ChatSession, entities: Dict[str, Any],
    ) -> str:
        """Handle 'search port' intent."""
        if not self._client:
            return "Base de données non connectée."

        ports = entities.get("ports", [])
        if not ports:
            return "Veuillez spécifier un port à rechercher."

        results_text = []
        for port in ports:
            query = f"""
                SELECT timestamp, src_ip, dst_ip, event_type, action
                FROM logs
                WHERE org_id = '{session.org_id}'
                AND port = {port}
                ORDER BY timestamp DESC
                LIMIT 5
            """

            try:
                results = self._client.execute(query)
                if results:
                    text = f"🔍 **Activité sur le port {port}:**\n"
                    for row in results:
                        text += (
                            f"• `{row[0]}` | {row[1]} → {row[2]} | "
                            f"{row[3]} | {row[4]}\n"
                        )
                    results_text.append(text)
                else:
                    results_text.append(f"✅ Aucune activité sur le port {port}.")

            except Exception as e:
                results_text.append(f"Erreur: {e}")

        return "\n".join(results_text)

    async def _handle_block_ip(
        self, session: ChatSession, entities: Dict[str, Any],
    ) -> str:
        """Handle 'block IP' intent."""
        ips = entities.get("ips", [])
        if not ips:
            return "Veuillez spécifier l'IP à bloquer."

        # In production, this would call the SOAR engine
        response = "🛡️ **Action de blocage:**\n\n"
        for ip in ips:
            response += (
                f"• IP {ip} → ⏳ Action de blocage soumise\n"
                f"  Le playbook `block_malicious_ip` va être exécuté.\n"
            )

        response += (
            "\n⚠️ **Note:** En production, cette action déclencherait:\n"
            "1. Blocage au niveau du firewall\n"
            "2. Mise à jour des règles Suricata\n"
            "3. Notification à l'équipe SOC\n"
            "4. Création d'un ticket incident\n"
        )

        return response

    async def _handle_investigate(
        self, session: ChatSession, entities: Dict[str, Any],
    ) -> str:
        """Handle 'investigate' intent - comprehensive analysis."""
        if not self._client:
            return "Base de données non connectée."

        ips = entities.get("ips", [])
        time_filter = self._get_time_filter(entities.get("time_range", "last_24h"))

        if not ips:
            return "Veuillez spécifier une IP ou un indicateur à investiguer."

        response = "🔬 **Analyse d'investigation:**\n\n"

        for ip in ips:
            response += f"**Cible: {ip}**\n"

            # Get connection count
            try:
                count_query = f"""
                    SELECT COUNT(*), COUNT(DISTINCT dst_ip), COUNT(DISTINCT port)
                    FROM logs
                    WHERE org_id = '{session.org_id}'
                    AND src_ip = '{ip}'
                    AND {time_filter}
                """
                count_result = self._client.execute(count_query)
                if count_result:
                    row = count_result[0]
                    response += (
                        f"   📊 Connexions: {row[0]} | "
                        f"Destinations uniques: {row[1]} | "
                        f"Ports: {row[2]}\n"
                    )
            except Exception:
                pass

            # Get blocked count
            try:
                blocked_query = f"""
                    SELECT COUNT(*)
                    FROM logs
                    WHERE org_id = '{session.org_id}'
                    AND src_ip = '{ip}'
                    AND action = 'block'
                    AND {time_filter}
                """
                blocked_result = self._client.execute(blocked_query)
                if blocked_result and blocked_result[0][0] > 0:
                    response += f"   🚫 Tentatives bloquées: {blocked_result[0][0]}\n"
            except Exception:
                pass

            # Check threat intel
            try:
                threat_query = f"""
                    SELECT is_malicious, threat_score, source
                    FROM threat_intel
                    WHERE org_id = '{session.org_id}'
                    AND ip = '{ip}'
                    LIMIT 1
                """
                threat_result = self._client.execute(threat_query)
                if threat_result:
                    row = threat_result[0]
                    if row[0]:
                        response += (
                            f"   ⚠️ **IP malveillante** | "
                            f"Score: {row[1]} | Source: {row[2]}\n"
                        )
            except Exception:
                pass

            response += "\n"

        return response

    async def _handle_stats(
        self, session: ChatSession, entities: Dict[str, Any],
    ) -> str:
        """Handle 'stats' intent."""
        if not self._client:
            return "Base de données non connectée."

        time_filter = self._get_time_filter(entities.get("time_range", "last_24h"))

        try:
            # Total logs
            logs_query = f"""
                SELECT COUNT(*)
                FROM logs
                WHERE org_id = '{session.org_id}'
                AND {time_filter}
            """
            logs_result = self._client.execute(logs_query)
            total_logs = logs_result[0][0] if logs_result else 0

            # Total alerts
            alerts_query = f"""
                SELECT COUNT(*), COUNTIf(severity = 'critical')
                FROM alerts
                WHERE org_id = '{session.org_id}'
                AND {time_filter}
            """
            alerts_result = self._client.execute(alerts_query)
            total_alerts = alerts_result[0][0] if alerts_result else 0
            critical_alerts = alerts_result[0][1] if alerts_result else 0

            # Total anomalies
            anomalies_query = f"""
                SELECT COUNT(*), COUNTIf(prediction = 1)
                FROM anomalies
                WHERE org_id = '{session.org_id}'
                AND {time_filter}
            """
            anomalies_result = self._client.execute(anomalies_query)
            total_anomalies = anomalies_result[0][0] if anomalies_result else 0
            detected = anomalies_result[0][1] if anomalies_result else 0

            # Unique IPs
            ips_query = f"""
                SELECT COUNT(DISTINCT src_ip)
                FROM logs
                WHERE org_id = '{session.org_id}'
                AND {time_filter}
            """
            ips_result = self._client.execute(ips_query)
            unique_ips = ips_result[0][0] if ips_result else 0

            response = (
                "📊 **Statistiques SOC:**\n\n"
                f"   📝 Logs traités: **{total_logs:,}**\n"
                f"   🚨 Alertes: **{total_alerts}** (🔴 {critical_alerts} critiques)\n"
                f"   🧠 Anomalies: **{total_anomalies}** (⚠️ {detected} détectées)\n"
                f"   🌐 IPs uniques: **{unique_ips:,}**\n"
            )

            if detected > 0:
                response += (
                    "\n⚠️ **Recommandation:** Des anomalies ont été détectées. "
                    "Je recommande une investigation approfondie."
                )

            return response

        except Exception as e:
            return f"Erreur lors de la récupération des statistiques: {e}"

    def _handle_help(self) -> str:
        """Handle 'help' intent."""
        return (
            "🤖 **Assistant SOC - Commandes disponibles:**\n\n"
            "🔍 **Recherche**\n"
            "• `show logs` - Affiche les derniers logs\n"
            "• `show alerts` - Affiche les alertes récentes\n"
            "• `show anomalies` - Affiche les anomalies ML\n"
            "• `search ip 192.168.1.1` - Cherche une IP\n"
            "• `search port 22` - Cherche un port\n\n"
            "🛡️ **Actions**\n"
            "• `block ip 192.168.1.1` - Bloque une IP\n"
            "• `investigate 192.168.1.1` - Analyse complète\n\n"
            "📊 **Statistiques**\n"
            "• `stats` - Vue d'ensemble\n"
            "• `status` - État du système\n\n"
            "⏰ **Filtres temporels**\n"
            "Ajoutez: `last hour`, `today`, `this week`, `this month`\n\n"
            "💡 **Exemples:**\n"
            "• \"show alerts from last hour\"\n"
            "• \"investigate 10.0.0.5\"\n"
            "• \"stats for this week\"\n"
        )

    async def _handle_status(self) -> str:
        """Handle 'status' intent."""
        status = "✅ **Système opérationnel**\n\n"

        if self._client:
            try:
                self._client.execute("SELECT 1")
                status += "   ✅ Base de données (ClickHouse): Connectée\n"
            except Exception:
                status += "   ❌ Base de données (ClickHouse): Déconnectée\n"
        else:
            status += "   ⚠️ Base de données (ClickHouse): Non configurée\n"

        if self._ml_model:
            status += "   ✅ Modèle ML: Chargé\n"
        else:
            status += "   ⚠️ Modèle ML: Non chargé\n"

        return status

    def _handle_unknown(self, message: str) -> str:
        """Handle unknown intent."""
        return (
            f"Je n'ai pas compris votre demande: \"{message}\"\n\n"
            "Tapez `help` pour voir la liste des commandes disponibles.\n\n"
            "💡 **Suggestions:**\n"
            "• \"show alerts\" - Voir les alertes\n"
            "• \"search ip 192.168.1.1\" - Chercher une IP\n"
            "• \"stats\" - Voir les statistiques\n"
        )


# Global SOC assistant instance
soc_assistant = SOCAssistant()
