# Cyber Global Shield — API Reference

> **Version**: 2.0.0  
> **Base URL**: `http://localhost:8000`  
> **Auth**: JWT Bearer Token (`/api/v1/auth/login`)  
> **Format**: JSON  
> **Interactive Docs**: Swagger UI at `/docs` | ReDoc at `/redoc`

---

## 📋 Table des Matières

1. [Authentication](#-authentication)
2. [Dashboard & Analytics](#-dashboard--analytics)
3. [Alert Management](#-alert-management)
4. [SOAR — Playbook Execution](#-soar--playbook-execution)
5. [ML — Anomaly Detection](#-ml--anomaly-detection)
6. [Agents IA — Pipeline Autonome](#-agents-ia--pipeline-autonome)
7. [Federated Learning](#-federated-learning)
8. [Ingestion & Logs](#-ingestion--logs)
9. [Security & Encryption](#-security--encryption)
10. [Health & Monitoring](#-health--monitoring)
11. [Ultra ML Modules (Niveaux 1-12)](#-ultra-ml-modules-niveaux-1-12)

---

## 🔐 Authentication

### POST `/api/v1/auth/login`
Authentifie un utilisateur et retourne un token JWT.

**Request:**
```http
POST /api/v1/auth/login
Content-Type: application/x-www-form-urlencoded

username=admin&password=cybershield2024
```

**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 3600,
  "user": {
    "username": "admin",
    "role": "admin",
    "org_id": "default"
  }
}
```

**Response (401):**
```json
{
  "detail": "Incorrect username or password"
}
```

### POST `/api/v1/auth/refresh`
Rafraîchit un token JWT existant.

**Headers:** `Authorization: Bearer <token>`

**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

---

## 📊 Dashboard & Analytics

### GET `/api/v1/dashboard/overview`
Récupère les métriques principales du dashboard SOC.

**Query Parameters:**
| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `org_id` | string | `default` | Organisation |
| `hours` | int | `24` | Période en heures |

**Response (200):**
```json
{
  "traffic_stats": {
    "volume": [
      {"timestamp": "2026-05-04T10:00:00Z", "event_count": 1250},
      {"timestamp": "2026-05-04T11:00:00Z", "event_count": 1420}
    ],
    "anomalies": [
      {"timestamp": "2026-05-04T10:00:00Z", "anomaly_count": 5}
    ]
  },
  "critical_alerts_24h": 3,
  "latest_alerts": [
    {
      "id": "alert-001",
      "timestamp": "2026-05-04T10:45:00Z",
      "event_type": "scan",
      "severity": "high",
      "src_ip": "45.33.32.156",
      "dst_ip": "10.0.1.50",
      "protocol": "tcp"
    }
  ],
  "sources": ["zeek", "suricata"],
  "total_logs_24h": 28470
}
```

### GET `/api/v1/dashboard/alerts`
Récupère la liste des alertes avec filtrage.

**Query Parameters:**
| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `org_id` | string | `default` | Organisation |
| `hours` | int | `24` | Période |
| `severity` | string | — | Filtre sévérité |
| `event_type` | string | — | Filtre type d'événement |
| `limit` | int | `50` | Nombre max de résultats |
| `offset` | int | `0` | Pagination |

**Response (200):**
```json
{
  "alerts": [
    {
      "id": "alert-001",
      "org_id": "default",
      "source": "zeek",
      "event_type": "scan",
      "severity": "high",
      "src_ip": "45.33.32.156",
      "dst_ip": "10.0.1.50",
      "src_port": 54321,
      "dst_port": 445,
      "protocol": "tcp",
      "timestamp": "2026-05-04T10:45:00Z",
      "tags": ["scan", "port_445"],
      "anomaly_score": 0.87,
      "is_anomaly": true
    }
  ],
  "total": 150,
  "page": 1,
  "page_size": 50
}
```

### GET `/api/v1/dashboard/stats`
Statistiques agrégées.

**Response (200):**
```json
{
  "total_logs": 28470,
  "total_alerts": 150,
  "critical_alerts": 3,
  "high_alerts": 12,
  "medium_alerts": 25,
  "low_alerts": 110,
  "anomalies_detected": 47,
  "playbooks_executed": 2,
  "avg_response_time_ms": 245,
  "active_sources": 2,
  "top_attack_types": [
    {"type": "scan", "count": 80},
    {"type": "brute_force", "count": 35},
    {"type": "c2_communication", "count": 20}
  ],
  "top_source_ips": [
    {"ip": "45.33.32.156", "count": 45},
    {"ip": "91.240.118.30", "count": 30}
  ]
}
```

---

## 🚨 Alert Management

### POST `/api/v1/alerts/ingest`
Ingère une alerte manuellement.

**Request:**
```json
{
  "org_id": "default",
  "source": "zeek",
  "event_type": "scan",
  "severity": "high",
  "src_ip": "45.33.32.156",
  "dst_ip": "10.0.1.50",
  "dst_port": 445,
  "protocol": "tcp",
  "raw_payload": {}
}
```

**Response (201):**
```json
{
  "id": "alert-abc123",
  "status": "ingested",
  "enriched": true,
  "anomaly_score": 0.87
}
```

### GET `/api/v1/alerts/{alert_id}`
Détails d'une alerte spécifique.

**Response (200):**
```json
{
  "id": "alert-abc123",
  "org_id": "default",
  "source": "zeek",
  "event_type": "scan",
  "severity": "high",
  "src_ip": "45.33.32.156",
  "dst_ip": "10.0.1.50",
  "timestamp": "2026-05-04T10:45:00Z",
  "anomaly_score": 0.87,
  "is_anomaly": true,
  "mitre_mapping": {
    "tactic": "TA0043",
    "technique": "T1595"
  },
  "threat_intel": {
    "threat_actor": "APT29",
    "confidence": 0.9,
    "tags": ["malicious", "c2"]
  },
  "soar_execution": {
    "playbook": "brute_force_response",
    "status": "completed",
    "execution_id": "exec-001"
  }
}
```

---

## ⚡ SOAR — Playbook Execution

### GET `/api/v1/soar/playbooks`
Liste tous les playbooks disponibles.

**Response (200):**
```json
[
  {
    "name": "ransomware_response",
    "description": "Réponse automatique aux activités ransomware",
    "actions_count": 8,
    "requires_approval": false,
    "on_cooldown": false,
    "cooldown_seconds": 60,
    "last_executed": null
  },
  {
    "name": "lateral_movement_response",
    "description": "Détection et blocage des mouvements latéraux",
    "actions_count": 6,
    "requires_approval": false,
    "on_cooldown": false,
    "cooldown_seconds": 120
  },
  {
    "name": "data_exfiltration_response",
    "description": "Réponse aux tentatives d'exfiltration de données",
    "actions_count": 5,
    "requires_approval": true,
    "on_cooldown": false,
    "cooldown_seconds": 300
  },
  {
    "name": "c2_communication_response",
    "description": "Blocage des communications C2",
    "actions_count": 5,
    "requires_approval": false,
    "on_cooldown": false,
    "cooldown_seconds": 60
  },
  {
    "name": "brute_force_response",
    "description": "Réponse aux attaques par force brute",
    "actions_count": 5,
    "requires_approval": false,
    "on_cooldown": false,
    "cooldown_seconds": 30
  }
]
```

### POST `/api/v1/soar/execute`
Exécute un playbook SOAR.

**Request:**
```json
{
  "playbook_name": "ransomware_response",
  "alert": {
    "id": "alert-001",
    "src_ip": "45.33.32.156",
    "dst_ip": "10.0.0.50",
    "user": "jdoe",
    "hostname": "host-42",
    "severity": "critical",
    "event_type": "ransomware_activity"
  },
  "iocs": {
    "ips": ["45.33.32.156", "91.240.118.30"],
    "domains": ["evil-c2.com"],
    "hashes": {
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  },
  "dry_run": false,
  "human_approved": true
}
```

**Response (200):**
```json
{
  "execution_id": "exec-abc123",
  "playbook_name": "ransomware_response",
  "status": "completed",
  "duration_ms": 1234.56,
  "dry_run": false,
  "actions": [
    {
      "name": "identify_patient_zero",
      "type": "internal",
      "status": "completed",
      "duration_ms": 45.2,
      "result": {"host": "host-42.internal"}
    },
    {
      "name": "firewall_block",
      "type": "firewall_block",
      "status": "completed",
      "duration_ms": 234.1,
      "result": {"blocked_ips": ["45.33.32.156", "91.240.118.30"]}
    },
    {
      "name": "edr_isolate",
      "type": "edr_action",
      "status": "completed",
      "duration_ms": 156.3,
      "result": {"isolated_hosts": ["host-42.internal"]}
    },
    {
      "name": "iam_disable_user",
      "type": "iam_action",
      "status": "completed",
      "duration_ms": 89.7,
      "result": {"disabled_users": ["jdoe"]}
    },
    {
      "name": "dns_sinkhole",
      "type": "dns_sinkhole",
      "status": "completed",
      "duration_ms": 67.8,
      "result": {"sinkholed_domains": ["evil-c2.com"]}
    },
    {
      "name": "network_segment",
      "type": "network_segment",
      "status": "completed",
      "duration_ms": 112.4,
      "result": {"segmented_network": "10.0.0.0/24"}
    },
    {
      "name": "forensic_snapshot",
      "type": "forensic_snapshot",
      "status": "completed",
      "duration_ms": 345.6,
      "result": {"snapshot_id": "snap-001"}
    },
    {
      "name": "create_ticket",
      "type": "ticket",
      "status": "completed",
      "duration_ms": 183.5,
      "result": {"ticket_id": "TKT-001"}
    }
  ],
  "audit_trail": [
    {"timestamp": "2026-05-04T10:45:00Z", "action": "playbook_started", "details": {}},
    {"timestamp": "2026-05-04T10:45:01Z", "action": "action_completed", "details": {"name": "identify_patient_zero"}},
    {"timestamp": "2026-05-04T10:45:05Z", "action": "playbook_completed", "details": {"status": "completed"}}
  ]
}
```

### GET `/api/v1/soar/executions/{execution_id}`
Récupère le résultat d'une exécution.

### GET `/api/v1/soar/audit`
Récupère la piste d'audit des exécutions.

**Query Parameters:**
| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `playbook` | string | — | Filtrer par playbook |
| `limit` | int | `50` | Nombre max |

### GET `/api/v1/soar/health`
Vérifie l'état de santé du moteur SOAR.

**Response (200):**
```json
{
  "status": "healthy",
  "playbooks_loaded": 5,
  "action_handlers": 8,
  "active_locks": 0,
  "uptime_seconds": 86400
}
```

---

## 🤖 ML — Anomaly Detection

### POST `/api/v1/ml/detect`
Détecte des anomalies dans des logs.

**Request:**
```json
{
  "logs": [
    {
      "src_ip": "45.33.32.156",
      "dst_ip": "10.0.0.50",
      "dst_port": 445,
      "protocol": "tcp",
      "bytes_sent": 1024,
      "bytes_received": 4096,
      "event_type": "connection"
    }
  ],
  "threshold": 0.95
}
```

**Response (200):**
```json
{
  "results": [
    {
      "is_anomaly": true,
      "anomaly_score": 0.97,
      "reconstruction_error": 0.034,
      "explanation": "Anomalie détectée: trafic sortant vers IP inconnue sur port 445 (SMB) avec volume de données anormal",
      "inference_time_ms": 12.3
    }
  ],
  "model_info": {
    "type": "TransformerAutoencoder",
    "input_dim": 128,
    "latent_dim": 64,
    "threshold": 0.95
  }
}
```

### POST `/api/v1/ml/train`
Lance l'entraînement du modèle.

**Request:**
```json
{
  "num_sequences": 10000,
  "seq_length": 64,
  "anomaly_probability": 0.1,
  "epochs": 50,
  "batch_size": 32,
  "learning_rate": 0.001
}
```

**Response (200):**
```json
{
  "status": "training_started",
  "job_id": "train-001",
  "config": {
    "num_sequences": 10000,
    "seq_length": 64,
    "epochs": 50
  },
  "estimated_duration_seconds": 120
}
```

### GET `/api/v1/ml/model/info`
Informations sur le modèle actuel.

**Response (200):**
```json
{
  "model_type": "TransformerAutoencoder",
  "input_dim": 128,
  "d_model": 256,
  "nhead": 8,
  "num_encoder_layers": 4,
  "num_decoder_layers": 2,
  "latent_dim": 64,
  "threshold": 0.95,
  "is_trained": true,
  "training_date": "2026-05-03T10:00:00Z",
  "training_samples": 50000,
  "validation_loss": 0.0023
}
```

### POST `/api/v1/ml/calibrate`
Calibre le seuil de détection.

**Request:**
```json
{
  "percentile": 95.0,
  "num_samples": 1000
}
```

**Response (200):**
```json
{
  "threshold": 0.92,
  "percentile": 95.0,
  "samples_used": 1000,
  "mean_reconstruction_error": 0.015,
  "std_reconstruction_error": 0.008
}
```

---

## 🧠 Agents IA — Pipeline Autonome

### POST `/api/v1/agents/pipeline`
Exécute le pipeline complet : Triage → Investigation → Réponse.

**Request:**
```json
{
  "alert": {
    "id": "alert-001",
    "alert_type": "ransomware_activity",
    "title": "Ransomware Detected on host-42",
    "source": "zeek",
    "src_ip": "45.33.32.156",
    "dst_ip": "10.0.1.50",
    "severity": "critical",
    "iocs": {
      "ips": ["45.33.32.156"],
      "domains": ["evil-c2.com"]
    }
  },
  "logs": [
    {
      "event_type": "ransomware_activity",
      "src_ip": "45.33.32.156",
      "dst_ip": "10.0.1.50",
      "severity": "critical"
    }
  ],
  "context": {
    "org_id": "default"
  }
}
```

**Response (200):**
```json
{
  "stage": "completed",
  "alert_id": "alert-001",
  "duration_seconds": 4.23,
  "triage": {
    "severity": "critical",
    "confidence": 0.95,
    "priority": 9,
    "is_false_positive": false,
    "requires_immediate_action": true,
    "reasoning": "Ransomware activity detected: SMB connection to known C2 infrastructure with file encryption indicators",
    "recommended_next_step": "Immediate host isolation and network segmentation required"
  },
  "investigation": {
    "root_cause": "Malware execution via phishing email",
    "attack_vector": "Email phishing with malicious attachment",
    "affected_assets": ["host-42.internal", "host-43.internal"],
    "mitre_tactic": "TA0001 - Initial Access",
    "mitre_technique": "T1566 - Phishing",
    "kill_chain_phase": "Exploitation",
    "iocs_found": {
      "ips": ["45.33.32.156", "91.240.118.30"],
      "domains": ["evil-c2.com"]
    },
    "lateral_movement_detected": true,
    "data_exfiltration_detected": false,
    "confidence": 0.9,
    "summary": "Malware successfully executed via phishing email, establishing C2 communication and beginning lateral movement"
  },
  "decision": {
    "decision_type": "isolate_host",
    "confidence": 0.98,
    "actions": [
      {
        "type": "edr_action",
        "name": "isolate_host_network",
        "params": {"host": "host-42.internal"}
      },
      {
        "type": "firewall_block",
        "name": "block_ioc_ips",
        "params": {"ips": ["45.33.32.156", "91.240.118.30"]}
      }
    ],
    "playbook_name": "ransomware_response",
    "requires_human_approval": false,
    "reasoning": "High confidence ransomware activity detected with active C2 communication. Immediate isolation required to prevent lateral movement and data encryption.",
    "risk_assessment": "Critical - active ransomware with lateral movement detected"
  }
}
```

---

## 🔄 Federated Learning

### POST `/api/v1/fl/start_round`
Démarre un nouveau round d'apprentissage fédéré.

**Request:**
```json
{
  "num_clients": 5,
  "num_rounds": 10,
  "local_epochs": 5,
  "fraction_fit": 0.6,
  "min_clients": 3,
  "differential_privacy": true,
  "dp_noise_multiplier": 1.0
}
```

**Response (200):**
```json
{
  "round_id": "fl-round-001",
  "status": "started",
  "config": {
    "num_clients": 5,
    "num_rounds": 10,
    "local_epochs": 5,
    "differential_privacy": true
  },
  "server_address": "localhost:9092"
}
```

### GET `/api/v1/fl/status`
Statut de l'apprentissage fédéré.

**Response (200):**
```json
{
  "status": "running",
  "current_round": 3,
  "total_rounds": 10,
  "clients_connected": 5,
  "clients_required": 3,
  "global_loss": 0.0234,
  "differential_privacy": true,
  "started_at": "2026-05-04T10:00:00Z",
  "estimated_completion": "2026-05-04T10:30:00Z"
}
```

### GET `/api/v1/fl/clients`
Liste des clients connectés.

**Response (200):**
```json
{
  "clients": [
    {
      "client_id": "client-001",
      "org_id": "org-a",
      "status": "training",
      "samples": 2000,
      "last_round": 3,
      "loss": 0.021,
      "dp_enabled": true
    }
  ],
  "total_connected": 5
}
```

---

## 📥 Ingestion & Logs

### POST `/api/v1/ingestion/ingest`
Ingère des logs dans le pipeline.

**Request:**
```json
{
  "org_id": "default",
  "source": "zeek",
  "logs": [
    {
      "event_type": "connection",
      "src_ip": "192.168.1.10",
      "dst_ip": "8.8.8.8",
      "src_port": 54321,
      "dst_port": 53,
      "protocol": "udp",
      "timestamp": "2026-05-04T10:45:00Z"
    }
  ]
}
```

**Response (200):**
```json
{
  "status": "ingested",
  "count": 1,
  "enriched": true,
  "anomalies_detected": 0,
  "processing_time_ms": 15.2
}
```

### GET `/api/v1/ingestion/sources`
Liste des sources de logs actives.

**Response (200):**
```json
{
  "sources": [
    {
      "name": "zeek",
      "type": "network",
      "status": "active",
      "logs_per_second": 45.2,
      "last_log": "2026-05-04T10:45:00Z"
    },
    {
      "name": "suricata",
      "type": "ids",
      "status": "active",
      "logs_per_second": 12.8,
      "last_log": "2026-05-04T10:45:00Z"
    }
  ]
}
```

---

## 🔒 Security & Encryption

### POST `/api/v1/security/encrypt`
Chiffre des données sensibles.

**Request:**
```json
{
  "data": {
    "src_ip": "45.33.32.156",
    "user": "jdoe",
    "password_attempt": "P@ssw0rd!"
  }
}
```

**Response (200):**
```json
{
  "encrypted": {
    "src_ip": "gAAAAABm...",
    "user": "gAAAAABn...",
    "password_attempt": "gAAAAABo..."
  },
  "algorithm": "AES-256-GCM"
}
```

### POST `/api/v1/security/decrypt`
Déchiffre des données.

**Request:**
```json
{
  "data": {
    "src_ip": "gAAAAABm..."
  }
}
```

**Response (200):**
```json
{
  "decrypted": {
    "src_ip": "45.33.32.156"
  }
}
```

---

## 💚 Health & Monitoring

### GET `/health`
Health check de l'API.

**Response (200):**
```json
{
  "status": "healthy",
  "version": "2.0.0",
  "uptime_seconds": 86400,
  "services": {
    "database": "connected",
    "kafka": "connected",
    "clickhouse": "connected",
    "redis": "connected"
  },
  "timestamp": "2026-05-04T10:45:00Z"
}
```

### GET `/api/v1/health/integrations`
Health check des intégrations.

**Response (200):**
```json
{
  "firewall": "healthy",
  "edr": "healthy",
  "iam": "healthy",
  "dns": "healthy",
  "notifications": "healthy",
  "tickets": "healthy",
  "thehive": "simulated",
  "misp": "simulated"
}
```

### GET `/api/v1/health/ml`
Health check du modèle ML.

**Response (200):**
```json
{
  "model_loaded": true,
  "model_type": "TransformerAutoencoder",
  "device": "cpu",
  "threshold": 0.95,
  "inference_time_ms": 12.3,
  "total_detections": 1500,
  "anomaly_rate": 0.031
}
```

---

## 📝 Codes d'Erreur

| Code | Description |
|------|-------------|
| `400` | Bad Request — paramètres invalides |
| `401` | Unauthorized — token manquant ou invalide |
| `403` | Forbidden — permissions insuffisantes |
| `404` | Not Found — ressource inexistante |
| `422` | Validation Error — payload invalide |
| `429` | Too Many Requests — rate limit dépassé |
| `500` | Internal Server Error |

**Exemple d'erreur (422):**
```json
{
  "detail": [
    {
      "loc": ["body", "playbook_name"],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```

---

## 🚀 Rate Limiting

| Endpoint | Limite | Fenêtre |
|----------|--------|---------|
| `/api/v1/auth/*` | 10 requêtes | 1 minute |
| `/api/v1/soar/execute` | 30 requêtes | 1 minute |
| `/api/v1/ml/detect` | 100 requêtes | 1 minute |
| `/api/v1/ingestion/*` | 1000 requêtes | 1 minute |
| Autres | 60 requêtes | 1 minute |

Headers de rate limiting dans les réponses :
```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1685894400
```

---

## 🔗 Webhooks

Configurez des webhooks pour recevoir des notifications en temps réel.

### POST `/api/v1/webhooks/register`
Enregistre un nouveau webhook.

**Request:**
```json
{
  "url": "https://hooks.slack.com/services/...",
  "events": ["alert.critical", "soar.completed", "anomaly.detected"],
  "secret": "whsec_..."
}
```

**Response (201):**
```json
{
  "id": "wh-001",
  "url": "https://hooks.slack.com/services/...",
  "events": ["alert.critical", "soar.completed", "anomaly.detected"],
  "status": "active"
}
```

### Événements disponibles

| Event | Description |
|-------|-------------|
| `alert.critical` | Alerte critique créée |
| `alert.high` | Alerte haute créée |
| `soar.completed` | Playbook SOAR terminé |
| `soar.failed` | Playbook SOAR échoué |
| `anomaly.detected` | Anomalie ML détectée |
| `fl.round_complete` | Round FL terminé |
| `system.health` | Changement de statut santé |

---

## 📦 Exemples cURL

```bash
# Login
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=cybershield2024"

# Dashboard overview
curl http://localhost:8000/api/v1/dashboard/overview?org_id=default \
  -H "Authorization: Bearer <token>"

# Execute SOAR playbook
curl -X POST http://localhost:8000/api/v1/soar/execute \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "playbook_name": "brute_force_response",
    "alert": {"src_ip": "45.33.32.156"},
    "iocs": {"ips": ["45.33.32.156"]},
    "human_approved": true
  }'

# ML detection
curl -X POST http://localhost:8000/api/v1/ml/detect \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "logs": [{"src_ip": "45.33.32.156", "dst_ip": "10.0.0.50", "dst_port": 445, "protocol": "tcp"}]
  }'

# Health check
curl http://localhost:8000/health
```

---

> **Documentation générée automatiquement** — Dernière mise à jour: 2026-05-04  
> **Swagger UI**: `http://localhost:8000/docs`  
> **ReDoc**: `http://localhost:8000/redoc`
