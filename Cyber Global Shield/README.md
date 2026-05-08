# Cyber Global Shield v2.0

<div align="center">

**🛡️ Autonomous Agentic SIEM Platform — Zero-Day Detection & Real-Time Response**

*"Detect what was never seen. Respond faster than ransomware encrypts."*

</div>

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     CYBER GLOBAL SHIELD v2                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │   Zeek   │  │ Suricata │  │  osquery  │  │  PyShark │        │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘        │
│       │              │              │              │              │
│       └──────────────┴──────┬───────┴──────────────┘              │
│                             │                                     │
│                       ┌─────▼─────┐                              │
│                       │   Vector   │  Log Collection              │
│                       └─────┬─────┘                              │
│                             │                                     │
│                       ┌─────▼─────┐                              │
│                       │   Kafka    │  Stream Buffer               │
│                       └─────┬─────┘                              │
│                             │                                     │
│              ┌──────────────┼──────────────┐                     │
│              │              │              │                      │
│        ┌─────▼─────┐ ┌─────▼─────┐ ┌─────▼─────┐                │
│        │ ClickHouse │ │ ML/Anomal │ │   CrewAI  │                │
│        │ (OLAP)     │ │  Detector │ │  Agents   │                │
│        └───────────┘ └─────┬─────┘ └─────┬─────┘                │
│                            │              │                      │
│                     ┌──────▼──────┐       │                      │
│                     │ Ray + Flower│       │                      │
│                     │ (Dist. ML)  │       │                      │
│                     └─────────────┘       │                      │
│                                           │                      │
│                                    ┌──────▼──────┐              │
│                                    │    SOAR     │              │
│                                    │  Playbooks  │              │
│                                    └──────┬──────┘              │
│                                           │                      │
│                              ┌────────────┼────────────┐        │
│                        ┌─────▼────┐ ┌─────▼────┐ ┌────▼───┐     │
│                        │ Firewall │ │   EDR    │ │  IAM   │     │
│                        └──────────┘ └──────────┘ └────────┘     │
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │   MISP   │  │  Cortex  │  │  Grafana │  │Prometheus│        │
│  │(TI Ctip) │  │(Analysis)│  │(Dash)    │  │(Metrics) │        │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘        │
└─────────────────────────────────────────────────────────────────┘
```

## Core Modules

| Module | Description | Technology |
|--------|-------------|------------|
| **Ingestion Pipeline** | High-throughput log collection & normalization | Vector + Kafka + ClickHouse |
| **ML Anomaly Detection** | Zero-day detection via Transformer Autoencoder + Isolation Forest | PyTorch, scikit-learn |
| **Federated Learning** | Privacy-preserving distributed model training | Flower + Ray |
| **Autonomous Agents** | AI-powered SOC analysts (Triage, Investigation, Response, Intel) | CrewAI + LLM |
| **SOAR Engine** | Automated response playbooks (Ransomware, Lateral Movement, Exfil, C2, Brute Force) | Custom Async |
| **Threat Intelligence** | Enrichment via MISP, Cortex, VirusTotal | pymisp, cortex4py, vt-py |
| **Observability** | Real-time dashboards & monitoring | Grafana + Prometheus |

## 35 Security Modules

| # | Module | Endpoint | Status |
|---|--------|----------|--------|
| 1 | 🪤 Honeypot Intelligence | `/api/v1/security/honeypot` | ✅ |
| 2 | 🛡️ Ransomware Shield | `/api/v1/security/ransomware` | ✅ |
| 3 | 🔍 Zero-Day Exploit Detection | `/api/v1/security/zero-day` | ✅ |
| 4 | 🔗 Supply Chain Security | `/api/v1/security/supply-chain` | ✅ |
| 5 | 🌐 Deep Packet Inspection | `/api/v1/security/dpi` | ✅ |
| 6 | 👤 Behavioral Biometrics | `/api/v1/security/biometrics` | ✅ |
| 7 | 🌑 Dark Web Monitoring | `/api/v1/security/dark-web` | ✅ |
| 8 | 🔬 Automated Forensics | `/api/v1/security/forensics` | ✅ |
| 9 | 📡 Threat Intelligence Feeds | `/api/v1/security/threat-intel` | ✅ |
| 10 | 🎭 AI Deception Grid | `/api/v1/security/deployment` | ✅ |
| 11 | 🔧 Self-Healing Infrastructure | `/api/v1/security/self-heal` | ✅ |
| 12 | 🔐 Quantum-Resistant Crypto | `/api/v1/security/crypto` | ✅ |
| 13 | 🎯 Autonomous Threat Hunter | `/api/v1/security/threat-hunt` | ✅ |
| 14 | 🔗 Blockchain Audit Trail | `/api/v1/security/blockchain` | ✅ |
| 15 | 🎭 Deepfake Detection | `/api/v1/security/deepfake` | ✅ |
| 16 | 📋 Automated Threat Modeling | `/api/v1/security/threat-model` | ✅ |
| 17 | 🛡️ Zero-Trust Microsegmentation | `/api/v1/security/zero-trust` | ✅ |
| 18 | 🔍 AI Code Security Auditor | `/api/v1/security/code-audit` | ✅ |
| 19 | ✅ Automated Compliance Engine | `/api/v1/security/compliance` | ✅ |
| 20 | 📊 Predictive Cyber Insurance | `/api/v1/security/insurance` | ✅ |
| 21 | 🔄 Digital Twin Security | `/api/v1/security/digital-twin` | ✅ |
| 22 | 🔴 Autonomous Penetration Testing | `/api/v1/security/pentest` | ✅ |
| 23 | 🔬 Memory Forensics Analyzer | `/api/v1/security/memory-forensics` | ✅ |
| 24 | 🌐 Network Traffic Analyzer | `/api/v1/security/network-traffic` | ✅ |
| 25 | 📱 Mobile Security Scanner | `/api/v1/security/mobile` | ✅ |
| 26 | ☁️ Cloud Security Posture | `/api/v1/security/cloud` | ✅ |
| 27 | 🔑 Secrets Detection Engine | `/api/v1/security/secrets` | ✅ |
| 28 | 📊 Security Dashboard API | `/api/v1/security/dashboard` | ✅ |
| 29 | ⚡ Performance Optimizer | `/api/v1/security/performance` | ✅ |
| 30 | 🤖 AI Chatbot Assistant | `/api/v1/agents/chatbot` | ✅ |
| 31 | 🧠 AI SOC Analyst | `/api/v1/agents/soc-analyst` | ✅ |
| 32 | ⚡ Zero-Touch SOAR | `/api/v1/soar/zero-touch` | ✅ |
| 33 | 🚨 Incident Response | `/api/v1/soar/incident-response` | ✅ |
| 34 | 🔮 Attack Predictor | `/api/v1/ml/attack-predictor` | ✅ |
| 35 | 🛡️ Adversarial ML Defense | `/api/v1/ml/adversarial-defense` | ✅ |

## Infrastructure & DevOps

| Component | Description | Status |
|-----------|-------------|--------|
| **Docker Compose** | Full stack orchestration (API, Kafka, ClickHouse, Vector, Zeek, Suricata) | ✅ |
| **Helm Chart** | Kubernetes deployment (12 templates: deployment, service, HPA, ingress, PDB, PVC, canary, backup) | ✅ |
| **Terraform** | AWS infrastructure (VPC, EKS, RDS, ElastiCache, S3, CloudWatch) | ✅ |
| **CI/CD** | GitHub Actions (lint, test, build, deploy, security scan) | ✅ |
| **Canary Deployments** | Progressive rollout with metrics-based rollback | ✅ |
| **Backup/Restore** | ClickHouse backup to S3 with retention policies | ✅ |
| **Monitoring** | Prometheus + Grafana dashboards | ✅ |
| **Load Testing** | Locust distributed load testing | ✅ |

## Security Features

| Feature | Description | Status |
|---------|-------------|--------|
| **JWT Auth** | OAuth2 with role-based access control | ✅ |
| **API Keys** | Programmatic access with scoped permissions | ✅ |
| **SSO/OAuth** | Single Sign-On (Google, GitHub, Azure AD) | ✅ |
| **Rate Limiting** | Token bucket algorithm (per-IP + per-key) | ✅ |
| **CORS** | Restricted origins for production | ✅ |
| **Security Headers** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options | ✅ |
| **WebSockets** | Real-time security event streaming | ✅ |
| **Webhooks** | Outgoing event notifications | ✅ |
| **Notifications** | Slack, Teams, Email, SMS, Push | ✅ |
| **Multi-Tenant** | org_id isolation across all data | ✅ |
| **Pagination** | Cursor-based pagination for all list endpoints | ✅ |
| **Export** | CSV, JSON, PDF export | ✅ |
| **Full-Text Search** | Elasticsearch-like search across security data | ✅ |
| **LLM Cost Monitor** | Track and optimize LLM API usage costs | ✅ |
| **A/B Testing** | ML model comparison and evaluation | ✅ |
| **MLflow** | Experiment tracking and model drift detection | ✅ |
| **Feature Store** | Centralized feature management for ML | ✅ |
| **SOC Chatbot** | Natural language query interface | ✅ |
| **Threat Map** | Real-time geolocation threat visualization | ✅ |
| **Dashboard** | Chart.js interactive SOC dashboard | ✅ |


## Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.11+
- 16GB RAM recommended

### Environment Setup
```bash
cd "Cyber Global Shield"

# Copy environment template
cp .env.example .env

# Edit .env with your API keys (OpenAI, MISP, etc.)
```

### Start Full Stack
```bash
# Start all services
docker compose up -d

# View logs
docker compose logs -f api

# Check health
curl http://localhost:8000/health
```

### Start Dev Mode
```bash
# Install dependencies
pip install -r requirements.txt

# Run API server
python app.py
```

## API Endpoints

### Platform
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/` | Platform info |

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/login` | Login (OAuth2) |
| POST | `/api/v1/auth/api-key` | Generate API key |

### Ingestion
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/ingest/log` | Ingest single log |
| POST | `/api/v1/ingest/batch` | Ingest batch of logs |
| GET | `/api/v1/ingest/stats` | Ingestion statistics |

### ML Detection
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/ml/detect` | Detect anomalies |
| POST | `/api/v1/ml/calibrate` | Calibrate threshold |

### Federated Learning
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/fl/train` | Start FL training |
| GET | `/api/v1/fl/stats` | FL statistics |

### Autonomous Agents
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/agents/triage` | Triage alert |
| POST | `/api/v1/agents/investigate` | Deep investigation |
| POST | `/api/v1/agents/pipeline` | Full SOC pipeline |

### SOAR
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/soar/playbooks` | List playbooks |
| POST | `/api/v1/soar/execute` | Execute playbook |

### Dashboard
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/dashboard/overview` | Dashboard overview |
| GET | `/api/v1/dashboard/alerts` | Search alerts |

### Threat Intel
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/threat-intel/enrich` | Enrich IOCs |

## Attack Response Flow

```
Zeek detects port scan on port 445 (SMB)
    ↓ (Vector ingests, Kafka buffers)
ML Autoencoder → reconstruction error spike → ANOMALY DETECTED
    ↓
CrewAI Triage Agent → Severity: CRITICAL, Priority: 10
    ↓
Threat Intel Agent (MISP) → IP matches EternalBlue exploit kit
    ↓
Investigation Agent → Lateral movement pattern detected
    ↓
Response Agent → Execute ransomware_response playbook
    ↓
SOAR Engine:
   ├─ Isolate patient zero (EDR)
   ├─ Block C2 IPs (Firewall)
   ├─ Sinkhole domains (DNS)
   ├─ Disable compromised accounts (IAM)
   ├─ Snapshot for forensic
   ├─ Notify SOC team
   └─ Create incident ticket
    ↓
Total time: < 5 seconds
```

## SOAR Playbooks

| Playbook | Trigger | Auto | Actions |
|----------|---------|------|---------|
| `ransomware_response` | Ransomware detected | ✅ | Isolate host, block IOCs, disable users, snapshot, notify |
| `lateral_movement_response` | Lateral movement | ✅ | Segment network, revoke credentials, block internal |
| `data_exfiltration_response` | Data exfiltration | ❌* | Block egress, packet capture, snapshot, notify DPO |
| `c2_communication_response` | C2 communication | ✅ | Block C2 IPs, sinkhole DNS, isolate host, collect artifacts |
| `brute_force_response` | Brute force attack | ✅ | Block IP, enforce MFA, temp disable account |

*Requires human approval

## Scaling

| Component | Scale Strategy |
|-----------|---------------|
| API | Horizontal (add workers) |
| Kafka | Add brokers, increase partitions |
| ClickHouse | Sharding + replication |
| ML Inference | Ray cluster (GPU nodes) |
| FL Training | Add more clients |
| SOAR | Async execution, rate limiting with cooldowns |

## Ports

| Service | Port | URL |
|---------|------|-----|
| API | 8000 | http://localhost:8000 |
| Grafana | 3000 | http://localhost:3000 |
| Prometheus | 9090 | http://localhost:9090 |
| Kafka | 9092 | PLAINTEXT://localhost:9092 |
| ClickHouse HTTP | 8123 | http://localhost:8123 |
| ClickHouse Native | 9000 | localhost:9000 |
| Ray Dashboard | 8265 | http://localhost:8265 |
| FL Server | 8080 | localhost:8080 |
| MISP | 8443 | https://localhost:8443 |
| Vector | 9000 | localhost:9000 |

## Security

- JWT-based authentication with role-based access control
- API keys for programmatic access
- Differential Privacy support in Federated Learning
- Secure Aggregation for FL model updates
- Encrypted communication (mTLS planned via Istio)
- Audit logging of all agent decisions

## License

Proprietary — Cyber Global Shield Team

## Team

Built to address the $10 trillion annual cybercrime problem through autonomous detection and response.