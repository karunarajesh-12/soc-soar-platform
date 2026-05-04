# 🛡️ EDR/SOC Platform — Home Lab

> A full-stack **Endpoint Detection & Response (EDR)** platform built from scratch, integrating **osquery**, **ELK Stack**, **Velociraptor**, custom **threat intelligence enrichment**, and automated **SOAR response playbooks**.

---

## 📸 Screenshots

### Overview Dashboard
![Overview Dashboard](images/Screenshot_2026-05-03_193633.png)

### Live Detections Feed
![Live Detections](images/Screenshot_2026-05-03_193703.png)

### Network Monitor
![Network Monitor](images/Screenshot_2026-05-03_193925.png)

### IR & Response Panel
![IR & Response](images/Screenshot_2026-05-03_194023.png)

### EDR Incident Report — Summary
![Incident Report Summary](images/Screenshot_2026-05-03_194148.png)

### EDR Incident Report — Timeline & Triggers
![Incident Report Timeline](images/Screenshot_2026-05-03_194213.png)

---

## 🏗️ Architecture Overview

```
┌──────────────────────┐      ┌──────────────────────────┐      ┌──────────────────────────┐      ┌──────────────────────────┐      ┌──────────────────────┐
│     ENDPOINT         │      │     ELK PIPELINE         │      │      SOC PLATFORM        │      │     RESPONSE LAYER       │      │      OUTPUT          │
│  Debian/Linux Client │      │   Ubuntu 22.04 Server    │      │     Python / Flask       │      │   Automated Actions      │      │      RESULTS         │
├──────────────────────┤      ├──────────────────────────┤      ├──────────────────────────┤      ├──────────────────────────┤      ├──────────────────────┤
│ • osquery            │      │ • Logstash               │      │ • Threat Scoring         │      │ • Tier 1                 │      │ • < 60 sec response  │
│   - Process Monitor  │      │   - Ingest & Normalize   │      │   - Behavior Analysis    │      │   - Kill Process         │      │ • Real-time detect   │
│   - File Integrity   │      │   - ECS Normalization    │      │   - MITRE Mapping        │      │   - File Quarantine      │      │ • Low false positive │
│   - User Activity    │      │   - Correlation          │      │                          │      │                          │      │ • SOC visibility     │
│                      │      │                          │      │ • Threat Intel Hub       │      │ • Tier 2                 │      │ • Auto response      │
│ • Filebeat           │─────▶│ • Elasticsearch          │─────▶│   - VirusTotal           │─────▶│   - Block IP             │─────▶│                      │
│   - Log Shipping     │ TLS  │   - Index + Storage      │      │   - AlienVault OTX       │      │   - Stop C2              │      │                      │
│   - Secure Send      │      │   - Fast Search          │      │   - AbuseIPDB            │      │                          │      │                      │
│                      │      │                          │      │                          │      │ • Tier 3                 │      │                      │
│ • Velociraptor       │      │ • Kibana                 │      │ • Detection Engine       │      │   - Host Isolation       │      │                      │
│   - Forensics        │      │   - Dashboards           │      │   - APT Detection        │      │   - Network Disable      │      │                      │
│   - Threat Hunting   │      │   - Visualization        │      │   - Fileless Malware     │      │   - Forensics Collect    │      │                      │
│   - Artifacts        │      │   - Alerts               │      │   - Privilege Esc        │      │                          │      │                      │
│                      │      │                          │      │ • SOAR Engine            │      │                          │      │                      │
│                      │      │                          │      │   - Automation           │      │                          │      │                      │
│                      │      │                          │      │   - Playbooks            │      │                          │      │                      │
└──────────────────────┘      └──────────────────────────┘      └──────────────────────────┘      └──────────────────────────┘      └──────────────────────┘
```

---

## 🔧 Tech Stack

| Layer | Technology |
|-------|-----------|
| Endpoint Agent | osquery, Filebeat, Velociraptor |
| SIEM | Elasticsearch, Logstash, Kibana (ELK Stack) |
| SOC Platform | Python / Flask |
| Threat Intel | VirusTotal, AlienVault OTX, AbuseIPDB |
| SOAR | Custom playbook engine |
| OS | Debian/Linux (endpoint), Ubuntu 22.04 (server) |

---

## 🧩 How It Works

### 1. Endpoint Layer — Data Collection

- **osquery** turns the OS into a real-time queryable database: monitors processes, file integrity, and user activity for behavior-based detection (not signature-based)
- **Filebeat** securely ships logs over TLS from `/var/log` and osquery output to the ELK pipeline
- **Velociraptor** enables live forensics, artifact collection, and deep endpoint visibility during incident response

### 2. ELK Pipeline — Log Processing & SIEM

- **Logstash** ingests raw logs, normalizes to ECS (Elastic Common Schema), and correlates events
- **Elasticsearch** indexes and stores structured JSON log events with high-speed search
- **Kibana** provides real-time dashboards, alert monitoring, and security analytics

### 3. SOC Platform — Detection & Decision Engine

- **Threat Scoring Engine** assigns a risk score to every event using behavioral analysis and MITRE ATT&CK mapping
- **Threat Intelligence Hub** enriches alerts with VirusTotal, AlienVault OTX, and AbuseIPDB to reduce false positives
- **Detection Engine** covers APT patterns, fileless malware, and privilege escalation via rule-based + behavioral detection
- **SOAR Engine** automates incident response by executing predefined playbooks

### 4. Response Layer — Tiered Automated Actions

| Tier | Action |
|------|--------|
| 🟢 Tier 1 — Immediate | Kill malicious process, quarantine file |
| 🟡 Tier 2 — Network | Block attacker IP, stop C2 communication |
| 🔴 Tier 3 — Full Isolation | Network isolate endpoint, collect forensic artifacts |

---

## 📊 Key Metrics (Live Demo)

| Metric | Value |
|--------|-------|
| Critical Alerts | 45 |
| Active Alerts | 97 |
| Suspicious Events | 349 |
| SOAR Actions Fired | 430 |
| Enriched Documents | 102.7k |
| Threat Risk Score | **90 / 100 (CRITICAL)** |
| Avg Detection→Response Time | **42.1 seconds** |
| SOAR Steps Succeeded | **63%** |
| Total Response Steps | 164 |

---

## 🎯 MITRE ATT&CK Coverage

| Technique | ID | Detections |
|-----------|-----|------------|
| Execution | T1059 | 79 |
| Defense Evasion | T1222 | 23 |
| C2 | T1071 | 13 |
| Impact | T1496 | 12 |
| C2 | T1105 | 11 |
| Lateral Movement | T1021.004 | 11 |
| Defense Evasion | T1574 | 9 |
| Command & Control | T1105 | 8 |

---

## 🔍 Detection Methodology

| Method | Detections |
|--------|-----------|
| LotL Behavioral | 84 |
| Threat Intel API | 10 |
| Heuristic | 6 |

---

## 🚨 Top LotL (Living off the Land) Behavioral Triggers

| Trigger | Count |
|---------|-------|
| Exec perm on /tmp file | 23 |
| IRC backdoor | 13 |
| Cryptominer binary | 12 |
| Execute from /tmp | 12 |
| LD_PRELOAD rootkit | 9 |
| Download to /tmp | 9 |
| Netcat listener/connect | 8 |
| Interactive bash redirect | 7 |

---

## 📋 SOAR Playbook Distribution

| Playbook | Triggered |
|----------|-----------|
| PB-00-LOGGED-ONLY | 25 |
| PB-03-CRITICAL | 16 |
| PB-06-CRYPTOMINER | 16 |
| PB-08-BACKDOOR | 13 |
| PB-07-BOTNET | 8 |
| PB-02-MALICIOUS-HASH | 3 |
| PB-04-SUSPICIOUS | 3 |

---

## ✅ Results

- ⚡ **Detection-to-response time under 60 seconds**
- 🔍 **Real-time threat detection** across all monitored endpoints
- 🧠 **Reduced false positives** through multi-source threat intelligence enrichment
- 📺 **Full SOC visibility** via dashboard-driven interface
- 🤖 **Fully automated incident response** using tiered SOAR playbooks

---

## 📁 Project Structure

```
edr-platform/
├── endpoint/             # osquery configs, Filebeat setup, Velociraptor client
├── elk-pipeline/         # Logstash pipelines, Elasticsearch index templates
├── soc-platform/         # Flask app — detection engine, SOAR, threat intel
│   ├── detection/        # Behavioral rules, scoring logic
│   ├── soar/             # Playbooks and automation engine
│   └── threat_intel/     # VirusTotal, OTX, AbuseIPDB integrations
└── dashboards/           # Kibana dashboard exports
```

---

## ⚙️ Setup Overview

1. **Endpoint** — Install osquery + Filebeat on Debian client; configure Velociraptor agent
2. **ELK Stack** — Deploy Elasticsearch, Logstash, Kibana on Ubuntu 22.04 server
3. **SOC Platform** — Run the Flask application; configure threat intel API keys
4. **Connect** — Point Filebeat → Logstash; connect SOC platform to Elasticsearch
5. **Playbooks** — Configure SOAR playbooks with your response thresholds

---

*Built with ❤️ as a home lab project to explore real-world SOC operations and automated incident response.*
