# 🛡️ EDR/SOC Platform — Home Lab

## 📖 About This Project

This project is a fully functional **Endpoint Detection & Response (EDR)** and **Security Operations Center (SOC)** platform built entirely from scratch as a home lab. The goal was to simulate a real-world enterprise security monitoring environment — from raw telemetry collection on a Linux endpoint all the way through automated threat response — using open-source tools and custom Python code.

The platform works by deploying **osquery**, **Filebeat**, and **Velociraptor** on a Debian Linux endpoint to continuously collect system-level telemetry: running processes, file changes, network connections, and user activity. That data is securely shipped over TLS to an **ELK Stack** (Elasticsearch, Logstash, Kibana) server acting as the SIEM, where logs are normalized, correlated, and stored for fast querying and visualization.

On top of the SIEM sits a custom-built **SOC platform** written in Python/Flask. This is the brain of the system — it scores every incoming event for risk using behavioral analysis mapped to the **MITRE ATT&CK framework**, enriches alerts with external threat intelligence (VirusTotal, AlienVault OTX, AbuseIPDB) to separate real threats from noise, and feeds everything into a **SOAR engine** that automatically executes tiered response playbooks. Depending on the severity of a threat, the system can kill a malicious process, quarantine a file, block an attacker IP via iptables, or fully isolate the endpoint from the network — all without human intervention and with an average detection-to-response time of **42 seconds**.

In a live test run, the platform processed over **103,000 enriched documents**, fired **430 automated SOAR actions**, detected **45 critical alerts** (including cryptominer binaries, IRC backdoors, LD_PRELOAD rootkits, and reverse shells executing from `/tmp`), and achieved a threat risk score of **90/100 (CRITICAL)** — demonstrating the full end-to-end pipeline working in real time.

---

## 📸 Screenshots

### Overview Dashboard
![Overview Dashboard](images/Screenshot%202026-05-03%20193633.png)

### Live Detections Feed
![Live Detections](images/Screenshot%202026-05-03%20193703.png)

### Network Monitor
![Network Monitor](images/Screenshot%202026-05-03%20193925.png)

### IR & Response Panel
![IR & Response](images/Screenshot%202026-05-03%20194023.png)

### EDR Incident Report — Summary
![Incident Report Summary](images/Screenshot%202026-05-03%20194148.png)

### EDR Incident Report — Timeline & Triggers
![Incident Report Timeline](images/Screenshot%202026-05-03%20194213.png)

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
| SOAR | Custom playbook engine (`soar.py`) |
| OS | Debian/Linux (endpoint), Ubuntu 22.04 (server) |

---

## 🧩 How It Works

### 1. Endpoint Layer — Data Collection

**osquery** turns the OS into a real-time queryable database, monitoring processes, file integrity, and user activity for behavior-based detection — no signatures needed. **Filebeat** securely ships those logs over TLS from `/var/log` and osquery output to the ELK pipeline. **Velociraptor** enables live forensics and artifact collection during active incident response.

### 2. ELK Pipeline — Log Processing & SIEM

**Logstash** ingests raw logs, normalizes them to the Elastic Common Schema (ECS), and correlates events across sources. **Elasticsearch** indexes and stores all structured events for high-speed querying. **Kibana** provides the real-time dashboard, alert monitoring, and security analytics interface shown in the screenshots above.

### 3. SOC Platform — Detection & Decision Engine

The custom Flask application is the core of the platform. The **Threat Scoring Engine** assigns a risk score to every event using behavioral analysis and MITRE ATT&CK mapping. The **Threat Intelligence Hub** (`ti_enricher.py`) enriches alerts with live data from VirusTotal, AlienVault OTX, and AbuseIPDB to distinguish real threats from false positives. The **Detection Engine** identifies APT patterns, fileless malware, privilege escalation, and Living-off-the-Land (LotL) techniques.

### 4. SOAR Engine — Automated Response

`soar.py` and `soar_logger.py` drive the automated response pipeline. When an alert crosses a severity threshold, the SOAR engine selects the appropriate playbook and executes it automatically — no analyst needed for common threat patterns.

| Tier | Trigger | Action |
|------|---------|--------|
| 🟢 Tier 1 | Score ≥ 70 | Kill process, quarantine file |
| 🟡 Tier 2 | Score ≥ 78 + malicious hash | Block attacker IP, stop C2 |
| 🔴 Tier 3 | Score ≥ 100 (critical) | Full network isolation, forensic collection |

---

## 📊 Key Metrics (Live Demo)

| Metric | Value |
|--------|-------|
| Critical Alerts | 45 |
| Active Alerts | 97 |
| Suspicious Events | 349 |
| SOAR Actions Fired | 430 |
| Enriched Documents | 103.1k |
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

## 🚨 Top LotL Behavioral Triggers Detected

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

## 📁 Repository Structure

```
├── images/                   # Screenshots
├── soar.py                   # SOAR engine — playbook execution & response automation
├── soar_logger.py            # Structured logging for all SOAR actions
├── ti_enricher.py            # Threat intelligence enrichment (VT, OTX, AbuseIPDB)
└── README.md
```

---

## ✅ Results

- ⚡ **42-second average** detection-to-response time
- 🔍 Real-time threat detection across all monitored endpoints
- 🧠 Reduced false positives through multi-source threat intelligence enrichment
- 📺 Full SOC visibility via live dashboard
- 🤖 Fully automated incident response with zero analyst intervention for known threat patterns

---

*Built as a home lab project to explore real-world SOC operations, threat detection engineering, and automated incident response.*
