# ThreatFlux-SIEM

## Advanced Threat Intelligence & SOC Automation Platform

ThreatFlux-SIEM is a modern cybersecurity platform designed to automate threat intelligence collection, firewall enforcement, IOC analysis, and SOC operations through a centralized dashboard.

The platform integrates multiple intelligence feeds, automated kernel-level defense mechanisms, and real-time monitoring features to simulate enterprise-grade Security Operations Center (SOC) workflows.

---

# Features

## Threat Intelligence Aggregation

* AbuseIPDB Integration
* AlienVault OTX Integration
* PhishTank Intelligence Feed
* IOC Correlation & Risk Scoring

## SOC Dashboard

* Modern SIEM-style interface
* Live threat feed monitoring
* Interactive blocklist management
* Real-time execution logs

## Automated Defense

* Linux iptables enforcement
* Automatic high-risk IP blocking
* Manual block/unblock controls
* Emergency rollback support

## Offensive Security Validation

* Integrated penetration testing module
* Automated firewall validation
* Threat simulation testing

## Kernel-Level Security Operations

* Direct Linux firewall interaction
* Live kernel rule correlation
* Active defense management

---

# Technology Stack

| Component       | Technology                           |
| --------------- | ------------------------------------ |
| Backend         | Python + Flask                       |
| Frontend        | HTML5 + CSS3 + JavaScript            |
| Database        | MongoDB                              |
| Firewall Engine | Linux iptables                       |
| Threat Sources  | AbuseIPDB, AlienVault OTX, PhishTank |

---

# Project Architecture

```bash
ThreatFlux-SIEM/
│
├── src/
│   ├── api/
│   │   ├── app.py
│   │   └── templates/
│   │       └── index.html
│   │
│   ├── database/
│   │   └── db_connection.py
│   │
│   ├── processors/
│   │   └── policy_enforcer.py
│   │
│   ├── scrapers/
│   │   ├── abuseipdb.py
│   │   ├── alienvault.py
│   │   └── phishtank.py
│   │
│   ├── tests/
│   │   ├── auto_pentest.py
│   │   └── pen_test_sim.py
│   │
│   └── utils/
│       └── rollback.py
│
└── requirements.txt
```

---

# Installation

## Clone Repository

```bash
git clone https://github.com/Boscoefx/ThreatFlux-SIEM.git
```

## Navigate to Project

```bash
cd ThreatFlux-SIEM
```

## Create Virtual Environment

```bash
python3 -m venv venv
```

## Activate Environment

```bash
source venv/bin/activate
```

## Install Requirements

```bash
pip install -r requirements.txt
```

---

# Run Application

```bash
python3 -m src.api.app
```

Open browser:

```text
http://127.0.0.1:5000
```

---

# Dashboard Modules

## Update Intel

Fetches threat intelligence from multiple OSINT feeds.

## Push Defense

Automatically enforces firewall rules for high-risk indicators.

## Batch Pentest

Runs automated penetration simulations against blocked IPs.

## Blocklist Viewer

Displays active kernel firewall rules and correlated threat data.

## Emergency Rollback

Restores previous firewall state and removes platform rules.

---

# Screenshots

## SOC Dashboard

Add screenshots here.

```bash
screenshots/dashboard.png
```

---

# Security Notice

This platform is intended strictly for:

* Educational Use
* Cybersecurity Research
* Authorized Defensive Security Operations

Unauthorized usage against systems without permission is prohibited.

---

# Future Improvements

* Elasticsearch Integration
* Kibana Analytics
* Real-Time WebSocket Monitoring
* AI Threat Classification
* Docker Deployment
* Threat Hunting Automation
* Multi-Tenant SOC Support
* Updated virsions


---

# Author

Boscoefx

GitHub:
https://github.com/Boscoefx

---

# License

MIT License

---
# Acknowledgements

* AbuseIPDB
* AlienVault OTX
* PhishTank
* Open Source Cybersecurity Community



