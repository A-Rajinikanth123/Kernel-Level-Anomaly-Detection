# AI-Based Kernel-Level Anomaly Detection and Real-Time Operating System Security Monitoring System

### Cyber Security Operations Center (SOC)
**Kernel Sentinel &bull; Behavioral AI Threat Intelligence**

---

## 📌 Project Overview & Problem Statement
Traditional cybersecurity mechanisms (firewalls, antivirus, SIEMs, application firewalls) primarily inspect network traffic and user-space application logs. However, advanced threats—such as zero-day exploits, rootkits, unauthorized privilege escalations, stealthy process injections, in-memory payload execution, and anomalous kernel system calls—operate directly at the **operating system kernel level**, remaining invisible to conventional tools.

This project implements an intelligent, real-time operating system security monitoring system combining:
1. **Low-level Kernel Monitoring** (Linux eBPF tracepoints `sys_enter_execve`, `openat`, `connect`, `setuid`, `capset` & live cross-platform OS telemetry via `psutil`).
2. **Behavioral Feature Extraction** (tracking syscall velocity, memory/CPU footprints, handle allocations, network rates, privilege changes, and binary path indicators).
3. **AI / Machine Learning Anomaly Detection** (unsupervised **Isolation Forest** ensemble modeling trained on baseline kernel execution patterns).
4. **Automated Threat Classification & Alerting** (calibrating continuous anomaly scores $0.0 \to 1.0$ into Normal, Low, Medium, High, and Critical security incidents).
5. **Incident Response & Mitigation** (one-click process termination, binary quarantining, firewall IP blocking, and forensic review).
6. **Centralized Django Cyber SOC Web Dashboard** (interactive real-time charts, live event stream, attack simulation lab, and publication-ready PDF/CSV audit reports).

---

## 🏗️ System Architecture & Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│                 Operating System Kernel Space               │
│                                                             │
│   eBPF Probes (bpf_probe.c) / OS Telemetry Hook             │
│   ├─ sys_enter_execve  (Process spawn & binaries)           │
│   ├─ sys_enter_openat  (Sensitive file operations)          │
│   ├─ sys_enter_connect (Network sockets & C2 beaconing)     │
│   └─ sys_enter_setuid  (Privilege escalation attempts)      │
└──────────────────────────────┬──────────────────────────────┘
                               │  Perf / Event Buffer Stream
                               ▼
┌─────────────────────────────────────────────────────────────┐
│             User-Space Collector & Feature Extractor        │
│                                                             │
│   Extracts 10-dimensional behavioral vector:                │
│   [syscall_freq, cpu_usage, mem_usage_mb, thread_count,     │
│    open_fds, file_op_rate, net_conn_rate,                   │
│    is_priv_escalation, suspicious_path, sensitive_target]   │
└──────────────────────────────┬──────────────────────────────┘
                               │  StandardScaler Normalized Vectors
                               ▼
┌─────────────────────────────────────────────────────────────┐
│           AI / ML Anomaly Detection Engine (Scikit-Learn)    │
│                                                             │
│   Isolation Forest Ensemble (Contamination: 0.04, 120 Trees)│
│   ├─ Decision function projection                           │
│   ├─ Logistic score calibration: [0.00 - 1.00]              │
│   └─ Threat Level: NORMAL | LOW | MEDIUM | HIGH | CRITICAL  │
└──────────────────────────────┬──────────────────────────────┘
                               │  Anomaly Scores & Explanations
                               ▼
┌─────────────────────────────────────────────────────────────┐
│             Django SOC Web Dashboard & REST APIs            │
│                                                             │
│   ├─ Real-Time HUD Statistics & Telemetry Velocity Chart    │
│   ├─ Threat Severity Distribution & Radar Forensic Chart    │
│   ├─ Live Streaming Kernel Event Table                      │
│   ├─ Interactive Cyber-Attack Simulation Lab                │
│   ├─ Active Incident Mitigation (Kill, Quarantine, Resolve) │
│   └─ Executive PDF & SIEM CSV Audit Reports                 │
└─────────────────────────────────────────────────────────────┘
```

---

## 💻 Tech Stack
- **Backend**: Python 3.10+, Django 6.1
- **Machine Learning**: Scikit-Learn (`IsolationForest`, `StandardScaler`), NumPy, Joblib
- **Kernel Monitoring / OS Telemetry**: C (`bpf_probe.c`), Linux eBPF / BCC, Python `psutil`
- **Frontend / Presentation**: HTML5, Modern CSS3 (Dark SOC Cyber Theme), JavaScript ES6, Chart.js, FontAwesome 6
- **Database**: SQLite (default, zero configuration required) / MySQL / PostgreSQL ready

---

## 🚀 Quick Start Guide

### 1. Pre-requisites
Ensure Python 3.10+ is installed on your system.

### 2. Navigate to Project
```bash
cd C:\Users\rajin\.gemini\antigravity\scratch\kernel_anomaly_detection
```

### 3. Initialize Database & Seed Demo Data
Run migrations and pre-populate the database with the pre-trained Isolation Forest model, normal kernel baseline telemetry, and initial sample incidents:
```bash
python manage.py migrate
python manage.py seed_demo_data
```

### 4. Start the Django Development Server
```bash
python manage.py runserver 127.0.0.1:8000
```
Open your browser and navigate to: **`http://127.0.0.1:8000/`**

---

## 🔑 Authentication Portals & Default Credentials

### 1. Root Administrator Portal (`/admin-login/`)
- **URL**: `http://127.0.0.1:8000/admin-login/`
- Designed specifically for Lead Security Administrators with elevated privileges, TOTP token authentication, and destination console routing (SOC Dashboard vs Django Core Admin).
- **Credentials**:
  - Username: `admin`
  - Password: `admin123`
  - Security Token (simulated TOTP): `984210`

### 2. Security Analyst Portal (`/login/`)
- **URL**: `http://127.0.0.1:8000/login/`
- For SOC security analysts investigating events, checking anomaly scores, and auditing reports.
- **Credentials**:
  - Username: `analyst`
  - Password: `analyst123`

### 3. Django Core Admin (`/admin/`)
- **URL**: `http://127.0.0.1:8000/admin/`
- Custom Cyber SOC styled interface for database object management and user permissions.

---

## 🧪 Interactive Attack Simulator Lab
The platform includes a built-in **Cyber-Attack Simulation Lab** accessible via the top simulation bar or navigation menu (`/simulator/`):

1. **Privilege Escalation Attempt (`setuid` / `capset`)**:
   - Simulates an unprivileged user exploiting local binaries to transition to UID 0 (root/SYSTEM).
   - *AI Detection*: Flags `is_priv_escalation = 1.0`, yielding Anomaly Score > 0.88 (**CRITICAL**).
2. **Ransomware High-Velocity File Encryption**:
   - Simulates rapid mass file modification and encryption bursts.
   - *AI Detection*: Flags abnormal `file_op_rate` spike, yielding Anomaly Score > 0.82 (**HIGH**).
3. **Interactive Reverse Shell Spawn**:
   - Simulates spawning `/bin/sh` or command prompt from `/tmp/nc` communicating with a remote listener.
   - *AI Detection*: Flags `suspicious_path = 1.0` and network rate deviation (**HIGH**).
4. **Kernel Syscall Flood & Fork Bomb**:
   - Rapid process duplication and syscall table exhaustion (> 700 syscalls/sec).
   - *AI Detection*: Extreme outlier on `syscall_freq` ($Z > 15.0$) (**CRITICAL**).
5. **Rogue C2 Command & Control Beaconing**:
   - Simulates periodic outbound socket connections to malicious port 8443 (**MEDIUM**).
6. **Credential Database Exfiltration**:
   - Suspicious access targeting `/etc/shadow` or SAM registry hives (**CRITICAL**).

---

## 🛡️ Forensic Investigation & Mitigation
- Navigate to **Threat Alerts** (`/alerts/`) and click **Forensics** on any alert.
- View the **Behavioral Radar Chart** comparing the incident's feature vector directly against the normal system baseline mean.
- Click **Terminate Process** to trigger immediate process termination via `psutil.Process(pid).terminate()`.
- Click **Quarantine Binary** to isolate the executable path.
- Export audit trail to CSV or generate formal print-ready PDF reports with university branding.

---

## 🧪 Running Unit Tests
To run the automated verification test suite:
```bash
python manage.py test
```
All 6 tests verify ML scoring, simulation, API responses, authentication, and mitigation actions.
