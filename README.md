# Threat Vector — Advanced Cybersecurity Training & Threat Intelligence Platform

**Lead Developer:** Ms. Dhriti Gupta  
**Repository:** [https://github.com/Dhriti-001/Threat_Vector](https://github.com/Dhriti-001/Threat_Vector)  
**Technologies:** Python 3.14, Flask, SQLite, Scikit-Learn, HTML5, CSS3, JavaScript (Chart.js), Gunicorn

---

## 🌟 Platform Capabilities & Architecture

**Threat Vector** is a comprehensive, enterprise-grade cybersecurity awareness and threat defense platform engineered for corporate and institutional training. The system bridges psychological deception modeling with tactical defensive operations across 8 integrated modules:

### 1. 📊 Personal Analytics Dashboard (`/analytics`)
- **Strict Trainee Isolation:** Trainees inspect only their private telemetry and records.
- **Dynamic Progression:** Calculates total drills completed, defense accuracy %, earned XP, level progression, and active daily streak.
- **Cognitive Weakness Diagnosis:** Pinpoints specific cognitive vulnerabilities (Urgency, Authority, Fake Links, Incentive, Coercion) with fail-rate percentages and direct targeted drill recommendations.
- **Performance Curves:** Interactive Chart.js timeline rendering cumulative accuracy and reaction speeds.
- **Unified Activity Feed:** Chronological audit trail across simulation drills, captured flags, and phishing labs.

### 2. 🎣 Realistic Phishing Defense Range (`/phishing`)
- **Interactive Scenarios:** Beginner, Intermediate, and Advanced tiers covering Microsoft 365 credential lures, courier package tracking traps, Workday HR policy notices, and spoofed executive requests.
- **Address Bar & Domain Telemetry:** Highlights reply-to domain mismatches, subtle typosquatting, and obfuscated hyperlink targets.
- **Safe Simulated Destination Portals (`/phishing/<id>/portal`):** Sandboxed, educational login portals (M365, Workday, Courier) that never dispatch outbound requests or collect user credentials.
- **Forensic Indicator Checklist:** Trainees actively identify red flags before rendering a final verdict ("Report Phishing" vs "Mark Legitimate").

### 3. 🚩 CTF Mission Mode (`/ctf`)
- **Tactical Cyber Range:** Capture The Flag challenges spanning Log Analysis, Defensive Cryptography, Network Security, Digital Forensics, and Threat Identification.
- **Telemetry Artifact Inspection:** Real Apache web access logs, PowerShell `-EncodedCommand` persistence, Wireshark packet captures, and Caesar/ROT13 ciphers.
- **Progressive Hint Engine:** Multi-stage hints with automatic score penalties (-15 pts per hint).
- **Secure Flag Validation:** Cryptographically secured with SHA-256 constant-time hash comparison and anti-duplicate submission safeguards.

### 4. 🧠 AI Threat Analyst (`/ai-analyst`)
- **MITRE ATT&CK Mapping:** Classifies threats with official Technique IDs (e.g. `T1566.002 Spearphishing Link`), tactical stages, and CVSS v3.1 severity scores.
- **Deep Explanations:** Breaks down adversary psychology, organizational blast radius, and actionable technical/behavioral mitigations.
- **Decision Rationale:** Explicitly details why the correct action is appropriate and why alternative choices represent unacceptable risk or false alarms.
- **Custom Telemetry Inspector:** Allows trainees to paste arbitrary message text or headers to generate structured threat intelligence reports.

### 5. 🚨 Incident Response War Room (`/war-room`)
- **Branching Tactical Scenarios:** Multi-stage incident response exercises covering Ransomware Outbreaks, Executive Account Takeover, Stealth Data Exfiltration, and Supply Chain Compromises.
- **Dynamic Decision Branching:** Decisions alter containment scores, residual data loss penalties, and trigger consequences across subsequent stages.
- **NIST SP 800-61 Rev. 2 Debrief:** Generates comprehensive After-Action Reports with containment grading (A/B/C/D), timeline audit trails, and post-incident remediation workflows.

### 6. 🎖️ Skills, Badges & Certification Center (`/skills`)
- **5 Core Competency Domains:** Phishing Detection, Network Security, Incident Response, Digital Forensics, and Threat Intelligence.
- **Achievement Badges:** 8 milestone achievements (Flag Captor, Phish Buster, Incident Commander, Eagle Eye, Cyber Centurion, etc.).
- **Verifiable Completion Certificate (`/certificate`):** Cryptographically signed completion credential awarded upon satisfying qualification criteria (minimum 5 drills, &ge;50% accuracy).
- **Public Verification Gateway (`/verify-certificate/<cert_id>`):** Publicly accessible validation interface confirming credential authenticity and student telemetry.

### 7. 📡 Threat Intelligence Center (`/threat-intel`)
- **Authoritative Telemetry:** Live synchronization with CISA Known Exploited Vulnerabilities (KEV) and NIST National Vulnerability Database (NVD).
- **Offline Resilience:** Resilient local caching ensures zero downtime during network limits or API rate throttling.
- **Zero Hallucination Guarantee:** Never fabricates CVE identifiers, CVSS ratings, or threat advisories.

### 8. ⚙️ Admin & Trainer Command Console (`/admin`)
- **Role-Based Access Control (`@admin_required`):** Strictly protects administrative endpoints from trainee accounts.
- **Institutional Governance:** Aggregates organization-wide accuracy rates, composite risk profiles, and category vulnerability rates.
- **Drill Lifecycle Management:** Full CRUD control to author new drills, edit scenario content, and publish or retire drills.
- **User Administration:** Manage student privileges, inspect individual accuracy scores, and promote/demote roles.
- **Institutional CSV Exports:** 1-click downloads for Trainee Performance (`/admin/export/users`) and Complete Drill Logs (`/admin/export/drills`).

---

## 🚀 How to Run the Platform

### Option 1: 1-Click Launchers (Windows)
1. **Launch Server:** Double-click **`start_threat_vector.bat`** (opens [http://localhost:5000](http://localhost:5000) in your browser).
2. **Instant Public Web Link:** Double-click **`get_free_public_link.bat`** to generate a live HTTPS tunnel for mobile or remote testing.

### Option 2: Command Line
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run unit and integration tests
python test_all_enhancements.py

# 3. Start the application
python app.py
```
Open **[http://localhost:5000](http://localhost:5000)** in any web browser.

---

## 🔑 Default Accounts for Testing

| Role | Username | Password | Purpose |
| :--- | :--- | :--- | :--- |
| **Trainee (1-Click Demo)** | `demo` | `password123` | Immediate interactive access via the "Quick Demo Sign In" button |
| **Administrator / Trainer** | `admin` | `AdminPass2026!` | Access to the Trainer Command Console (`/admin`) and CSV exports |
| **Lead Developer** | `dhriti` | `password123` | Master account with Administrator privileges |

---

## 🧪 Automated Test Suite

A comprehensive test suite is provided in `test_all_enhancements.py`:
```bash
python test_all_enhancements.py
```
**Test Coverage:**
- `test_01_demo_login_and_dashboard`: Verifies login and total removal of static "Step X" markers.
- `test_02_personal_analytics_dashboard`: Validates trainee data isolation, streak tracking, and weakness calculations.
- `test_03_phishing_lab`: Tests email rendering, simulated login mockups, and indicator submission.
- `test_04_ctf_missions`: Verifies SHA-256 flag validation, hint penalties, and anti-duplicate protection.
- `test_05_ai_threat_analyst`: Asserts MITRE ATT&CK mapping, CVSS base scoring, and answer rationale.
- `test_06_incident_response_war_room`: Validates multi-stage branching decisions and after-action debriefing.
- `test_07_skills_and_certificate`: Verifies 5-domain skill matrix, badge evaluations, and certificate verification.
- `test_08_threat_intelligence_center`: Tests CISA KEV and NIST advisory filtering and caching.
- `test_09_rbac_trainee_cannot_access_admin`: Asserts that regular trainees receive an "Access Denied" redirect from `/admin`.
- `test_10_admin_console_and_csv_export`: Asserts administrator dashboard KPIs, drill lifecycle control, and valid CSV exports.

---

## 📜 Compliance & Standards
- **Incident Response:** Aligned with **NIST SP 800-61 Rev. 2** (Computer Security Incident Handling Guide).
- **Adversary Tactics:** Mapped to **MITRE ATT&CK Enterprise Matrix v14.1**.
- **Vulnerability Telemetry:** Sourced from **CISA Known Exploited Vulnerabilities (KEV)** and **NIST NVD**.
