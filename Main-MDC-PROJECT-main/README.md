# Threat Vector — AI Social Engineering Detection & Threat Defense Console

**Lead Developer:** Ms. Dhriti Gupta  
**Repository:** [https://github.com/Dhriti-001/Threat_Vector](https://github.com/Dhriti-001/Threat_Vector)  
**Deployment Target:** Vercel (Single-Link Consolidated Application)  
**Architecture:** Unified Single-Page Application (SPA) with Relative Routing & Client-Side Intelligence

---

## 🌟 Platform Overview & Unified Single-Link Architecture

**Threat Vector** is a consolidated, enterprise-grade cybersecurity awareness and threat defense platform running under a **single entry-point URL (`index.html`)** optimized for high-performance Vercel edge deployment.

The application features an interactive **Trainer Sign-In** entry point that captures the active trainer's username and dynamically displays `Active Trainer: <Logged_In_Username>` throughout the command console.

---

## 🛡️ The 8 Core Defense Modules

The application consolidates strictly the 8 allowed cybersecurity defense modules:

### 1. ⚡ Adaptive Simulation Drills
- Dynamic sequential simulation drills evaluating cognitive social-engineering vectors (Urgency, Authority Impersonation, Fake Links, Incentive Traps, Coercion).
- Real-time reaction stopwatch with cognitive timing insights (detects impulsive clicks under 4s).
- Deep Explainable AI (XAI) feedback banner, ground truth comparison, red-flag checklists, and actionable micro-lessons.

### 2. 🎣 Realistic Phishing Defense Range
- Interactive enterprise phishing email simulations across Beginner, Intermediate, and Advanced tiers.
- Raw email header inspection (From, Reply-To, Authentication-Results, and destination URL tracking).
- Safe simulated login portal sandbox previews (Microsoft 365, Workday SSO, Courier tracking fee, DocuSign OAuth consent).
- Multi-factor forensic indicator checklist and instant XP progression.

### 3. 🚩 CTF Tactical Missions
- Hands-on cyber defense challenges across Log Analysis (LOGS), Defensive Cryptography (CRYPTO), Network Security (NETSEC), Digital Forensics (FORENSICS), and Threat Identification (THREAT_ID).
- Live telemetry artifact viewer with real Apache access logs, Base64 beacons, DNS tunneling queries, and obfuscated PowerShell scripts.
- Constant-time cryptographic flag validation with progressive hint scoring.

### 4. 🚨 Incident Response War Room
- Branching multi-stage breach containment drills:
  - *Operation DarkRansom* (Active Workstation & Share Outbreak)
  - *Ghost Ingress* (Impossible Travel & Credential Stuffing)
  - *Silent Exfil* (Stealth Database Data Leak via Encrypted Tunnel)
  - *Supply Chain Poisoning* (Malicious CI/CD Dependency)
- Tactical decision branching with Security Impact (0-100%) tracking and Data Loss penalties.
- Comprehensive NIST SP 800-61 Rev. 2 Post-Incident Debriefs.

### 5. 🧠 AI Threat Analyst
- Official MITRE ATT&CK technique mapping (e.g., `T1566.002 Spearphishing Link`, `T1566.001 Attachment`, `T1078 Cloud Accounts`, `T1059.001 PowerShell`, `T1048 Exfiltration`).
- Adversary psychology profiling, organizational blast radius, and CVSS v3.1 severity scores.
- Interactive custom telemetry inspector generating structured AI diagnostic reports from pasted text or headers.

### 6. 🎖️ Skills, Badges & Verifiable Certification
- 5 core competency matrices with animated progress bars (Phishing Detection, Defensive Cryptography, Incident Response, Digital Forensics, Cognitive Vigilance).
- 8 milestone achievement badges (First Step 🎯, Eagle Eye 🦅, Phish Buster 🎣, Flag Captor 🚩, Master Cryptanalyst 🧩, Incident Commander 🚨, Daily Sentinel 🔥, Cyber Centurion 🛡️).
- Verifiable cryptographic Certificate of Competency generator.

### 7. 🏆 Global Defender Leaderboard
- HackerRank-style global rankings tracking points, accuracy %, completed drills, and speed bonuses.
- Dynamic highlighting of the active trainer in the rankings table.
- Trainee search and filtering.

### 8. 🔍 Real-Time AI Threat & Link Inspector
- Multi-factor heuristic scanning engine for suspicious URLs, email bodies, PDFs, and screenshots.
- Detects typosquatting, suspicious TLDs (`.top`, `.xyz`, `.biz`, `.cc`), double extensions (`.pdf.exe`), and credential harvesting hooks.
- Threat likelihood gauge (0-100%), detected red-flags list, and actionable security guidance.

---

## ⚡ Vercel Deployment Configuration

The application is pre-configured with `vercel.json` for single-link routing:

```json
{
  "version": 2,
  "cleanUrls": true,
  "trailingSlash": false,
  "rewrites": [
    { "source": "/(.*)", "destination": "/index.html" }
  ]
}
```

### Deploy to Vercel in 1 Click:
1. Push this repository to GitHub:
   ```bash
   git add .
   git commit -m "Consolidate into single-link Vercel app"
   git push origin main
   ```
2. Import the repository in [Vercel](https://vercel.com).
3. Deploy! The single live link will serve `index.html` across all routes.
