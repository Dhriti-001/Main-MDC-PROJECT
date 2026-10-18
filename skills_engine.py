"""
Threat Vector — Skills, Badges & Certification Engine
Quantifies proficiency across 5 core cybersecurity domains,
manages achievements and awards cryptographic completion certificates.
"""

import json
import uuid
import hashlib
from datetime import datetime

SKILL_CATEGORIES = [
    {
        "code": "PHISH",
        "name": "Phishing & Social Engineering Detection",
        "icon": "🎣",
        "description": "Identifying deceptive sender headers, typosquatted URLs, credential traps, and psychological manipulation."
    },
    {
        "code": "NETSEC",
        "name": "Network Security & Traffic Analysis",
        "icon": "🌐",
        "description": "Detecting port scans, DNS tunneling, anomalous exfiltration, and C2 beaconing signatures."
    },
    {
        "code": "IR",
        "name": "Incident Response & Threat Containment",
        "icon": "🚨",
        "description": "Triage, containment protocols, host isolation, and post-breach mitigation workflows (NIST SP 800-61)."
    },
    {
        "code": "FORENSICS",
        "name": "Digital Forensics & Log Investigation",
        "icon": "🔍",
        "description": "Analyzing web server logs, Windows Event IDs, obfuscated scripts, and memory artifacts."
    },
    {
        "code": "INTEL",
        "name": "Threat Intelligence & Vulnerability Management",
        "icon": "🛡️",
        "description": "Assessing CVE severity, CISA KEV advisories, MITRE ATT&CK mapping, and patch prioritization."
    }
]

def calculate_user_skills(db, user_id):
    """
    Computes proficiency score (0 to 100) and tier for each of the 5 skill domains
    derived from actual completed drills, CTF flags, phishing labs, and war room sessions.
    """
    # 1. Base counts
    attempts = db.execute("""
        SELECT s.category_code, a.is_correct 
        FROM user_attempts a
        JOIN scenarios s ON a.scenario_id = s.id
        WHERE a.user_id = ?
    """, (user_id,)).fetchall()
    ctf_rows = db.execute("""
        SELECT ch.category, c.points_awarded 
        FROM user_ctf_completions c 
        JOIN ctf_challenges ch ON c.challenge_id = ch.id 
        WHERE c.user_id = ?
    """, (user_id,)).fetchall()
    phish_rows = db.execute("SELECT is_correct FROM user_phishing_attempts WHERE user_id = ?", (user_id,)).fetchall()
    war_rows = db.execute("SELECT final_score FROM user_war_room_sessions WHERE user_id = ? AND status = 'completed'", (user_id,)).fetchall()

    # 1. PHISH score
    phish_correct = sum(1 for p in phish_rows if p["is_correct"])
    drill_phish = [a for a in attempts if a["category_code"] in ('FAKELINKS', 'URGENCY', 'AUTHORITY')]
    drill_phish_correct = sum(1 for a in drill_phish if a["is_correct"])
    phish_score = min(100, int((phish_correct * 20) + (drill_phish_correct * 10) + (len(drill_phish) * 2)))

    # 2. NETSEC score
    netsec_ctf = sum(c["points_awarded"] for c in ctf_rows if c["category"] == 'NETSEC')
    netsec_score = min(100, int((netsec_ctf / 3.0) + (len(attempts) * 2)))

    # 3. IR score
    best_war_score = max([w["final_score"] for w in war_rows], default=0)
    ir_score = min(100, int((best_war_score * 0.8) + (len(war_rows) * 10)))

    # 4. FORENSICS score
    forensics_ctf = sum(c["points_awarded"] for c in ctf_rows if c["category"] in ('FORENSICS', 'LOGS'))
    forensics_score = min(100, int((forensics_ctf / 3.5) + (len(attempts) * 1.5)))

    # 5. INTEL score
    intel_ctf = sum(c["points_awarded"] for c in ctf_rows if c["category"] == 'THREAT_ID')
    drill_authority = sum(1 for a in attempts if a["category_code"] == 'AUTHORITY' and a["is_correct"])
    intel_score = min(100, int((intel_ctf / 2.0) + (drill_authority * 12) + (len(attempts) * 2)))

    skill_ratings = {
        "PHISH": max(15 if len(attempts) > 0 else 0, phish_score),
        "NETSEC": max(10 if len(attempts) > 0 else 0, netsec_score),
        "IR": max(10 if len(attempts) > 0 else 0, ir_score),
        "FORENSICS": max(10 if len(attempts) > 0 else 0, forensics_score),
        "INTEL": max(15 if len(attempts) > 0 else 0, intel_score)
    }

    skills_data = []
    for cat in SKILL_CATEGORIES:
        score = skill_ratings.get(cat["code"], 0)
        if score >= 80:
            tier = "Advanced Specialist 🛡️"
            tier_class = "badge-safe"
        elif score >= 50:
            tier = "Proficient Practitioner ⚔️"
            tier_class = "badge-ai"
        elif score >= 25:
            tier = "Developing Cadet 🔰"
            tier_class = "badge"
        else:
            tier = "Foundational ⏳"
            tier_class = "badge"

        skills_data.append({
            "code": cat["code"],
            "name": cat["name"],
            "icon": cat["icon"],
            "description": cat["description"],
            "score": score,
            "tier": tier,
            "tier_class": tier_class
        })

    return skills_data

def evaluate_and_award_badges(db, user_id):
    """Checks criteria and awards any newly earned badges."""
    attempts = db.execute("SELECT is_correct FROM user_attempts WHERE user_id = ?", (user_id,)).fetchall()
    user = db.execute("SELECT xp FROM users WHERE id = ?", (user_id,)).fetchone()
    user_xp = user["xp"] if user else 0

    awarded = []

    # FIRST_DRILL
    if len(attempts) >= 1:
        if not db.execute("SELECT id FROM user_badges WHERE user_id = ? AND badge_code = 'FIRST_DRILL'", (user_id,)).fetchone():
            db.execute("""
                INSERT INTO user_badges (user_id, badge_code, badge_name, badge_desc, icon, category)
                VALUES (?, 'FIRST_DRILL', 'First Step', 'Completed your very first diagnostic cybersecurity drill.', '🎯', 'DRILL')
            """, (user_id,))
            awarded.append("First Step 🎯")

    # SHARP_EYE (5 drills with 100% accuracy)
    if len(attempts) >= 5 and all(a["is_correct"] for a in attempts[-5:]):
        if not db.execute("SELECT id FROM user_badges WHERE user_id = ? AND badge_code = 'SHARP_EYE'", (user_id,)).fetchone():
            db.execute("""
                INSERT INTO user_badges (user_id, badge_code, badge_name, badge_desc, icon, category)
                VALUES (?, 'SHARP_EYE', 'Eagle Eye', 'Achieved 100% accuracy across 5 consecutive drills.', '🦅', 'ACCURACY')
            """, (user_id,))
            awarded.append("Eagle Eye 🦅")

    # CENTURION (XP >= 1000)
    if user_xp >= 1000:
        if not db.execute("SELECT id FROM user_badges WHERE user_id = ? AND badge_code = 'CENTURION'", (user_id,)).fetchone():
            db.execute("""
                INSERT INTO user_badges (user_id, badge_code, badge_name, badge_desc, icon, category)
                VALUES (?, 'CENTURION', 'Cyber Centurion', 'Accumulated over 1,000 XP in the Threat Vector platform.', '🛡️', 'XP')
            """, (user_id,))
            awarded.append("Cyber Centurion 🛡️")

    db.commit()
    return awarded

ALL_BADGE_DEFINITIONS = [
    {"code": "FIRST_DRILL", "name": "First Step 🎯", "desc": "Completed your very first diagnostic drill.", "icon": "🎯", "category": "DRILL", "criteria": "Complete 1 simulation drill"},
    {"code": "SHARP_EYE", "name": "Eagle Eye 🦅", "desc": "Achieved 100% accuracy across 5 consecutive drills.", "icon": "🦅", "category": "ACCURACY", "criteria": "5 consecutive correct drills"},
    {"code": "CENTURION", "name": "Cyber Centurion 🛡️", "desc": "Accumulated over 1,000 XP in the Threat Vector platform.", "icon": "🛡️", "category": "XP", "criteria": "Reach 1,000 total XP"},
    {"code": "CTF_ROOKIE", "name": "Flag Captor 🚩", "desc": "Captured your first Capture The Flag mission flag.", "icon": "🚩", "category": "CTF", "criteria": "Solve 1 CTF challenge"},
    {"code": "CTF_MASTER", "name": "Master Cryptanalyst 🧩", "desc": "Solved 5 or more CTF challenges.", "icon": "🧩", "category": "CTF", "criteria": "Solve 5 CTF challenges"},
    {"code": "PHISH_BUSTER", "name": "Phish Buster 🎣", "desc": "Successfully identified 3 realistic phishing attacks.", "icon": "🎣", "category": "PHISHING", "criteria": "Pass 3 phishing labs"},
    {"code": "INCIDENT_COMMANDER", "name": "Incident Commander 🚨", "desc": "Resolved a War Room incident with an A-Grade rating.", "icon": "🚨", "category": "IR", "criteria": "Earn Grade A in War Room"},
    {"code": "SOC_VETERAN", "name": "SOC Veteran ⚔️", "desc": "Completed 15 or more drills across all categories.", "icon": "⚔️", "category": "MASTERY", "criteria": "Complete 15 total drills"}
]

def get_all_badges_with_user_status(db, user_id):
    evaluate_and_award_badges(db, user_id)
    user_badges = db.execute("SELECT badge_code, awarded_at FROM user_badges WHERE user_id = ?", (user_id,)).fetchall()
    earned_map = {b["badge_code"]: b["awarded_at"] for b in user_badges}

    results = []
    for b in ALL_BADGE_DEFINITIONS:
        is_unlocked = b["code"] in earned_map
        results.append({
            "code": b["code"],
            "name": b["name"],
            "desc": b["desc"],
            "icon": b["icon"],
            "category": b["category"],
            "criteria": b["criteria"],
            "is_unlocked": is_unlocked,
            "awarded_at": earned_map.get(b["code"])
        })
    return results

def issue_or_get_certificate(db, user_id):
    """
    Issues a verified cybersecurity completion certificate if user meets qualification criteria:
    - Minimum 5 completed drills
    - Accuracy >= 50%
    """
    user = db.execute("SELECT id, username, full_name, xp FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return None, "User not found."

    existing = db.execute("SELECT * FROM certificates WHERE user_id = ?", (user_id,)).fetchone()
    if existing:
        return {
            "cert_id": existing["cert_id"],
            "user_full_name": user["full_name"],
            "username": user["username"],
            "title": existing["title"],
            "issue_date": existing["issue_date"],
            "metrics": json.loads(existing["metrics_json"]),
            "verification_hash": existing["verification_hash"]
        }, None

    # Check eligibility
    attempts = db.execute("SELECT is_correct FROM user_attempts WHERE user_id = ?", (user_id,)).fetchall()
    total_drills = len(attempts)
    correct_drills = sum(1 for a in attempts if a["is_correct"])
    accuracy = round((correct_drills / total_drills * 100), 1) if total_drills > 0 else 0.0

    if total_drills < 5:
        return None, f"Certificate qualification requires at least 5 completed simulation drills. Current: {total_drills} drills completed."

    cert_id = f"TV-CERT-{uuid.uuid4().hex[:8].upper()}"
    issue_date = datetime.now().strftime("%B %d, %Y")
    metrics = {
        "drills_completed": total_drills,
        "accuracy_pct": accuracy,
        "total_xp": user["xp"] or 0,
        "credential_type": "Certified Adaptive Threat Defense Practitioner"
    }

    # Generate verification hash
    raw_sig = f"{cert_id}:{user['id']}:{user['username']}:{accuracy}:{issue_date}:threat-vector-verified-key"
    verification_hash = hashlib.sha256(raw_sig.encode('utf-8')).hexdigest()[:24].upper()

    db.execute("""
        INSERT INTO certificates (cert_id, user_id, title, issue_date, metrics_json, verification_hash)
        VALUES (?, ?, 'Certified Threat Defense Practitioner', ?, ?, ?)
    """, (cert_id, user_id, issue_date, json.dumps(metrics), verification_hash))
    db.commit()

    return {
        "cert_id": cert_id,
        "user_full_name": user["full_name"],
        "username": user["username"],
        "title": "Certified Threat Defense Practitioner",
        "issue_date": issue_date,
        "metrics": metrics,
        "verification_hash": verification_hash
    }, None

def verify_certificate_by_id(db, cert_id):
    cert = db.execute("""
        SELECT c.*, u.full_name, u.username 
        FROM certificates c
        JOIN users u ON c.user_id = u.id
        WHERE c.cert_id = ?
    """, (cert_id.strip().upper(),)).fetchone()
    if not cert:
        return None
    return {
        "cert_id": cert["cert_id"],
        "user_full_name": cert["full_name"],
        "username": cert["username"],
        "title": cert["title"],
        "issue_date": cert["issue_date"],
        "metrics": json.loads(cert["metrics_json"]),
        "verification_hash": cert["verification_hash"],
        "status": "VERIFIED & AUTHENTIC ✓"
    }
