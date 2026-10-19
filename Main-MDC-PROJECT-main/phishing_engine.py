"""
Threat Vector — Realistic Phishing Simulation Engine
Processes interactive phishing scenarios, simulated login portal previews,
red-flag indicator matching, and instant educational diagnostics.
"""

import json
from datetime import datetime

def get_all_phishing_scenarios(db, user_id=None, difficulty=None):
    query = "SELECT * FROM phishing_scenarios WHERE is_active = 1"
    params = []
    if difficulty:
        query += " AND difficulty = ?"
        params.append(difficulty)
    query += " ORDER BY id ASC"

    rows = db.execute(query, params).fetchall()
    scenarios = []

    # Get user completed scenarios if logged in
    completed_map = {}
    if user_id:
        user_attempts = db.execute("""
            SELECT scenario_id, is_correct, timestamp 
            FROM user_phishing_attempts 
            WHERE user_id = ?
        """, (user_id,)).fetchall()
        for ua in user_attempts:
            completed_map[ua["scenario_id"]] = bool(ua["is_correct"])

    for r in rows:
        scenarios.append({
            "id": r["id"],
            "title": r["title"],
            "difficulty": r["difficulty"],
            "category": r["category"],
            "sender_name": r["sender_name"],
            "sender_email": r["sender_email"],
            "reply_to": r["reply_to"],
            "subject": r["subject"],
            "body_html": r["body_html"],
            "simulated_url": r["simulated_url"],
            "display_link_text": r["display_link_text"],
            "fake_portal_type": r["fake_portal_type"],
            "fake_portal_title": r["fake_portal_title"],
            "attachment_name": r["attachment_name"],
            "attachment_type": r["attachment_type"],
            "attachment_risk": r["attachment_risk"],
            "is_phishing": bool(r["is_phishing"]),
            "red_flags": json.loads(r["red_flags_json"]) if r["red_flags_json"] else [],
            "indicator_options": json.loads(r["indicator_options_json"]) if r["indicator_options_json"] else [],
            "user_status": "Passed ✓" if completed_map.get(r["id"]) is True else ("Failed ✗" if r["id"] in completed_map else "Unattempted")
        })
    return scenarios

def get_phishing_scenario_by_id(db, scenario_id):
    r = db.execute("SELECT * FROM phishing_scenarios WHERE id = ? AND is_active = 1", (scenario_id,)).fetchone()
    if not r:
        return None
    return {
        "id": r["id"],
        "title": r["title"],
        "difficulty": r["difficulty"],
        "category": r["category"],
        "sender_name": r["sender_name"],
        "sender_email": r["sender_email"],
        "reply_to": r["reply_to"],
        "subject": r["subject"],
        "body_html": r["body_html"],
        "simulated_url": r["simulated_url"],
        "display_link_text": r["display_link_text"],
        "fake_portal_type": r["fake_portal_type"],
        "fake_portal_title": r["fake_portal_title"],
        "attachment_name": r["attachment_name"],
        "attachment_type": r["attachment_type"],
        "attachment_risk": r["attachment_risk"],
        "is_phishing": bool(r["is_phishing"]),
        "red_flags": json.loads(r["red_flags_json"]) if r["red_flags_json"] else [],
        "indicator_options": json.loads(r["indicator_options_json"]) if r["indicator_options_json"] else [],
        "explanation": r["explanation"]
    }

def evaluate_phishing_attempt(db, user_id, scenario_id, user_verdict_str, selected_indicators, response_time_sec):
    scenario = get_phishing_scenario_by_id(db, scenario_id)
    if not scenario:
        return None

    # user_verdict_str: 'phishing' or 'safe'
    user_verdict = True if user_verdict_str == 'phishing' else False
    is_correct = (user_verdict == scenario["is_phishing"])

    # Record attempt
    db.execute("""
        INSERT INTO user_phishing_attempts (user_id, scenario_id, user_verdict, is_correct, identified_indicators_json, response_time_sec)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user_id, scenario_id, 1 if user_verdict else 0, 1 if is_correct else 0, json.dumps(selected_indicators), response_time_sec))
    
    # Award XP
    xp_earned = 75 if is_correct else 20
    db.execute("UPDATE users SET xp = COALESCE(xp, 0) + ? WHERE id = ?", (xp_earned, user_id))

    # Badge check: PHISH_BUSTER (3 correct phishing evaluations)
    correct_count = db.execute("""
        SELECT COUNT(*) FROM user_phishing_attempts 
        WHERE user_id = ? AND is_correct = 1
    """, (user_id,)).fetchone()[0]

    badge_awarded = None
    if correct_count >= 3:
        existing = db.execute("SELECT id FROM user_badges WHERE user_id = ? AND badge_code = 'PHISH_BUSTER'", (user_id,)).fetchone()
        if not existing:
            db.execute("""
                INSERT INTO user_badges (user_id, badge_code, badge_name, badge_desc, icon, category)
                VALUES (?, 'PHISH_BUSTER', 'Phish Buster', 'Successfully identified 3 realistic phishing attacks in the Phishing Lab.', '🎣', 'PHISHING')
            """, (user_id,))
            badge_awarded = "Phish Buster 🎣"

    db.commit()

    # Determine feedback verdict banner
    if is_correct:
        if scenario["is_phishing"]:
            verdict_badge = "Excellent Detection! Phishing Threat Identified 🛡️"
            alert_class = "success"
        else:
            verdict_badge = "Accurate Assessment! Legitimate Email Recognized 🛡️"
            alert_class = "success"
    else:
        if scenario["is_phishing"]:
            verdict_badge = "Phishing Trap Missed! Credential Compromise Simulated 🚨"
            alert_class = "danger"
        else:
            verdict_badge = "False Alarm! Legitimate Communication Flagged ⚠️"
            alert_class = "warning"

    return {
        "scenario": scenario,
        "user_verdict": user_verdict,
        "is_correct": is_correct,
        "verdict_badge": verdict_badge,
        "alert_class": alert_class,
        "xp_earned": xp_earned,
        "badge_awarded": badge_awarded,
        "response_time": response_time_sec,
        "selected_indicators": selected_indicators,
        "actual_red_flags": scenario["red_flags"],
        "explanation": scenario["explanation"]
    }
