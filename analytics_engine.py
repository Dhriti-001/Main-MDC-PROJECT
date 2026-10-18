"""
Threat Vector — Personal Analytics Engine
Calculates private, user-isolated cybersecurity training analytics,
XP progression, streak tracking, cognitive weakness diagnosis,
and drill recommendations from actual stored database records.
"""

import json
from datetime import datetime, timedelta

def get_user_level(xp):
    if xp >= 2500:
        return {"level": 5, "title": "Elite Cyber Guardian 🛡️", "next_xp": 5000, "progress_pct": 100}
    elif xp >= 1200:
        return {"level": 4, "title": "Senior Security Defender ⚔️", "next_xp": 2500, "progress_pct": int(((xp - 1200) / 1300) * 100)}
    elif xp >= 600:
        return {"level": 3, "title": "Cyber Threat Specialist 🔍", "next_xp": 1200, "progress_pct": int(((xp - 600) / 600) * 100)}
    elif xp >= 200:
        return {"level": 2, "title": "Security Analyst 📊", "next_xp": 600, "progress_pct": int(((xp - 200) / 400) * 100)}
    else:
        return {"level": 1, "title": "Security Cadet 🔰", "next_xp": 200, "progress_pct": int((xp / 200) * 100)}

def calculate_streak(attempts_timestamps):
    """Calculates active consecutive day streak from user attempt timestamps."""
    if not attempts_timestamps:
        return 0

    dates = set()
    for ts in attempts_timestamps:
        try:
            # Timestamp format usually '%Y-%m-%d %H:%M:%S' or '%Y-%m-%d %H:%M'
            dt = datetime.strptime(ts[:10], "%Y-%m-%d").date()
            dates.add(dt)
        except Exception:
            continue

    if not dates:
        return 0

    sorted_dates = sorted(dates, reverse=True)
    today = datetime.now().date()
    yesterday = today - timedelta(days=1)

    # Check if user was active today or yesterday
    if sorted_dates[0] not in (today, yesterday):
        return 0

    streak = 1
    current = sorted_dates[0]
    for d in sorted_dates[1:]:
        if d == current - timedelta(days=1):
            streak += 1
            current = d
        elif d == current:
            continue
        else:
            break
    return streak

def get_personal_analytics(db, user_id):
    """
    Computes exhaustive, private analytics for the specified user_id.
    Strictly isolated: queries filter by user_id = ?.
    """
    user = db.execute("SELECT id, username, full_name, created_at, role, xp FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return None

    # Fetch attempts
    attempts = db.execute("""
        SELECT a.id, a.scenario_id, a.user_choice, a.is_correct, a.response_time_sec,
               a.timestamp, s.title, s.category_code, s.is_threat, s.difficulty
        FROM user_attempts a
        JOIN scenarios s ON a.scenario_id = s.id
        WHERE a.user_id = ?
        ORDER BY a.id ASC
    """, (user_id,)).fetchall()

    # Fetch CTF completions
    ctf_completions = db.execute("""
        SELECT c.*, ch.title, ch.category, ch.difficulty, ch.points
        FROM user_ctf_completions c
        JOIN ctf_challenges ch ON c.challenge_id = ch.id
        WHERE c.user_id = ?
        ORDER BY c.completed_at DESC
    """, (user_id,)).fetchall()

    # Fetch Phishing attempts
    phish_attempts = db.execute("""
        SELECT p.*, s.title, s.difficulty, s.category
        FROM user_phishing_attempts p
        JOIN phishing_scenarios s ON p.scenario_id = s.id
        WHERE p.user_id = ?
        ORDER BY p.timestamp DESC
    """, (user_id,)).fetchall()

    # Fetch War Room sessions
    war_sessions = db.execute("""
        SELECT w.*, s.title, s.difficulty
        FROM user_war_room_sessions w
        JOIN war_room_scenarios s ON w.scenario_id = s.id
        WHERE w.user_id = ?
        ORDER BY w.started_at DESC
    """, (user_id,)).fetchall()

    # Fetch Badges
    badges = db.execute("""
        SELECT * FROM user_badges WHERE user_id = ? ORDER BY awarded_at DESC
    """, (user_id,)).fetchall()

    # Calculate Drill metrics
    total_drills = len(attempts)
    correct_drills = sum(1 for a in attempts if a["is_correct"])
    accuracy_pct = round((correct_drills / total_drills * 100), 1) if total_drills > 0 else 0.0
    avg_speed = round(sum(a["response_time_sec"] for a in attempts) / total_drills, 1) if total_drills > 0 else 0.0

    # Calculate XP dynamically from all activities
    drill_xp = (correct_drills * 50) + (total_drills * 15)
    ctf_xp = sum(c["xp_awarded"] for c in ctf_completions)
    phish_xp = sum(60 if p["is_correct"] else 15 for p in phish_attempts)
    war_xp = sum(int(w["final_score"] * 1.5) for w in war_sessions if w["status"] == 'completed')
    badge_xp = len(badges) * 75

    total_xp = (user["xp"] or 0) + drill_xp + ctf_xp + phish_xp + war_xp + badge_xp
    level_info = get_user_level(total_xp)

    # Calculate Streak
    all_timestamps = [a["timestamp"] for a in attempts] + [p["timestamp"] for p in phish_attempts] + [c["completed_at"] for c in ctf_completions]
    streak_days = calculate_streak(all_timestamps)

    # Category breakdown for Radar chart and Weakness detection
    CATEGORY_KEYS = ['URGENCY', 'AUTHORITY', 'FAKELINKS', 'INCENTIVE', 'COERCION']
    CATEGORY_LABELS = {
        'URGENCY': 'Urgency & Time Pressure',
        'AUTHORITY': 'Authority Impersonation',
        'FAKELINKS': 'Fake Links & Typosquatting',
        'INCENTIVE': 'Reward & Greed Traps',
        'COERCION': 'Fear & Coercion'
    }

    category_stats = {cat: {"total": 0, "failed": 0, "correct": 0, "vuln_pct": 0.0, "accuracy": 0.0, "accuracy_pct": 0.0, "label": CATEGORY_LABELS.get(cat, cat), "fails": 0} for cat in CATEGORY_KEYS}
    for a in attempts:
        cat = a["category_code"]
        if cat in category_stats:
            category_stats[cat]["total"] += 1
            if a["is_correct"]:
                category_stats[cat]["correct"] += 1
            else:
                category_stats[cat]["failed"] += 1
                category_stats[cat]["fails"] += 1

    weaknesses = []
    for cat, stats in category_stats.items():
        stats["label"] = CATEGORY_LABELS.get(cat, cat)
        if stats["total"] > 0:
            stats["vuln_pct"] = round((stats["failed"] / stats["total"]) * 100, 1)
            stats["accuracy_pct"] = round((stats["correct"] / stats["total"]) * 100, 1)
            stats["accuracy"] = stats["accuracy_pct"]
            if stats["vuln_pct"] >= 40.0:
                weaknesses.append({
                    "code": cat,
                    "name": CATEGORY_LABELS.get(cat, cat),
                    "vuln_pct": stats["vuln_pct"],
                    "drills_count": stats["total"],
                    "failed_count": stats["failed"]
                })
        else:
            stats["vuln_pct"] = 0.0
            stats["accuracy_pct"] = 0.0
            stats["accuracy"] = 0.0

    # Sort weaknesses descending by vulnerability percentage
    weaknesses.sort(key=lambda w: w["vuln_pct"], reverse=True)

    # Recommend drills tailored to weaknesses
    recommended_drills = []
    if weaknesses:
        top_weak_code = weaknesses[0]["code"]
        rec_rows = db.execute("""
            SELECT id, title, channel, category_code, difficulty
            FROM scenarios
            WHERE category_code = ? AND status = 'published'
            LIMIT 3
        """, (top_weak_code,)).fetchall()
        for r in rec_rows:
            recommended_drills.append(dict(r))
    if not recommended_drills:
        # Fallback recommendations if no acute weakness
        rec_rows = db.execute("SELECT id, title, channel, category_code, difficulty FROM scenarios LIMIT 3").fetchall()
        for r in rec_rows:
            recommended_drills.append(dict(r))

    # Chronological Progress Curve (Rolling Accuracy over attempts)
    progress_curve = []
    running_correct = 0
    for idx, a in enumerate(attempts, 1):
        if a["is_correct"]:
            running_correct += 1
        progress_curve.append({
            "drill_num": idx,
            "accuracy": round((running_correct / idx) * 100, 1),
            "response_time": a["response_time_sec"],
            "timestamp": a["timestamp"][:10] if a["timestamp"] else ""
        })

    # Recent Unified Activity Feed
    recent_activity = []
    for a in attempts[-6:]:
        recent_activity.append({
            "type": "DRILL",
            "icon": "⚡",
            "title": f"Simulation Drill: {a['title']}",
            "result": "Defended ✓" if a["is_correct"] else "Threat Missed ✗",
            "status_class": "badge-safe" if a["is_correct"] else "badge-threat",
            "timestamp": a["timestamp"]
        })
    for c in ctf_completions[:4]:
        recent_activity.append({
            "type": "CTF",
            "icon": "🚩",
            "title": f"Captured Flag: {c['title']}",
            "result": f"+{c['points_awarded']} pts",
            "status_class": "badge-ai",
            "timestamp": c["completed_at"]
        })
    for p in phish_attempts[:4]:
        recent_activity.append({
            "type": "PHISH",
            "icon": "🎣",
            "title": f"Phishing Lab: {p['title']}",
            "result": "Detected ✓" if p["is_correct"] else "Fell for Lure ✗",
            "status_class": "badge-safe" if p["is_correct"] else "badge-threat",
            "timestamp": p["timestamp"]
        })

    # Sort recent activity newest first
    recent_activity.sort(key=lambda x: x["timestamp"] or "", reverse=True)
    recent_activity = recent_activity[:8]

    return {
        "user": dict(user),
        "total_drills": total_drills,
        "correct_drills": correct_drills,
        "accuracy_pct": accuracy_pct,
        "avg_speed": avg_speed,
        "total_xp": total_xp,
        "level_info": level_info,
        "streak_days": streak_days,
        "category_stats": category_stats,
        "weaknesses": weaknesses,
        "recommended_drills": recommended_drills,
        "progress_curve": progress_curve,
        "recent_activity": recent_activity,
        "ctf_solved_count": len(ctf_completions),
        "phish_completed_count": len(phish_attempts),
        "war_room_count": len([w for w in war_sessions if w["status"] == 'completed']),
        "badges": [dict(b) for b in badges]
    }
