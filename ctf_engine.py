"""
Threat Vector — CTF Mission Mode Engine
Handles Capture the Flag challenge retrieval, hint unlocking with score penalties,
cryptographically secure flag validation, anti-duplicate protection, and XP award.
"""

import json
import hashlib
import hmac

def hash_flag(flag_str):
    return hashlib.sha256(flag_str.strip().encode('utf-8')).hexdigest()

def get_all_ctf_challenges(db, user_id=None, category=None):
    query = "SELECT * FROM ctf_challenges WHERE is_active = 1"
    params = []
    if category and category.upper() != 'ALL':
        query += " AND category = ?"
        params.append(category.upper())
    query += " ORDER BY points ASC, id ASC"

    rows = db.execute(query, params).fetchall()
    
    completed_ids = set()
    if user_id:
        completed_rows = db.execute("SELECT challenge_id FROM user_ctf_completions WHERE user_id = ?", (user_id,)).fetchall()
        completed_ids = {r["challenge_id"] for r in completed_rows}

    challenges = []
    for r in rows:
        hints = json.loads(r["hints_json"]) if r["hints_json"] else []
        challenges.append({
            "id": r["id"],
            "title": r["title"],
            "category": r["category"],
            "difficulty": r["difficulty"],
            "points": r["points"],
            "xp_reward": r["xp_reward"],
            "description": r["description"],
            "scenario_context": r["scenario_context"],
            "artifact_data": r["artifact_data"],
            "hints_count": len(hints),
            "is_solved": r["id"] in completed_ids
        })
    return challenges

def get_ctf_challenge_by_id(db, challenge_id, user_id=None):
    r = db.execute("SELECT * FROM ctf_challenges WHERE id = ? AND is_active = 1", (challenge_id,)).fetchone()
    if not r:
        return None

    is_solved = False
    solved_record = None
    if user_id:
        solved_record = db.execute("""
            SELECT * FROM user_ctf_completions 
            WHERE user_id = ? AND challenge_id = ?
        """, (user_id, challenge_id)).fetchone()
        if solved_record:
            is_solved = True

    hints = json.loads(r["hints_json"]) if r["hints_json"] else []

    return {
        "id": r["id"],
        "title": r["title"],
        "category": r["category"],
        "difficulty": r["difficulty"],
        "points": r["points"],
        "xp_reward": r["xp_reward"],
        "description": r["description"],
        "scenario_context": r["scenario_context"],
        "artifact_data": r["artifact_data"],
        "hints": hints,
        "is_solved": is_solved,
        "solved_at": solved_record["completed_at"] if solved_record else None,
        "points_awarded": solved_record["points_awarded"] if solved_record else r["points"]
    }

def validate_ctf_flag(db, user_id, challenge_id, submitted_flag, hints_used=0):
    """
    Validates submitted flag securely.
    Guarantees:
    - Secure constant-time hash comparison
    - Anti-duplicate submission protection
    - Proper point and XP attribution
    - Badge unlocking
    """
    if not submitted_flag or not submitted_flag.strip():
        return False, "Please enter a non-empty flag.", 0

    challenge = db.execute("SELECT * FROM ctf_challenges WHERE id = ? AND is_active = 1", (challenge_id,)).fetchone()
    if not challenge:
        return False, "Challenge not found.", 0

    # Check if already solved by this user
    existing = db.execute("""
        SELECT id FROM user_ctf_completions 
        WHERE user_id = ? AND challenge_id = ?
    """, (user_id, challenge_id)).fetchone()
    if existing:
        return False, "You have already captured this flag! Duplicate submissions do not award extra points.", 0

    submitted_hash = hash_flag(submitted_flag)
    target_hash = challenge["flag_hash"]

    # Constant time comparison to prevent timing attacks
    if not hmac.compare_digest(submitted_hash, target_hash):
        return False, "Incorrect flag. Re-examine the telemetry artifacts and hints.", 0

    # Calculate final points (penalty for hints used: 15 pts per hint, minimum 50% points)
    base_points = challenge["points"]
    penalty = hints_used * 15
    final_points = max(int(base_points * 0.5), base_points - penalty)
    xp_awarded = challenge["xp_reward"]

    # Record completion
    db.execute("""
        INSERT INTO user_ctf_completions (user_id, challenge_id, points_awarded, xp_awarded, hints_used)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, challenge_id, final_points, xp_awarded, hints_used))

    # Update user XP
    db.execute("UPDATE users SET xp = COALESCE(xp, 0) + ? WHERE id = ?", (xp_awarded, user_id))

    # Check Badges:
    # 1. CTF_ROOKIE (first flag)
    # 2. CTF_MASTER (5 flags)
    total_solved = db.execute("SELECT COUNT(*) FROM user_ctf_completions WHERE user_id = ?", (user_id,)).fetchone()[0]
    
    badge_awarded = None
    if total_solved >= 1:
        has_rookie = db.execute("SELECT id FROM user_badges WHERE user_id = ? AND badge_code = 'CTF_ROOKIE'", (user_id,)).fetchone()
        if not has_rookie:
            db.execute("""
                INSERT INTO user_badges (user_id, badge_code, badge_name, badge_desc, icon, category)
                VALUES (?, 'CTF_ROOKIE', 'Flag Captor', 'Captured your first Capture The Flag mission flag.', '🚩', 'CTF')
            """, (user_id,))
            badge_awarded = "Flag Captor 🚩"

    if total_solved >= 5:
        has_master = db.execute("SELECT id FROM user_badges WHERE user_id = ? AND badge_code = 'CTF_MASTER'", (user_id,)).fetchone()
        if not has_master:
            db.execute("""
                INSERT INTO user_badges (user_id, badge_code, badge_name, badge_desc, icon, category)
                VALUES (?, 'CTF_MASTER', 'Master Cryptanalyst', 'Solved 5 or more CTF challenges across log analysis and cryptography.', '🧩', 'CTF')
            """, (user_id,))
            badge_awarded = "Master Cryptanalyst 🧩"

    db.commit()
    msg = f"Flag Verified! +{final_points} points and +{xp_awarded} XP awarded."
    if badge_awarded:
        msg += f" Achievement Unlocked: {badge_awarded}!"
    return True, msg, final_points
