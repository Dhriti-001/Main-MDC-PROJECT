"""
Threat Vector — Incident Response War Room Engine
Manages branching scenario-based incident response exercises,
decision path tracking, security impact scoring, and post-incident debriefs.
"""

import json
import uuid
from datetime import datetime

def get_all_war_room_scenarios(db, user_id=None):
    rows = db.execute("SELECT * FROM war_room_scenarios WHERE is_active = 1 ORDER BY id ASC").fetchall()
    scenarios = []

    user_completed_map = {}
    if user_id:
        user_sessions = db.execute("""
            SELECT scenario_id, MAX(final_score) as best_score, status 
            FROM user_war_room_sessions 
            WHERE user_id = ? AND status = 'completed'
            GROUP BY scenario_id
        """, (user_id,)).fetchall()
        for s in user_sessions:
            user_completed_map[s["scenario_id"]] = s["best_score"]

    for r in rows:
        stages = json.loads(r["stages_json"]) if r["stages_json"] else []
        scenarios.append({
            "id": r["id"],
            "code": r["code"],
            "title": r["title"],
            "difficulty": r["difficulty"],
            "threat_actor": r["threat_actor"],
            "initial_briefing": r["initial_briefing"],
            "stages_count": len(stages),
            "best_score": user_completed_map.get(r["id"]),
            "is_completed": r["id"] in user_completed_map
        })
    return scenarios

def start_or_get_war_room_session(db, user_id, scenario_id):
    scenario = db.execute("SELECT * FROM war_room_scenarios WHERE id = ? AND is_active = 1", (scenario_id,)).fetchone()
    if not scenario:
        return None

    # Check for an active in-progress session for this scenario
    active_session = db.execute("""
        SELECT * FROM user_war_room_sessions 
        WHERE user_id = ? AND scenario_id = ? AND status = 'in_progress'
        ORDER BY started_at DESC LIMIT 1
    """, (user_id, scenario_id)).fetchone()

    if active_session:
        return active_session["session_id"]

    # Start fresh session
    new_session_id = f"IR-{uuid.uuid4().hex[:10].upper()}"
    db.execute("""
        INSERT INTO user_war_room_sessions (session_id, user_id, scenario_id, current_stage_idx, decision_history_json, containment_score, data_loss_score, final_score, status)
        VALUES (?, ?, ?, 0, '[]', 0, 0, 0, 'in_progress')
    """, (new_session_id, user_id, scenario_id))
    db.commit()
    return new_session_id

def get_war_room_session_state(db, session_id, user_id):
    sess = db.execute("""
        SELECT * FROM user_war_room_sessions 
        WHERE session_id = ? AND user_id = ?
    """, (session_id, user_id)).fetchone()
    if not sess:
        return None

    scenario = db.execute("SELECT * FROM war_room_scenarios WHERE id = ?", (sess["scenario_id"],)).fetchone()
    if not scenario:
        return None

    stages = json.loads(scenario["stages_json"]) if scenario["stages_json"] else []
    current_idx = sess["current_stage_idx"]
    history = json.loads(sess["decision_history_json"]) if sess["decision_history_json"] else []

    is_finished = (sess["status"] == "completed" or current_idx >= len(stages))
    current_stage = stages[current_idx] if current_idx < len(stages) else None

    return {
        "session": dict(sess),
        "scenario": dict(scenario),
        "stages": stages,
        "current_stage": current_stage,
        "current_stage_idx": current_idx,
        "total_stages": len(stages),
        "history": history,
        "is_finished": is_finished,
        "final_score": sess["final_score"]
    }

def record_war_room_decision(db, session_id, user_id, selected_option_id):
    state = get_war_room_session_state(db, session_id, user_id)
    if not state or state["is_finished"]:
        return False, "Session already finalized or invalid.", None

    current_stage = state["current_stage"]
    current_idx = state["current_stage_idx"]
    stages = state["stages"]

    # Find the chosen option
    chosen_opt = None
    for opt in current_stage["options"]:
        if opt["id"] == selected_option_id:
            chosen_opt = opt
            break

    if not chosen_opt:
        return False, "Invalid decision option selected.", None

    history = state["history"]
    history.append({
        "stage_idx": current_idx,
        "stage_title": current_stage["stage_title"],
        "chosen_id": chosen_opt["id"],
        "chosen_text": chosen_opt["text"],
        "consequence": chosen_opt["consequence"],
        "security_impact": chosen_opt["security_impact"],
        "data_loss_penalty": chosen_opt["data_loss_penalty"],
        "is_ideal": chosen_opt.get("is_ideal", False)
    })

    new_stage_idx = current_idx + 1
    new_containment = state["session"]["containment_score"] + chosen_opt["security_impact"]
    new_data_loss = state["session"]["data_loss_score"] + chosen_opt["data_loss_penalty"]

    is_now_finished = (new_stage_idx >= len(stages))
    badge_awarded = None

    if is_now_finished:
        final_score = int(new_containment / len(stages))
        db.execute("""
            UPDATE user_war_room_sessions 
            SET current_stage_idx = ?, decision_history_json = ?, containment_score = ?, data_loss_score = ?, final_score = ?, status = 'completed', completed_at = CURRENT_TIMESTAMP
            WHERE session_id = ? AND user_id = ?
        """, (new_stage_idx, json.dumps(history), new_containment, new_data_loss, final_score, session_id, user_id))

        # Award XP based on performance
        xp_awarded = max(50, int(final_score * 2.0))
        db.execute("UPDATE users SET xp = COALESCE(xp, 0) + ? WHERE id = ?", (xp_awarded, user_id))

        # Check INCIDENT_COMMANDER Badge if score >= 85
        if final_score >= 85:
            existing = db.execute("SELECT id FROM user_badges WHERE user_id = ? AND badge_code = 'INCIDENT_COMMANDER'", (user_id,)).fetchone()
            if not existing:
                db.execute("""
                    INSERT INTO user_badges (user_id, badge_code, badge_name, badge_desc, icon, category)
                    VALUES (?, 'INCIDENT_COMMANDER', 'Incident Commander', 'Successfully resolved a War Room incident with an A-Grade rating.', '🚨', 'IR')
                """, (user_id,))
                badge_awarded = "Incident Commander 🚨"
    else:
        db.execute("""
            UPDATE user_war_room_sessions 
            SET current_stage_idx = ?, decision_history_json = ?, containment_score = ?, data_loss_score = ?
            WHERE session_id = ? AND user_id = ?
        """, (new_stage_idx, json.dumps(history), new_containment, new_data_loss, session_id, user_id))

    db.commit()
    return True, "Decision recorded.", {
        "consequence": chosen_opt["consequence"],
        "is_ideal": chosen_opt["is_ideal"],
        "is_finished": is_now_finished,
        "badge_awarded": badge_awarded
    }
