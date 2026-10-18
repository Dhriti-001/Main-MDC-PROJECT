"""
Threat Vector — Admin & Trainer Management Service
Provides role-based access control, drill lifecycle management (publish/retire),
institutional training oversight, and CSV performance export.
"""

import csv
import io
import json
from functools import wraps
from flask import session, flash, redirect, url_for

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please sign in to access the system.", "warning")
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash("Access Denied: Administrative privileges required.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def get_admin_metrics(db):
    """Computes aggregate institutional performance metrics."""
    total_users = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    total_attempts = db.execute("SELECT COUNT(*) FROM user_attempts").fetchone()[0]
    correct_attempts = db.execute("SELECT COUNT(*) FROM user_attempts WHERE is_correct = 1").fetchone()[0]
    org_accuracy = round((correct_attempts / total_attempts * 100), 1) if total_attempts > 0 else 0.0

    avg_risk = db.execute("SELECT AVG(composite_risk_score) FROM user_profiles").fetchone()[0] or 50.0

    # Category vulnerability breakdown
    cats = db.execute("""
        SELECT s.category_code, COUNT(a.id) as total, 
               SUM(CASE WHEN a.is_correct = 0 THEN 1 ELSE 0 END) as fails 
        FROM user_attempts a
        JOIN scenarios s ON a.scenario_id = s.id
        GROUP BY s.category_code
    """).fetchall()
    cat_breakdown = {}
    for c in cats:
        rate = round((c["fails"] / c["total"] * 100), 1) if c["total"] > 0 else 0.0
        cat_breakdown[c["category_code"]] = {"total": c["total"], "fails": c["fails"], "vuln_rate": rate}

    published_drills = db.execute("SELECT COUNT(*) FROM scenarios WHERE status = 'published'").fetchone()[0]
    retired_drills = db.execute("SELECT COUNT(*) FROM scenarios WHERE status = 'retired'").fetchone()[0]

    return {
        "total_users": total_users,
        "total_attempts": total_attempts,
        "org_accuracy": org_accuracy,
        "org_risk_score": round(avg_risk, 1),
        "cat_breakdown": cat_breakdown,
        "published_drills": published_drills,
        "retired_drills": retired_drills
    }

def get_all_scenarios_admin(db):
    rows = db.execute("""
        SELECT s.*, COUNT(a.id) as completion_count 
        FROM scenarios s
        LEFT JOIN user_attempts a ON s.id = a.scenario_id
        GROUP BY s.id
        ORDER BY s.id ASC
    """).fetchall()
    drills = []
    for r in rows:
        drills.append({
            "id": r["id"],
            "title": r["title"],
            "category_code": r["category_code"],
            "channel": r["channel"],
            "difficulty": r["difficulty"],
            "is_threat": bool(r["is_threat"]),
            "status": r["status"] if "status" in r.keys() else "published",
            "created_by": r["created_by"] if "created_by" in r.keys() else "system",
            "completion_count": r["completion_count"]
        })
    return drills

def get_all_users_admin(db):
    rows = db.execute("""
        SELECT u.id, u.username, u.full_name, u.role, u.xp, u.created_at,
               COUNT(a.id) as total_drills,
               COALESCE(SUM(CASE WHEN a.is_correct = 1 THEN 1 ELSE 0 END), 0) as correct_drills,
               COALESCE(p.composite_risk_score, 50.0) as risk_score
        FROM users u
        LEFT JOIN user_attempts a ON u.id = a.user_id
        LEFT JOIN user_profiles p ON u.id = p.user_id
        GROUP BY u.id
        ORDER BY u.id ASC
    """).fetchall()

    users = []
    for r in rows:
        total = r["total_drills"]
        correct = r["correct_drills"]
        acc = round((correct / total * 100), 1) if total > 0 else 0.0
        users.append({
            "id": r["id"],
            "username": r["username"],
            "full_name": r["full_name"],
            "role": r["role"] if r["role"] else "trainee",
            "xp": r["xp"] or 0,
            "created_at": r["created_at"],
            "total_drills": total,
            "accuracy_pct": acc,
            "risk_score": round(r["risk_score"], 1)
        })
    return users

def toggle_scenario_status(db, scenario_id):
    current = db.execute("SELECT status FROM scenarios WHERE id = ?", (scenario_id,)).fetchone()
    if not current:
        return False, "Scenario not found."
    new_status = 'retired' if current["status"] == 'published' else 'published'
    db.execute("UPDATE scenarios SET status = ? WHERE id = ?", (new_status, scenario_id))
    db.commit()
    return True, f"Drill status changed to '{new_status}'."

def toggle_user_role(db, target_user_id, current_admin_id):
    if int(target_user_id) == int(current_admin_id):
        return False, "Cannot modify your own administrator role."
    target = db.execute("SELECT role, username FROM users WHERE id = ?", (target_user_id,)).fetchone()
    if not target:
        return False, "User not found."
    new_role = 'admin' if target["role"] != 'admin' else 'trainee'
    db.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, target_user_id))
    db.commit()
    return True, f"User @{target['username']} role updated to '{new_role}'."

def export_training_report_csv(db, report_type="users"):
    output = io.StringIO()
    writer = csv.writer(output)

    if report_type == "users":
        writer.writerow(["User ID", "Username", "Full Name", "Role", "Total XP", "Drills Completed", "Accuracy (%)", "Risk Score", "Joined Date"])
        users = get_all_users_admin(db)
        for u in users:
            writer.writerow([u["id"], u["username"], u["full_name"], u["role"], u["xp"], u["total_drills"], u["accuracy_pct"], u["risk_score"], u["created_at"]])
    elif report_type == "drills":
        writer.writerow(["Attempt ID", "User ID", "Username", "Scenario ID", "Scenario Title", "Vector", "User Choice", "Ground Truth", "Is Correct", "Response Time (s)", "Timestamp"])
        rows = db.execute("""
            SELECT a.id, a.user_id, u.username, a.scenario_id, s.title, s.category_code,
                   a.user_choice, s.is_threat, a.is_correct, a.response_time_sec, a.timestamp
            FROM user_attempts a
            JOIN users u ON a.user_id = u.id
            JOIN scenarios s ON a.scenario_id = s.id
            ORDER BY a.id DESC
        """).fetchall()
        for r in rows:
            writer.writerow([
                r["id"], r["user_id"], r["username"], r["scenario_id"], r["title"], r["category_code"],
                "Threat" if r["user_choice"] else "Safe",
                "Threat" if r["is_threat"] else "Safe",
                "Correct" if r["is_correct"] else "Incorrect",
                r["response_time_sec"], r["timestamp"]
            ])

    output.seek(0)
    return output.getvalue()
