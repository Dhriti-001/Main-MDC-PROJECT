import os
import sqlite3
import json
from flask import g
from werkzeug.security import generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'threat_vector.db')
if not os.path.exists(DB_PATH):
    parent_db = os.path.join(os.path.dirname(BASE_DIR), 'threat_vector.db')
    if os.path.exists(parent_db):
        DB_PATH = parent_db

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

def get_direct_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def ensure_tables():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    cur = conn.cursor()

    # 1. CORE EXISTING TABLES
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        full_name TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        password_hash TEXT DEFAULT ''
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        icon TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS scenarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        category_code TEXT NOT NULL,
        channel TEXT NOT NULL DEFAULT 'email',
        title TEXT NOT NULL,
        sender TEXT NOT NULL,
        sender_name TEXT,
        subject TEXT,
        body TEXT NOT NULL,
        is_threat BOOLEAN NOT NULL,
        difficulty TEXT NOT NULL DEFAULT 'medium',
        red_flags TEXT NOT NULL,
        explanation TEXT NOT NULL,
        micro_lesson TEXT NOT NULL,
        FOREIGN KEY(category_code) REFERENCES categories(code)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS user_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        scenario_id INTEGER NOT NULL,
        user_choice BOOLEAN NOT NULL,
        is_correct BOOLEAN NOT NULL,
        response_time_sec REAL NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(scenario_id) REFERENCES scenarios(id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS user_profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL,
        composite_risk_score REAL DEFAULT 50.0,
        primary_weakness TEXT DEFAULT 'Baseline (Not yet evaluated)',
        category_stats TEXT DEFAULT '{}',
        total_tests INTEGER DEFAULT 0,
        accuracy_pct REAL DEFAULT 0.0,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    # 2. SAFE COLUMN MIGRATIONS ON EXISTING TABLES
    user_cols = [c[1] for c in cur.execute("PRAGMA table_info(users)").fetchall()]
    if 'role' not in user_cols:
        cur.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'trainee'")
    if 'xp' not in user_cols:
        cur.execute("ALTER TABLE users ADD COLUMN xp INTEGER DEFAULT 0")
    if 'streak_days' not in user_cols:
        cur.execute("ALTER TABLE users ADD COLUMN streak_days INTEGER DEFAULT 0")
    if 'last_active_date' not in user_cols:
        cur.execute("ALTER TABLE users ADD COLUMN last_active_date TEXT DEFAULT ''")

    scenario_cols = [c[1] for c in cur.execute("PRAGMA table_info(scenarios)").fetchall()]
    if 'status' not in scenario_cols:
        cur.execute("ALTER TABLE scenarios ADD COLUMN status TEXT DEFAULT 'published'")
    if 'created_by' not in scenario_cols:
        cur.execute("ALTER TABLE scenarios ADD COLUMN created_by TEXT DEFAULT 'system'")

    # 3. NEW FEATURE TABLES: CTF MISSION MODE
    cur.execute("""
    CREATE TABLE IF NOT EXISTS ctf_challenges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        difficulty TEXT NOT NULL,
        points INTEGER NOT NULL DEFAULT 100,
        xp_reward INTEGER NOT NULL DEFAULT 150,
        description TEXT NOT NULL,
        scenario_context TEXT NOT NULL,
        artifact_data TEXT DEFAULT '',
        hints_json TEXT DEFAULT '[]',
        flag_hash TEXT NOT NULL,
        flag_plain TEXT DEFAULT '',
        is_active BOOLEAN NOT NULL DEFAULT 1
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS user_ctf_completions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        challenge_id INTEGER NOT NULL,
        points_awarded INTEGER NOT NULL,
        xp_awarded INTEGER NOT NULL,
        hints_used INTEGER DEFAULT 0,
        completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, challenge_id),
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(challenge_id) REFERENCES ctf_challenges(id)
    )
    """)

    # 4. NEW FEATURE TABLES: REALISTIC PHISHING LAB
    cur.execute("""
    CREATE TABLE IF NOT EXISTS phishing_scenarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        difficulty TEXT NOT NULL,
        category TEXT NOT NULL,
        sender_name TEXT NOT NULL,
        sender_email TEXT NOT NULL,
        reply_to TEXT DEFAULT '',
        subject TEXT NOT NULL,
        body_html TEXT NOT NULL,
        simulated_url TEXT NOT NULL,
        display_link_text TEXT NOT NULL,
        fake_portal_type TEXT DEFAULT '',
        fake_portal_title TEXT DEFAULT '',
        attachment_name TEXT DEFAULT '',
        attachment_type TEXT DEFAULT '',
        attachment_risk TEXT DEFAULT '',
        is_phishing BOOLEAN NOT NULL DEFAULT 1,
        red_flags_json TEXT NOT NULL,
        indicator_options_json TEXT NOT NULL,
        explanation TEXT NOT NULL,
        is_active BOOLEAN NOT NULL DEFAULT 1
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS user_phishing_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        scenario_id INTEGER NOT NULL,
        user_verdict BOOLEAN NOT NULL,
        is_correct BOOLEAN NOT NULL,
        identified_indicators_json TEXT DEFAULT '[]',
        response_time_sec REAL NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(scenario_id) REFERENCES phishing_scenarios(id)
    )
    """)

    # 5. NEW FEATURE TABLES: INCIDENT RESPONSE WAR ROOM
    cur.execute("""
    CREATE TABLE IF NOT EXISTS war_room_scenarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        difficulty TEXT NOT NULL,
        threat_actor TEXT NOT NULL,
        initial_briefing TEXT NOT NULL,
        stages_json TEXT NOT NULL,
        is_active BOOLEAN NOT NULL DEFAULT 1
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS user_war_room_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT UNIQUE NOT NULL,
        user_id INTEGER NOT NULL,
        scenario_id INTEGER NOT NULL,
        current_stage_idx INTEGER DEFAULT 0,
        decision_history_json TEXT DEFAULT '[]',
        containment_score INTEGER DEFAULT 0,
        data_loss_score INTEGER DEFAULT 0,
        speed_score INTEGER DEFAULT 0,
        final_score INTEGER DEFAULT 0,
        status TEXT DEFAULT 'in_progress',
        started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(scenario_id) REFERENCES war_room_scenarios(id)
    )
    """)

    # 6. NEW FEATURE TABLES: BADGES & CERTIFICATES
    cur.execute("""
    CREATE TABLE IF NOT EXISTS user_badges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        badge_code TEXT NOT NULL,
        badge_name TEXT NOT NULL,
        badge_desc TEXT NOT NULL,
        icon TEXT NOT NULL,
        category TEXT NOT NULL,
        awarded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, badge_code),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS certificates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cert_id TEXT UNIQUE NOT NULL,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        issue_date TEXT NOT NULL,
        metrics_json TEXT NOT NULL,
        verification_hash TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    # 7. NEW FEATURE TABLES: THREAT INTEL CACHE
    cur.execute("""
    CREATE TABLE IF NOT EXISTS threat_intel_cache (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        cvss_score REAL DEFAULT 0.0,
        affected_vendor TEXT NOT NULL,
        affected_product TEXT NOT NULL,
        summary TEXT NOT NULL,
        mitigation TEXT NOT NULL,
        source_url TEXT NOT NULL,
        source_name TEXT NOT NULL DEFAULT 'CISA KEV / NVD',
        published_date TEXT NOT NULL,
        cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # 8. PERFORMANCE INDEXES
    cur.execute("CREATE INDEX IF NOT EXISTS idx_user_attempts_user_id ON user_attempts(user_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ctf_completions_user ON user_ctf_completions(user_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_phishing_attempts_user ON user_phishing_attempts(user_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_user_badges_user ON user_badges(user_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_certificates_cert_id ON certificates(cert_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_intel_cve ON threat_intel_cache(cve_id)")

    # 9. SEED ENHANCEMENT DATA IF EMPTY
    try:
        from seed_data import (
            CTF_CHALLENGES, PHISHING_SCENARIOS, WAR_ROOM_SCENARIOS,
            THREAT_INTEL_INITIAL
        )

        ctf_count = cur.execute("SELECT COUNT(*) FROM ctf_challenges").fetchone()[0]
        if ctf_count == 0:
            for c in CTF_CHALLENGES:
                cur.execute("""
                    INSERT INTO ctf_challenges (title, category, difficulty, points, xp_reward, description, scenario_context, artifact_data, hints_json, flag_hash, flag_plain, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                """, (c["title"], c["category"], c["difficulty"], c["points"], c["xp_reward"], c["description"], c["scenario_context"], c["artifact_data"], c["hints_json"], c["flag_hash"], c["flag_plain"]))

        phish_count = cur.execute("SELECT COUNT(*) FROM phishing_scenarios").fetchone()[0]
        if phish_count == 0:
            for p in PHISHING_SCENARIOS:
                cur.execute("""
                    INSERT INTO phishing_scenarios (title, difficulty, category, sender_name, sender_email, reply_to, subject, body_html, simulated_url, display_link_text, fake_portal_type, fake_portal_title, attachment_name, attachment_type, attachment_risk, is_phishing, red_flags_json, indicator_options_json, explanation, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                """, (
                    p["title"], p["difficulty"], p["category"], p["sender_name"], p["sender_email"],
                    p.get("reply_to", ""), p["subject"], p["body_html"], p["simulated_url"],
                    p["display_link_text"], p.get("fake_portal_type", ""), p.get("fake_portal_title", ""),
                    p.get("attachment_name", ""), p.get("attachment_type", ""), p.get("attachment_risk", ""),
                    1 if p["is_phishing"] else 0, p["red_flags_json"], p["indicator_options_json"], p["explanation"]
                ))

        war_count = cur.execute("SELECT COUNT(*) FROM war_room_scenarios").fetchone()[0]
        if war_count == 0:
            for w in WAR_ROOM_SCENARIOS:
                cur.execute("""
                    INSERT INTO war_room_scenarios (code, title, difficulty, threat_actor, initial_briefing, stages_json, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, 1)
                """, (w["code"], w["title"], w["difficulty"], w["threat_actor"], w["initial_briefing"], w["stages_json"]))

        intel_count = cur.execute("SELECT COUNT(*) FROM threat_intel_cache").fetchone()[0]
        if intel_count == 0:
            for i in THREAT_INTEL_INITIAL:
                cur.execute("""
                    INSERT OR IGNORE INTO threat_intel_cache (cve_id, title, severity, cvss_score, affected_vendor, affected_product, summary, mitigation, source_url, source_name, published_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    i["cve_id"], i["title"], i["severity"], i["cvss_score"], i["affected_vendor"],
                    i["affected_product"], i["summary"], i["mitigation"], i["source_url"],
                    i["source_name"], i["published_date"]
                ))
    except Exception as e:
        print(f"Notice: Seed data initialization warning: {e}")

    # 10. ENSURE ADMIN ROLE & ACCOUNTS
    cur.execute("UPDATE users SET role = 'admin' WHERE username IN ('dhriti', 'admin')")

    admin_exists = cur.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()
    if not admin_exists:
        cur.execute(
            "INSERT INTO users (username, full_name, password_hash, role, xp) VALUES (?, ?, ?, 'admin', 500)",
            ('admin', 'System Administrator', generate_password_hash('AdminPass2026!'))
        )
        admin_id = cur.lastrowid
        cur.execute("""
            INSERT OR IGNORE INTO user_profiles (user_id, composite_risk_score, primary_weakness, category_stats, total_tests, accuracy_pct)
            VALUES (?, 12.0, 'None (Hardened Admin)', '{}', 25, 96.0)
        """, (admin_id,))

    conn.commit()
    conn.close()

def init_db():
    ensure_tables()
