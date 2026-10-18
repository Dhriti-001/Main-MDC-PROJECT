"""
Comprehensive Automated Verification Test Suite for Threat Vector
Tests all 8 core enhancement modules, RBAC isolation, sequential drills, and data persistence.
"""

import unittest
import json
from app import app
from db import get_db

class TestThreatVectorEnhancements(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        cls.client = app.test_client()

    def login_demo(self):
        return self.client.post('/demo-login', follow_redirects=True)

    def login_trainee(self):
        self.client.get('/logout')
        with app.app_context():
            db = get_db()
            from werkzeug.security import generate_password_hash
            db.execute("INSERT OR REPLACE INTO users (id, username, full_name, password_hash, role) VALUES (999, 'test_trainee', 'Test Trainee', ?, 'trainee')", (generate_password_hash('trainee123'),))
            db.commit()
        return self.client.post('/login', data={'username': 'test_trainee', 'password': 'trainee123'}, follow_redirects=True)

    def login_admin(self):
        self.client.get('/logout')
        import os
        admin_pw = os.environ.get('ADMIN_PASSWORD', 'test_admin_pass')
        with app.app_context():
            db = get_db()
            from werkzeug.security import generate_password_hash
            db.execute("UPDATE users SET password_hash = ? WHERE username = 'admin'", (generate_password_hash(admin_pw),))
            db.commit()
        return self.client.post('/login', data={'username': 'admin', 'password': admin_pw}, follow_redirects=True)


    def test_01_demo_login_and_dashboard(self):
        res = self.login_demo()
        self.assertEqual(res.status_code, 200)
        body = res.data.decode('utf-8')
        self.assertIn("Adaptive Social Engineering Dashboard", body)
        # Ensure NO hardcoded step text exists
        self.assertNotIn("Step 1:", body)
        self.assertNotIn("Step 2:", body)
        self.assertNotIn("Step 3:", body)
        self.assertNotIn("Step 4:", body)

    def test_02_personal_analytics_dashboard(self):
        self.login_demo()
        res = self.client.get('/analytics')
        self.assertEqual(res.status_code, 200)
        body = res.data.decode('utf-8')
        self.assertIn("Personal Threat Readiness Analytics", body)
        self.assertIn("Total Earned XP", body)
        self.assertIn("Active Day Streak", body)
        self.assertIn("Identified Cognitive Weaknesses", body)

    def test_03_phishing_lab(self):
        self.login_demo()
        res = self.client.get('/phishing')
        self.assertEqual(res.status_code, 200)
        body = res.data.decode('utf-8')
        self.assertIn("Realistic Phishing Defense Range", body)

        # Inspect scenario 1
        res2 = self.client.get('/phishing/1')
        self.assertEqual(res2.status_code, 200)
        body2 = res2.data.decode('utf-8')
        self.assertIn("Trainee Forensic Analysis", body2)

        # Test safe simulated portal preview
        res_portal = self.client.get('/phishing/1/portal')
        self.assertEqual(res_portal.status_code, 200)
        self.assertIn("SIMULATED CYBER RANGE", res_portal.data.decode('utf-8'))

        # Submit phishing attempt
        res_submit = self.client.post('/phishing/submit', json={
            "scenario_id": 1,
            "verdict": "phishing",
            "indicators": ["Sender Domain Mismatch"],
            "response_time": 8
        })
        self.assertEqual(res_submit.status_code, 200)
        data = res_submit.get_json()
        self.assertTrue(data['success'])
        self.assertTrue(data['result']['is_correct'])

    def test_04_ctf_missions(self):
        self.login_demo()
        res = self.client.get('/ctf')
        self.assertEqual(res.status_code, 200)
        body = res.data.decode('utf-8')
        self.assertIn("CTF Mission Headquarters", body)
        self.assertIn("Flags Captured", body)

        # Inspect challenge 1
        res2 = self.client.get('/ctf/1')
        self.assertEqual(res2.status_code, 200)
        self.assertIn("Raw Telemetry Artifact", res2.data.decode('utf-8'))

        # Submit wrong flag
        res_wrong = self.client.post('/ctf/submit', json={
            "challenge_id": 1,
            "flag": "TV{wrong_flag}",
            "hints_used": 0
        })
        self.assertEqual(res_wrong.status_code, 200)
        self.assertFalse(res_wrong.get_json()['success'])

        # Submit correct flag
        res_correct = self.client.post('/ctf/submit', json={
            "challenge_id": 1,
            "flag": "FLAG{192.168.1.105}",
            "hints_used": 0
        })
        self.assertEqual(res_correct.status_code, 200)
        # Should be true or duplicate if already solved
        data = res_correct.get_json()
        self.assertTrue(data['success'] or "already captured" in data['message'])

    def test_05_ai_threat_analyst(self):
        self.login_demo()
        res = self.client.get('/ai-analyst')
        self.assertEqual(res.status_code, 200)
        body = res.data.decode('utf-8')
        self.assertIn("AI Threat Analyst & Diagnostic Intelligence", body)
        self.assertIn("MITRE ATT&CK", body)

        # Generate report via POST
        res_gen = self.client.post('/ai-analyst/generate', json={"scenario_id": 1})
        self.assertEqual(res_gen.status_code, 200)
        rep = res_gen.get_json()['report']
        self.assertIn('cvss_score', rep)
        self.assertIn('mitre_technique', rep)
        self.assertIn('why_correct', rep)

    def test_06_incident_response_war_room(self):
        self.login_demo()
        res = self.client.get('/war-room')
        self.assertEqual(res.status_code, 200)
        body = res.data.decode('utf-8')
        self.assertIn("Incident Response War Room", body)

        # Launch scenario 1
        res_launch = self.client.get('/war-room/1', follow_redirects=True)
        self.assertEqual(res_launch.status_code, 200)
        body_launch = res_launch.data.decode('utf-8')
        self.assertTrue("STAGE" in body_launch or "After-Action Report" in body_launch)

    def test_07_skills_and_certificate(self):
        self.login_demo()
        res = self.client.get('/skills')
        self.assertEqual(res.status_code, 200)
        body = res.data.decode('utf-8')
        self.assertIn("Core Competency Matrix", body)
        self.assertIn("Achievement Badges", body)

        # Public certificate verification
        res_verify = self.client.get('/verify-certificate/TV-CERT-NONEXISTENT')
        self.assertEqual(res_verify.status_code, 200)
        self.assertIn("INVALID OR UNRECOGNIZED", res_verify.data.decode('utf-8'))

    def test_08_threat_intelligence_center(self):
        res = self.client.get('/threat-intel')
        self.assertEqual(res.status_code, 200)
        body = res.data.decode('utf-8')
        self.assertIn("Threat Intelligence Center", body)
        self.assertIn("CVE-", body)

    def test_09_rbac_trainee_cannot_access_admin(self):
        self.login_trainee() # Role is explicitly trainee
        res = self.client.get('/admin', follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        body = res.data.decode('utf-8')
        self.assertIn("Access Denied", body)

    def test_10_admin_console_and_csv_export(self):
        self.login_admin() # Role is admin
        res = self.client.get('/admin')
        self.assertEqual(res.status_code, 200)
        body = res.data.decode('utf-8')
        self.assertIn("Trainer & Institutional Command Console", body)
        self.assertIn("Export Trainees CSV", body)

        # Test CSV Export
        res_csv_users = self.client.get('/admin/export/users')
        self.assertEqual(res_csv_users.status_code, 200)
        self.assertEqual(res_csv_users.mimetype, 'text/csv')
        self.assertIn("User ID,Username,Full Name", res_csv_users.data.decode('utf-8'))

        res_csv_drills = self.client.get('/admin/export/drills')
        self.assertEqual(res_csv_drills.status_code, 200)
        self.assertEqual(res_csv_drills.mimetype, 'text/csv')
        self.assertIn("Attempt ID,User ID", res_csv_drills.data.decode('utf-8'))

if __name__ == '__main__':
    unittest.main()
