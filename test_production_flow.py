"""
Threat Vector — Complete End-to-End Production Flow Verification Test
Tests all requested user paths:
Login -> Dashboard -> Launch Drill -> Complete Drill -> Submit -> Score -> Feedback -> Leaderboard
Plus: Phishing, CTF, War Room, Analytics, AI Analyst, Threat Intel, Skills, Logout.
"""

import sys
import unittest

from app import app
from database.db import ensure_tables

class TestProductionFlow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        cls.client = app.test_client()
        with app.app_context():
            ensure_tables()

    def test_01_complete_drill_lifecycle(self):
        # 1. Demo Login
        res_login = self.client.post('/demo-login', follow_redirects=True)
        self.assertEqual(res_login.status_code, 200, "Demo login failed")
        self.assertIn("Adaptive Social Engineering Dashboard", res_login.data.decode('utf-8'))

        # 2. Access Dashboard
        res_dash = self.client.get('/dashboard')
        self.assertEqual(res_dash.status_code, 200)

        # 3. Launch New Drill (/drill or /simulation)
        res_drill = self.client.get('/drill', follow_redirects=True)
        self.assertEqual(res_drill.status_code, 200)
        body_drill = res_drill.data.decode('utf-8')
        self.assertTrue("Threat" in body_drill or "Simulation" in body_drill)

        # 4. Complete & Submit Drill (/drill/submit)
        res_submit = self.client.post('/drill/submit', data={
            'scenario_id': '1',
            'user_choice': 'threat',
            'response_time': '3.8',
            'drill_number': '1'
        }, follow_redirects=True)
        self.assertEqual(res_submit.status_code, 200)
        body_result = res_submit.data.decode('utf-8')

        # 5. Score & Feedback Verification (Explanation view)
        self.assertTrue(
            "Diagnostic" in body_result or "Explanation" in body_result or "Micro-Lesson" in body_result or "Next Adaptive Drill" in body_result,
            "Explanation view failed to render diagnostic feedback"
        )
        self.assertIn("Next Adaptive Drill", body_result)

        # 6. Global Leaderboard
        res_lb = self.client.get('/leaderboard')
        self.assertEqual(res_lb.status_code, 200)
        body_lb = res_lb.data.decode('utf-8')
        self.assertIn("Cybersecurity Defense Leaderboard", body_lb)
        self.assertIn("Score", body_lb)

    def test_02_all_specialized_modules(self):
        self.client.post('/demo-login')

        # Phishing Simulation
        res_phish = self.client.get('/phishing')
        self.assertEqual(res_phish.status_code, 200)
        self.assertIn("Realistic Phishing Defense Range", res_phish.data.decode('utf-8'))
        res_phish_detail = self.client.get('/phishing/1')
        self.assertEqual(res_phish_detail.status_code, 200)

        # CTF Mission Mode
        res_ctf = self.client.get('/ctf')
        self.assertEqual(res_ctf.status_code, 200)
        self.assertIn("CTF Mission Headquarters", res_ctf.data.decode('utf-8'))
        res_ctf_chal = self.client.get('/ctf/1')
        self.assertEqual(res_ctf_chal.status_code, 200)

        # Incident Response War Room
        res_war = self.client.get('/war-room')
        self.assertEqual(res_war.status_code, 200)
        self.assertIn("Incident Response War Room", res_war.data.decode('utf-8'))
        res_war_sc = self.client.get('/war-room/1')
        self.assertEqual(res_war_sc.status_code, 200)

        # Personal Analytics Dashboard
        res_analytics = self.client.get('/analytics')
        self.assertEqual(res_analytics.status_code, 200)
        self.assertIn("Personal Threat Readiness Analytics", res_analytics.data.decode('utf-8'))

        # AI Threat Analyst
        res_ai = self.client.get('/ai-analyst')
        self.assertEqual(res_ai.status_code, 200)
        self.assertIn("AI Threat Analyst & Diagnostic Intelligence", res_ai.data.decode('utf-8'))


        # Threat Intelligence Center
        res_intel = self.client.get('/threat-intel')
        self.assertEqual(res_intel.status_code, 200)
        self.assertIn("Threat Intelligence Center", res_intel.data.decode('utf-8'))

        # Skills & Badges
        res_skills = self.client.get('/skills')
        self.assertEqual(res_skills.status_code, 200)
        self.assertIn("Cybersecurity Skills & Achievements", res_skills.data.decode('utf-8'))


        # Leaderboard
        res_lb = self.client.get('/leaderboard')
        self.assertEqual(res_lb.status_code, 200)

        # Logout
        res_logout = self.client.get('/logout', follow_redirects=True)
        self.assertEqual(res_logout.status_code, 200)
        self.assertIn("Trainee Sign In", res_logout.data.decode('utf-8'))

if __name__ == '__main__':
    unittest.main()
