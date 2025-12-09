🕶️ PHISHING EMAIL THREAT ANALYSIS – TASK 2

Cyber Security Internship • Offensive-Style Documentation

███████╗██╗  ██╗██╗███████╗██╗  ██╗██╗███╗   ███╗
██╔════╝██║  ██║██║██╔════╝██║ ██╔╝██║████╗ ████║
█████╗  ███████║██║███████╗█████╔╝ ██║██╔████╔██║
██╔══╝  ██╔══██║██║╚════██║██╔═██╗ ██║██║╚██╔╝██║
███████╗██║  ██║██║███████║██║  ██╗██║██║ ╚═╝ ██║
╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝

>> ADVANCED PHISHING ANALYSIS MODULE <<
🧠 MISSION OBJECTIVE

Conduct a full-spectrum forensic assessment of a suspicious email designed to impersonate a trusted service provider.
Identify the attacker’s technical tradecraft, social engineering patterns, and operational intent.

🎯 PRIMARY INDICATORS DETECTED

Your investigation surfaced several high-confidence malicious markers:

🕵️ 1. Spoofed Sender Identity

Sender address was masked as a well-known service.

Envelope sender domain = support@paypaI-alerts.com
 (uppercase “I” instead of lowercase “l”).

Clear domain impersonation tactic.

🧨 2. Malicious / Mismatched URLs

Hovering revealed redirect chain → hxxps://secure-verify-login[.]global/auth

Claim: "Verify your account"

Reality: credential harvesting endpoint

SSL certificate is a free, non-EV cert → used to appear legitimate.

🧳 3. Suspicious Attachment (ZIP Payload)

Attached file: Account_Report_2025.zip

Inside → obfuscated JS loader referencing a C2 domain.

Likely malware class: keylogger or initial access dropper.

📡 4. Header Forgery (Authentication Failures)

Header analysis revealed:

Mechanism	Status	Meaning
SPF	FAIL	Sender not allowed to send from this domain
DKIM	FAIL	Tampered or unsigned message
DMARC	FAIL	Alignment broken → high spoofing likelihood

These failures strongly correlate with identity forgery operations.

🧪 5. Social Engineering Pressure

The attacker weaponized psychological triggers:

Urgency → “Your account will be permanently suspended in 12 hours.”

Fear → Claims of “irregular transactions”.

Authority abuse → Masquerades as the “Security Operations Center”.

Call-to-action pressure → Button labeled “RESOLVE NOW”.

Classic T1566.002 (spearphishing link) tradecraft.

✍️ 6. Formatting / Linguistic Red Flags

Inconsistent capitalization

Unprofessional sentence structure

Improper punctuation

Corporate branding mismatched vs real templates

Overuse of alarming language

Fingerprint consistent with non-corporate authorship.

📁 REPO STRUCTURE (ASSIGNMENT-OPTIMIZED)
phishing-email-analysis-task2/
│
├── README.md                  # Executive summary + mission overview
│
├── report/
│   └── phishing_email_analysis.md   # Deep-dive analysis + evidence
│
├── samples/
│   └── email_sample.txt       # Raw copy of the phishing email
│
└── screenshots/
    └── *.png (optional)       # Header analysis, URL hover, payload details

🧬 SKILL EXECUTION LOG
✔ Reconnaissance

Identified deceptive domain → paypaI-alerts.com

Confirmed via WHOIS: newly registered, privacy-protected.

✔ Payload Analysis

ZIP → JS → C2 beaconing pattern.

Strong indicator of info-stealer malware.

✔ Behavioral Analysis

Fear escalation: “Your funds may be restricted immediately.”

High-pressure scenario to force user actions.

✔ Malware Indicators

Script attempts to contact external host using port 8082.

Possible remote payload retrieval.

✔ Linguistic Fingerprinting

Multiple grammar anomalies.

Suggests mass-produced phishing kits.

✔ Header Forensics

SPF/DKIM/DMARC misalignment

SMTP relay from unknown foreign IP

🧩 ATTACK PATTERN CLASSIFICATION
Category	Threat Level
🎭 Social Engineering	HIGH
🌐 Domain Spoofing	HIGH
💣 Malware Delivery	HIGH
🏷 Brand Impersonation	HIGH
🧾 Authentication Failure	HIGH

Mapped to MITRE ATT&CK:

T1566.002 – Spearphishing Link

T1566.001 – Spearphishing Attachment

T1589 – Identity Information Gathering

T1204 – User Execution

T1059 – Command Scripting Loader (JS)

🔥 FINAL OUTCOME

✔ Phishing attack confirmed
✔ All technical/behavioral indicators documented
✔ Payload traits consistent with credential harvesting + malware vector
✔ Repository organized for submission
✔ Internship-grade analysis complete
✔ Threat modelling aligned with industry standards
