🕶️ Phishing Email Threat Analysis – Task 2
Cyber Security Internship • Offensive-Style Documentation
███████╗██╗  ██╗██╗███████╗██╗  ██╗██╗███╗   ███╗
██╔════╝██║  ██║██║██╔════╝██║ ██╔╝██║████╗ ████║
█████╗  ███████║██║███████╗█████╔╝ ██║██╔████╔██║
██╔══╝  ██╔══██║██║╚════██║██╔═██╗ ██║██║╚██╔╝██║
███████╗██║  ██║██║███████║██║  ██╗██║██║ ╚═╝ ██║
╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝


🎯 Mission Objective
Conduct a full-spectrum forensic assessment of a suspicious email impersonating ICICI Bank.
Identify attacker tradecraft, social engineering techniques, and operational intent.

📌 Primary Indicators Detected
- Spoofed Sender Identity
- Claimed sender: alerts@icicibank-secure.com
- Domain impersonation tactic (fake banking domain).
- Malicious / Mismatched URLs
- Embedded link: [Restore Access] → redirects to credential harvesting endpoint.
- SSL certificate: free, non-EV → false legitimacy.
- Suspicious Attachment
- Payload: Account_Report_2025.zip
- Contains obfuscated JavaScript loader beaconing to C2 domain.
- Likely malware: keylogger / initial access dropper.
- Header Forgery / Authentication Failures
- SPF: FAIL – unauthorized sender
- DKIM: FAIL – unsigned/tampered message
- DMARC: FAIL – misaligned, spoofing confirmed
- Social Engineering Pressure
- Urgency: “Account blocked in 12 hours”
- Fear: “Suspicious activity detected”
- Authority abuse: fake “Security Department”
- Call-to-action: “Restore Access” button
- Formatting / Linguistic Red Flags
- Poor grammar, inconsistent capitalization
- Branding mismatches vs legitimate ICICI templates
- Overuse of alarming language

🧬 Skill Execution Log
- Reconnaissance
- Domain icicibank-secure.com → newly registered, privacy-protected.
- Payload Analysis
- ZIP → JS loader → C2 beaconing pattern.
- Indicators of info-stealer malware.
- Behavioral Analysis
- Fear escalation: “Funds restricted immediately.”
- High-pressure tactics to force user action.
- Malware Indicators
- Script attempts external host connection via port 8082.
- Possible remote payload retrieval.
- Linguistic Fingerprinting
- Grammar anomalies → mass-produced phishing kit.
- Header Forensics
- SPF/DKIM/DMARC misalignment
- SMTP relay from foreign IP

🔐 Attack Pattern Classification (Bullet Format)
- Social Engineering → HIGH
- Domain Spoofing → HIGH
- Malware Delivery → HIGH
- Brand Impersonation → HIGH
- Authentication Failures → HIGH

Mapped to MITRE ATT&CK:
- T1566.002 – Spearphishing Link
- T1566.001 – Spearphishing Attachment
- T1589 – Identity Information Gathering
- T1204 – User Execution
- T1059 – Command Scripting Loader (JS)

🔥 Final Outcome
- ✔ Phishing attack confirmed
- ✔ Technical & behavioral indicators documented
- ✔ Payload traits consistent with credential harvesting + malware vector
- ✔ Repository organized for submission
- ✔ Threat modeling aligned with industry standards
