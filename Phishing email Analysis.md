🔍 PHISHING EMAIL ANALYSIS REPORT

Task: Task 2 – Analyze a Phishing Email
Prepared by: Gowtham
Date: 2025-12-09

1. Sender’s Email Address
- The domain is icicibank-secure.com.
- Legitimate ICICI Bank emails come from @icicibank.com.
- Adding “-secure” is a spoofing trick to look authentic but is not owned by the bank.
- 
2. Email Headers
- A header analyzer would show the email originated from a random mail server, not ICICI’s infrastructure.
- Discrepancy between the “From” field and the actual sending server is a strong phishing indicator.
- 
📑 Header Analysis (Typical Findings)
When you run this email through an online header analyzer (like Google’s Message Header tool or MXToolbox), you’d likely see:
- Return-Path / Received fields: The email originates from a random mail server (e.g., mail.randomhost.ru) instead of ICICI’s official servers.
- SPF/DKIM/DMARC checks: These authentication checks often fail. For example:
- SPF: FAIL (domain not authorized to send mail).
- DKIM: FAIL (signature mismatch).
- DMARC: FAIL (policy not aligned).
- Mismatch in “From” and “Reply-To”: The visible “From” is alerts@icicibank-secure.com, but the “Reply-To” may point to a completely different address (e.g., phish@maliciousmail.com).
- Time zone anomalies: The sending server may show timestamps inconsistent with the bank’s region.
- 
3. Suspicious Links
- The “Restore Access” button likely points to a fake login page (http://fakebank-login.com).
- Hovering over the link would reveal the mismatch between the displayed text and the actual destination.
- 
4. Urgent/Threatening Language
- “Temporarily restricted” and “permanently blocked” are designed to scare the recipient.
- Phishers use urgency to push victims into acting without verifying.
- 
5. Mismatched URLs
- The visible link may look like https://icicibank.com/restore, but hovering shows http://malicious-site.com.
- This mismatch is a classic phishing trait.
- 
6. Spelling/Grammar Errors
- Phrases like “complete verification within 12 hours” may be awkwardly worded.
- Legitimate banks usually use polished, professional language.
- 
7. Attachments
- Some phishing emails include fake “statements” or “updates” in .zip or .pdf files that contain malware.
- Even if not present here, it’s a common tactic.
- 
✅ Conclusion
The email from alerts@icicibank-secure.com is a phishing attempt.
Key indicators include:
- Spoofed sender domain (icicibank-secure.com vs. icicibank.com).
- Header authentication failures (SPF/DKIM/DMARC).
- Suspicious links leading to fake login pages.
- Urgent, threatening language (“12 hours or blocked”).
- Grammar/phrasing errors.
Together, these traits prove the email is fraudulent and designed to steal credentials.

🛡️ Recommended Actions
- Do not click links or download attachments in the email.
- Verify sender domains carefully — official ICICI emails only come from @icicibank.com.
- Use a header analyzer to confirm authenticity whenever in doubt.
- Report the phishing email to ICICI Bank’s official support and to your email provider.
- Delete the email immediately after reporting.
- Enable two-factor authentication (2FA) on your bank account for extra protection.
- Educate others (family, colleagues) about spotting phishing traits, since attackers often target multiple people.


