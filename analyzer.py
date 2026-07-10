import hashlib
import os
import sys
import time
import re
import requests
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet


try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def safe_print(*args):
    text = " ".join(str(arg) for arg in args)
    sys.stdout.buffer.write((text + "\n").encode("utf-8", errors="replace"))
os.system("chcp 65001 >nul")
sys.stdout.reconfigure(encoding="utf-8")
VT_API_KEY="fc8aa646ca4588410ffa08827d4c5e03d05abbb11916b41e9bd907e6a8a8e73e"

def read_email(email_file):
    with open(email_file, "rb") as file:
        email = BytesParser(policy=policy.default).parse(file)
    return email
    
def extract_email_body(email):
    body = email.get_body(preferencelist=('plain',))
    if body:
     email_body=body.get_content(errors="replace")
    else:
     email_body=""
    return email_body

def extract_urls(email_body):
    urls = re.findall(r'https?://\S+', email_body)

    if urls:
     for i, url in enumerate(urls, start=1):
        safe_print(f"{i}. {url}")
    else:
        safe_print("No URLs Found")
    return urls

def detect_keywords(email_body):
    safe_print("\nSuspicious Keywords Found:")
    safe_print("-" * 50)
 #------------------------
    #Suspicious Keyword Detection
    #-------------------------
    suspicious_keywords = [
    "urgent",
    "verify",
    "password",
    "login",
    "click",
    "bank",
    "account",
    "security",
    "confirm",
    "suspended",
    "update"
]
    email_body = email_body.lower()

    found_keywords = []

    for keyword in suspicious_keywords:
      if keyword in email_body:
        found_keywords.append(keyword)

    if found_keywords:
     for i, keyword in enumerate(found_keywords, start=1):
       safe_print(f"{i}. {keyword}")

     safe_print(f"\nTotal Suspicious Keywords: {len(found_keywords)}")
    else:
        safe_print("No suspicious keywords found.")
    return found_keywords

def check_url_virustotal(url):

    headers = {
        "x-apikey": VT_API_KEY
    }

    data = {
        "url": url
    }

    safe_print("\nVirusTotal Analysis:")
    safe_print("-" * 50)

    submit = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data=data
    )

    if submit.status_code != 200:
        safe_print("Error:", submit.status_code)
        safe_print(submit.text)
        return

    analysis_id = submit.json()["data"]["id"]

    safe_print("URL submitted successfully.")
    safe_print("Waiting for analysis...")

    time.sleep(5)

    result = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers=headers
    )

    if result.status_code == 200:

        stats = result.json()["data"]["attributes"]["stats"]

        safe_print("\nDetection Results")
        safe_print("-" * 50)

        safe_print("Harmless   :", stats["harmless"])
        safe_print("Malicious  :", stats["malicious"])
        safe_print("Suspicious :", stats["suspicious"])
        safe_print("Undetected :", stats["undetected"])

        if stats["malicious"] > 0:
            safe_print("\nVerdict : MALICIOUS URL")
        elif stats["suspicious"] > 0:
            safe_print("\nVerdict : SUSPICIOUS URL")
        else:
            safe_print("\nVerdict : CLEAN URL")

    else:
        safe_print("Failed to fetch analysis.")

def check_email_authentication(email):

    safe_print("\nEmail Authentication Analysis:")
    safe_print("-" * 50)

    spf = email.get("Received-SPF")
    dkim = email.get("DKIM-Signature")
    dmarc = email.get("Authentication-Results")

    # SPF
    if spf:
        if "pass" in spf.lower():
            safe_print("SPF   : PASS")
        else:
            safe_print("SPF   : FAIL")
    else:
        safe_print("SPF   : Not Present")

    # DKIM
    if dkim:
        safe_print("DKIM  : Present")
    else:
        safe_print("DKIM  : Not Present")

    # DMARC
    if dmarc:
        if "dmarc=pass" in dmarc.lower():
            safe_print("DMARC : PASS")
        elif "dmarc=fail" in dmarc.lower():
            safe_print("DMARC : FAIL")
        else:
            safe_print("DMARC : Present")
    else:
        safe_print("DMARC : Not Present")

def calculate_attachment_hash(email):

    safe_print("\nAttachment Hash Analysis:")
    safe_print("-" * 50)

    found = False

    for part in email.iter_attachments():

        filename = part.get_filename()

        if filename:

            found = True

            file_data = part.get_payload(decode=True)

            sha256_hash = hashlib.sha256(file_data).hexdigest()

            safe_print("Filename :", filename)
            safe_print("SHA-256  :", sha256_hash)
            check_file_hash_virustotal(sha256_hash)
            safe_print("-" * 50)

    if not found:
        safe_print("No attachments available for hash analysis.")

def check_file_hash_virustotal(file_hash):

    headers = {
        "x-apikey": VT_API_KEY
    }

    safe_print("\nVirusTotal File Analysis:")
    safe_print("-" * 50)

    response = requests.get(
        f"https://www.virustotal.com/api/v3/files/{file_hash}",
        headers=headers
    )

    if response.status_code == 200:

        stats = response.json()["data"]["attributes"]["last_analysis_stats"]

        safe_print("Harmless   :", stats["harmless"])
        safe_print("Malicious  :", stats["malicious"])
        safe_print("Suspicious :", stats["suspicious"])
        safe_print("Undetected :", stats["undetected"])

        if stats["malicious"] > 0:
            safe_print("\nVerdict : MALICIOUS FILE")
        elif stats["suspicious"] > 0:
            safe_print("\nVerdict : SUSPICIOUS FILE")
        else:
            safe_print("\nVerdict : CLEAN FILE")

    elif response.status_code == 404:
        safe_print("Hash not found in VirusTotal database.")

    else:
        safe_print("Error:", response.status_code)
def generate_pdf_report():

    doc = SimpleDocTemplate("Phishing_Report.pdf")

    styles = getSampleStyleSheet()

    story = []

    story.append(Paragraph("<b>PHISHING EMAIL ANALYSIS REPORT</b>", styles["Heading1"]))

    story.append(Paragraph(f"<b>From:</b> {email['From']}", styles["BodyText"]))
    story.append(Paragraph(f"<b>To:</b> {email['To']}", styles["BodyText"]))
    story.append(Paragraph(f"<b>Subject:</b> {email['Subject']}", styles["BodyText"]))
    story.append(Paragraph(f"<b>Date:</b> {email['Date']}", styles["BodyText"]))

    story.append(Paragraph("<br/>", styles["BodyText"]))

    story.append(Paragraph(f"<b>Sender Domain:</b> {sender_domain}", styles["BodyText"]))

    story.append(Paragraph(f"<b>URLs Found:</b> {len(urls)}", styles["BodyText"]))

    story.append(Paragraph(f"<b>Keywords Found:</b> {len(found_keywords)}", styles["BodyText"]))

    story.append(Paragraph(f"<b>Risk Score:</b> {risk_score}/100", styles["BodyText"]))

    story.append(
        Paragraph(
            f"<b>Verdict:</b> {'HIGH RISK' if risk_score>=70 else 'MEDIUM RISK' if risk_score>=40 else 'LOW RISK'}",
            styles["BodyText"]
        )
    )

    doc.build(story)

    safe_print("\nPDF Report generated successfully.")
    safe_print("Saved as Phishing_Report.pdf")


if len(sys.argv) > 1:
    email = read_email(sys.argv[1])
else:
    email = read_email("emails/sample_email.eml")

from_header = email.get("From", "Not Available")
to_header = email.get("To", "Not Available")
subject_header = email.get("Subject", "Not Available")
date_header = email.get("Date", "Not Available")
safe_print("=" * 60)
safe_print("        PHISHING EMAIL ANALYSIS REPORT")
safe_print("=" * 60)

safe_print("Email Headers:")
safe_print("-" * 50)
safe_print(f"From    : {from_header}")
safe_print(f"To      : {to_header}")
safe_print(f"Subject : {subject_header}")
safe_print(f"Date    : {date_header}")
safe_print("-" * 50)
safe_print("\nEmail Body:")
safe_print("-" * 50)

email_body = extract_email_body(email)
try:
    safe_print(email_body)
except UnicodeDecodeError:
    safe_print(email_body.encode("ascii",errors="replace").decode())

urls = extract_urls(email_body)

found_keywords = detect_keywords(email_body)
safe_print("\nSender Analysis:")
safe_print("-" * 50)

sender = email.get("From")

if sender is None:
    sender = ""

match = re.search(r'[\w\.-]+@[\w\.-]+', sender)

if match:
    sender_email = match.group()
    sender_domain = sender_email.split("@")[1]

    safe_print("Sender Email :", sender_email)
    safe_print("Sender Domain:", sender_domain)
else:
    safe_print("No sender email found.")
safe_print("\nURL Domain Analysis:")
safe_print("-" * 50)

if urls:
    for url in urls:
        parsed_url = urlparse(url)
        url_domain = parsed_url.netloc

        safe_print("URL:", url)
        safe_print("Domain:", url_domain)

    check_url_virustotal(url)
    check_email_authentication(email)
    if url_domain == sender_domain:
            safe_print("Status: Domain matches sender")
    else:
            safe_print("Status: Domain does NOT match sender")
            safe_print("-" * 30)
else:
    safe_print("No URLs available for analysis.")
safe_print("\nRisk Score Analysis:")
safe_print("-" * 50)
risk_score = 0
risk_score += len(found_keywords) * 5
risk_score += len(urls) * 10
if urls and sender_domain != url_domain:
    risk_score += 20
safe_print(f"Risk Score : {risk_score}/100")
if risk_score >= 70:
    verdict = "HIGH RISK"

elif risk_score >= 40:
    verdict = "MEDIUM RISK"

else:
    verdict = "LOW RISK"

safe_print(f"Verdict : {verdict}")
safe_print("\nRecommended Action:")
safe_print("-" * 50)

if risk_score >= 70:
    safe_print("- Do NOT click any links.")
    safe_print("- Block the sender.")
    safe_print("- Report the email as phishing.")
    safe_print("- Delete the email immediately.")

elif risk_score >= 40:
    safe_print("- Be cautious before opening links.")
    safe_print("- Verify the sender's identity.")
    safe_print("- Scan any attachments.")
    safe_print("- Report to the security team if suspicious.")

else:
    safe_print("- Email appears relatively safe.")
    safe_print("- Continue monitoring.")
safe_print("\nAttachment Analysis:")
safe_print("-" * 50)


calculate_attachment_hash(email)
attachments = []

for part in email.iter_attachments():
    filename = part.get_filename()

    if filename:
        attachments.append(filename)

if attachments:
    safe_print("Attachments Found:")

    for i, file in enumerate(attachments, start=1):
        safe_print(f"{i}. {file}")

else:
    safe_print("No Attachments Found.")
safe_print("\nIP Address Analysis:")
safe_print("-" * 50)

ip_addresses = re.findall(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    email_body
)

if ip_addresses:
    safe_print("IP Addresses Found:")

    for i, ip in enumerate(ip_addresses, start=1):
        safe_print(f"{i}. {ip}")

else:
    safe_print("No IP Addresses Found.")
safe_print("\nHTML Email Analysis:")
safe_print("-" * 50)

html_body = email.get_body(preferencelist=('html',))

if html_body:
    safe_print("HTML Content Found.")
    safe_print("This email contains HTML formatting.")
else:
    safe_print("No HTML Content Found.")
safe_print("\n" + "=" * 60)
safe_print("PHISHING EMAIL ANALYSIS REPORT")
safe_print("=" * 60)

safe_print(f"From           : {from_header}")
safe_print(f"To             : {to_header}")
safe_print(f"Subject        : {subject_header}")
safe_print(f"Date           : {date_header}")
safe_print(f"Sender Domain  : {sender_domain}")
safe_print(f"URLs Found     : {len(urls)}")
safe_print(f"Keywords Found : {len(found_keywords)}")
safe_print(f"Risk Score     : {risk_score}/100")
safe_print(f"Verdict        : {verdict}")

report = f"""
============================================================
PHISHING EMAIL ANALYSIS REPORT
============================================================

From           : {from_header}
To             : {to_header}
Subject        : {subject_header}
Date           : {date_header}

Sender Domain  : {sender_domain}
URLs Found     : {len(urls)}
Keywords Found : {len(found_keywords)}
Risk Score     : {risk_score}/100
Verdict        : {verdict}

Generated By : Python Phishing Email Analyzer
"""

with open("report.txt", "w", encoding="utf-8") as file:
    file.write(report)

safe_print("\nReport generated successfully.")
safe_print("Saved as report.txt")

generate_pdf_report()
