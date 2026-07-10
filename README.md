 Phishing Email Analyzer

A Python-based desktop application that analyzes phishing emails by extracting email headers, URLs, attachments, sender information, and security indicators. The tool calculates a phishing risk score and generates investigation reports in PDF and text format.

---

 Features

- Analyze .eml email files
- Extract email headers
- Sender domain analysis
- URL extraction
- Suspicious keyword detection
- VirusTotal URL reputation check
- Attachment SHA-256 hash generation
- VirusTotal file reputation check
- SPF, DKIM & DMARC analysis
- HTML email detection
- IP address extraction
- Risk score calculation
- Automated phishing verdict
- PDF report generation
- Text report generation
- Cybersecurity-themed GUI

---

 Technologies Used

- Python
- Tkinter
- ReportLab
- VirusTotal API
- Regular Expressions (Regex)
- Email Parser
- hashlib
- Requests
- Git & GitHub

---

 Project Structure


 ## 📂 Project Structure

text
Phishing-Email-Analyzer
│
├── analyzer.py
├── gui.py
├── requirements.txt
├── README.md
├── emails/
├── screenshots/
└── reports/

---

 How to Run

 Clone Repository

bash
git clone https://github.com/lohithiremath44/Phishing-Email-analyzer.git

 Install Dependencies

bash
pip install -r requirements.txt


bash
python gui.py

 Run GUI

bash
python gui.py


---

 Risk Levels

| Risk Score | Verdict |
|------------|----------|
| 0–39 | Low Risk |
| 40–69 | Medium Risk |
| 70–100 | High Risk |

---

 Output

- GUI Analysis
- PDF Report
- Text Report

---

 Future Enhancements

- Machine Learning-based phishing detection
- Email attachment sandboxing
- Threat Intelligence integration
- Domain reputation lookup
- IP reputation lookup
- IOC export
- Email header visualization

---

## 📸 Screenshots

### Main GUI

![GUI](screenshots/gui.png)

### Email Analysis

![Analysis](screenshots/analysis.png)

### Generated Report

![Report](screenshots/report.png)

### email upload

![Risk](screenshots/emailupload.png)

Developed By

Lohit M Hiremath

GitHub: https://github.com/lohithiremath44