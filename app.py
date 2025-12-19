import io
from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

# -------------------------------------------------
# FASTAPI APP
# -------------------------------------------------

app = FastAPI(
    title="GenAI Cyber Incident Reporting System",
    description="Offline SOC-ready cyber incident analysis and reporting tool",
    version="1.0.0"
)

# -------------------------------------------------
# CORE LOGIC: LOG CORRELATION + SEVERITY
# -------------------------------------------------

def correlate_logs(logs: dict) -> dict:
    indicators = {
        "ip_addresses": set(),
        "domains": set(),
        "user_accounts": set()
    }

    timeline = []
    failed_logins = 0
    phishing_detected = False

    # Firewall logs
    for log in logs.get("firewall_logs", []):
        indicators["ip_addresses"].add(log["src_ip"])
        timeline.append(
            f"{log['timestamp']} - Firewall blocked traffic from {log['src_ip']}"
        )

    # Authentication logs
    for log in logs.get("auth_logs", []):
        indicators["ip_addresses"].add(log["src_ip"])
        indicators["user_accounts"].add(log["user"])

        if log["status"] == "FAILED":
            failed_logins += 1
            timeline.append(
                f"{log['timestamp']} - Failed login for user {log['user']} from {log['src_ip']}"
            )

    # Phishing alerts
    for alert in logs.get("phishing_alerts", []):
        phishing_detected = True
        domain = alert["malicious_url"].split("//")[-1]
        indicators["domains"].add(domain)
        indicators["user_accounts"].add(alert["email"])
        timeline.append(
            f"{alert['timestamp']} - Phishing email detected for {alert['email']}"
        )

    # Severity logic
    if phishing_detected and failed_logins >= 2:
        severity = "High"
    elif phishing_detected or failed_logins >= 2:
        severity = "Medium"
    else:
        severity = "Low"

    return {
        "incident_type": "Phishing with Possible Credential Abuse"
        if phishing_detected else "Suspicious Authentication Activity",
        "severity": severity,
        "timeline": sorted(timeline),
        "indicators": {
            "ip_addresses": list(indicators["ip_addresses"]),
            "domains": list(indicators["domains"]),
            "user_accounts": list(indicators["user_accounts"])
        }
    }

# -------------------------------------------------
# OFFLINE GenAI-STYLE REPORT GENERATOR
# -------------------------------------------------

def generate_report(incident: dict) -> str:
    summary = (
        f"This security incident has been classified as "
        f"{incident['incident_type']} with a severity level of "
        f"{incident['severity']}.\n\n"
        f"The investigation identified suspicious activity involving "
        f"multiple security indicators, suggesting a coordinated attack attempt."
    )

    timeline_text = "\n".join(
        f"- {event}" for event in incident["timeline"]
    )

    indicators = incident["indicators"]
    indicators_text = (
        f"IP Addresses: {', '.join(indicators['ip_addresses'])}\n"
        f"Domains: {', '.join(indicators['domains'])}\n"
        f"User Accounts: {', '.join(indicators['user_accounts'])}"
    )

    recommendations = (
        "- Reset credentials of affected user accounts\n"
        "- Block identified malicious IPs and domains\n"
        "- Monitor authentication logs for further anomalies\n"
        "- Conduct user awareness training on phishing attacks"
    )

    report = f"""
INCIDENT SUMMARY
----------------
{summary}

TIMELINE OF EVENTS
------------------
{timeline_text}

INDICATORS OF COMPROMISE (IOCs)
-------------------------------
{indicators_text}

RECOMMENDED MITIGATION STEPS
----------------------------
{recommendations}

NOTE
----
This report was generated automatically and must be reviewed by a security analyst.
"""

    return report.strip()

# -------------------------------------------------
# PDF EXPORT
# -------------------------------------------------

def generate_pdf(report_text: str) -> bytes:
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    x, y = 40, height - 40

    for line in report_text.split("\n"):
        if y < 40:
            pdf.showPage()
            y = height - 40
        pdf.drawString(x, y, line)
        y -= 14

    pdf.save()
    buffer.seek(0)
    return buffer.read()

# -------------------------------------------------
# API ENDPOINTS
# -------------------------------------------------

@app.post("/analyze")
def analyze_incident(logs: dict):
    incident = correlate_logs(logs)
    report = generate_report(incident)

    return {
        "incident_type": incident["incident_type"],
        "severity": incident["severity"],
        "indicators": incident["indicators"],
        "timeline": incident["timeline"],
        "report": report
    }

@app.post("/export/pdf")
def export_pdf(logs: dict):
    incident = correlate_logs(logs)
    report = generate_report(incident)
    pdf_bytes = generate_pdf(report)

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": "attachment; filename=incident_report.pdf"
        }
    )
