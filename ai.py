def generate_report(incident: dict) -> str:
    """
    Offline incident report generator.
    This simulates GenAI-style structured reporting without external APIs.
    """

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
