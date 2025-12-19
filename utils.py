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

    # Auth logs
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
    elif failed_logins >= 2 or phishing_detected:
        severity = "Medium"
    else:
        severity = "Low"

    return {
        "incident_type": "Phishing with Possible Credential Abuse"
        if phishing_detected else "Suspicious Authentication Activity",
        "timeline": sorted(timeline),
        "indicators": {
            "ip_addresses": list(indicators["ip_addresses"]),
            "domains": list(indicators["domains"]),
            "user_accounts": list(indicators["user_accounts"])
        },
        "severity": severity
    }
