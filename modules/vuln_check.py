def analyze(target: str, protocols: dict):
    findings = []
    tcp = protocols.get("tcp", {})
    if 80 in tcp and tcp[80].get("state") == "open":
        findings.append({
            "severity": "Medium",
            "issue": "HTTP service open",
            "evidence": "Port 80/tcp open",
            "recommendation": "Use HTTPS instead of HTTP"
        })
    if 23 in tcp and tcp[23].get("state") == "open":
        findings.append({
            "severity": "High",
            "issue": "Telnet service open",
            "evidence": "Port 23/tcp open",
            "recommendation": "Disable Telnet, use SSH"
        })
    return findings
