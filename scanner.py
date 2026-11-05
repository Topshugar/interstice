"""
INTERSTICE - Defensive Website Security Scanner
Author: Topshugar
Purpose: Help website owners identify and remediate security gaps.
License: MIT
"""

import argparse
import requests
from datetime import datetime
from urllib.parse import urlparse

# ============================================================================
# CONFIGURATION
# ============================================================================

# Security headers that every modern website should implement.
# Missing headers do not mean the site is hacked, but they increase risk.
REQUIRED_HEADERS = {
    "Content-Security-Policy": "Prevents XSS by controlling allowed resources.",
    "Strict-Transport-Security": "Forces HTTPS and prevents downgrade attacks.",
    "X-Frame-Options": "Prevents clickjacking by blocking iframes.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing attacks.",
    "Referrer-Policy": "Controls how much referrer information is leaked.",
}

# ============================================================================
# CORE SCANNING FUNCTIONS
# ============================================================================

def normalize_domain(user_input):
    """
    Normalize user input into a clean domain name.
    Accepts: example.com, https://example.com, www.example.com
    """
    if not user_input.startswith("http"):
        user_input = "https://" + user_input
    parsed = urlparse(user_input)
    return parsed.netloc

def check_https(domain):
    """
    Verify HTTPS availability and SSL certificate validity.
    Returns a structured finding with severity and remediation.
    """
    try:
        response = requests.get(f"https://{domain}", timeout=10)
        return {
            "check": "HTTPS Enabled",
            "status": "PASS",
            "severity": "None",
            "detail": f"Site responds over HTTPS with status {response.status_code}.",
            "fix": "No action required."
        }
    except requests.exceptions.SSLError:
        return {
            "check": "HTTPS Enabled",
            "status": "FAIL",
            "severity": "Critical",
            "detail": "SSL certificate is invalid, expired, or misconfigured.",
            "fix": "Renew and install a valid SSL certificate from a trusted provider."
        }
    except Exception as e:
        return {
            "check": "HTTPS Enabled",
            "status": "FAIL",
            "severity": "High",
            "detail": f"Site is not reachable over HTTPS: {str(e)}",
            "fix": "Enable HTTPS and redirect all HTTP traffic to HTTPS."
        }

def check_security_headers(domain):
    """
    Analyze HTTP response headers against industry best practices.
    Missing headers are reported as individual findings for clarity.
    """
    findings = []
    try:
        response = requests.get(f"https://{domain}", timeout=10)
        headers = response.headers

        for header, description in REQUIRED_HEADERS.items():
            if header not in headers:
                findings.append({
                    "check": f"Header: {header}",
                    "status": "FAIL",
                    "severity": "Medium",
                    "detail": f"Missing {header}. {description}",
                    "fix": f"Configure your server to send the {header} header."
                })
            else:
                findings.append({
                    "check": f"Header: {header}",
                    "status": "PASS",
                    "severity": "None",
                    "detail": f"{header} is present.",
                    "fix": "No action required."
                })

        # Check for information disclosure via Server header
        if "Server" in headers:
            findings.append({
                "check": "Server Information Disclosure",
                "status": "WARNING",
                "severity": "Low",
                "detail": f"Server header reveals: {headers['Server']}",
                "fix": "Hide Server header to avoid revealing software versions."
            })

    except Exception as e:
        findings.append({
            "check": "Security Headers",
            "status": "ERROR",
            "severity": "High",
            "detail": f"Could not fetch headers: {str(e)}",
            "fix": "Ensure the domain is online and reachable."
        })

    return findings

def calculate_score(findings):
    """
    Calculate a 0-100 security score based on severity of failures.
    This is a guidance score, not a guarantee of security.
    """
    score = 100
    deductions = {"Critical": 25, "High": 15, "Medium": 7, "Low": 3}
    for finding in findings:
        if finding["status"] == "FAIL":
            score -= deductions.get(finding["severity"], 5)
        elif finding["status"] == "WARNING":
            score -= 3
    return max(0, score)

# ============================================================================
# REPORT GENERATION
# ============================================================================

def generate_html_report(domain, findings, score):
    """
    Generate a clean, professional HTML report for the website owner.
    Uses semantic H1 / H2 tags for structure and readability.
    """
    rows = ""
    for f in findings:
        if f["status"] == "PASS":
            color = "green"
        elif f["status"] == "FAIL":
            color = "red"
        else:
            color = "orange"
        rows += (
            f"<tr><td>{f['check']}</td>"
            f"<td style=\"color:{color}; font-weight:bold;\">{f['status']}</td>"
            f"<td>{f['severity']}</td>"
            f"<td>{f['detail']}</td>"
            f"<td>{f['fix']}</td></tr>\n"
        )

    generated = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    table_header = (
        "<tr><th>Check</th><th>Status</th><th>Severity</th>"
        "<th>Detail</th><th>Recommended Fix</th></tr>"
    )
    disclaimer = (
        "This report is for defensive use on assets you own. "
        "It identifies common gaps and does not guarantee complete security."
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Interstice Report - {domain}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f4f6f8; }}
        .container {{ background: #fff; padding: 30px; border-radius: 12px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; font-size: 14px; }}
        th {{ background: #111; color: #fff; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>INTERSTICE Security Report</h1>
        <h2>Target: {domain}</h2>
        <h2>Security Score: {score} / 100</h2>
        <h2>Generated: {generated}</h2>
        <h2>Findings</h2>
        <table>
            {table_header}
            {rows}
        </table>
        <p><strong>Disclaimer:</strong> {disclaimer}</p>
    </div>
</body>
</html>
"""
    filename = f"interstice_report_{domain.replace('.', '_')}.html"
    with open(filename, "w", encoding="utf-8") as file:
        file.write(html)
    return filename

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """
    Main entry point. Enforces explicit ownership confirmation before scanning.
    """
    parser = argparse.ArgumentParser(description="INTERSTICE - Defensive Scanner")
    parser.add_argument("--domain", required=True, help="Domain you own, e.g. example.com")
    parser.add_argument(
        "--confirm-ownership",
        action="store_true",
        help="Confirm you own this domain or have written permission"
    )
    args = parser.parse_args()

    if not args.confirm_ownership:
        print("[!] ERROR: You must confirm ownership with --confirm-ownership")
        print("[!] Only scan assets you own or have written permission to test.")
        return

    domain = normalize_domain(args.domain)
    print(f"[+] INTERSTICE: Starting scan for {domain}")

    findings = []
    findings.append(check_https(domain))
    findings.extend(check_security_headers(domain))

    score = calculate_score(findings)
    report = generate_html_report(domain, findings, score)

    print(f"[+] Scan complete. Score: {score}/100")
    print(f"[+] Report saved: {report}")

if __name__ == "__main__":
    main()