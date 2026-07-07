import json
import html
from datetime import datetime
from typing import Dict, Any

class ReportGenerator:
    def __init__(
        self,
        header_data: Dict[str, Any],
        ssl_data: Dict[str, Any],
        xss_data: Dict[str, Any] = None,
        sql_data: Dict[str, Any] = None,
    ):
        self.header_data = header_data
        self.ssl_data = ssl_data
        self.xss_data = xss_data or {}
        self.sql_data = sql_data or {}
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate_text_report(self) -> str:
        report = []
        report.append("=" * 60)
        report.append("             SECURITY CONFIGURATION AUDIT REPORT")
        report.append("=" * 60)
        report.append(f"Generated At: {self.timestamp}")
        report.append(f"Target URL:   {self.header_data.get('url')}")
        report.append("-" * 60)
        
        report.append("\n[1] HTTP Security Headers Analysis:")
        if self.header_data.get("error"):
            report.append(f"    Error retrieving headers: {self.header_data['error']}")
        else:
            report.append(f"    Response Status Code: {self.header_data['status_code']}")
            report.append(f"    Server Identification: {self.header_data['server']}")
            for header, info in self.header_data["security_headers"].items():
                status = "CONFIGURED" if info["present"] else "MISSING"
                report.append(f"    - {header}: {status}")

        report.append("\n[2] SSL/TLS Certificate Analysis:")
        if self.ssl_data.get("error"):
            report.append(f"    Error establishing TLS: {self.ssl_data['error']}")
        else:
            report.append(f"    Certificate Valid: {self.ssl_data['valid']}")
            report.append(f"    TLS Version:       {self.ssl_data['tls_version']}")
            report.append(f"    Issuer:            {self.ssl_data['issuer'].get('commonName', 'Unknown')}")
            report.append(f"    Expiration Date:   {self.ssl_data['expiry_date']}")
            report.append(f"    Days Remaining:    {self.ssl_data['days_remaining']}")

        if self.xss_data:
            report.append("\n[3] XSS Detection:")
            if self.xss_data.get("error"):
                report.append(f"    Error running XSS checks: {self.xss_data['error']}")
            else:
                report.append(f"    Forms Found:       {self.xss_data.get('forms_found', 0)}")
                report.append(f"    Vectors Tested:    {self.xss_data.get('tested_vectors', 0)}")
                findings = self.xss_data.get("findings", [])
                report.append(f"    Findings:          {len(findings)}")
                for finding in findings:
                    report.append(
                        f"    - {finding.get('type')} in {finding.get('location')} "
                        f"'{finding.get('parameter')}': {finding.get('evidence')}"
                    )

        if self.sql_data:
            report.append("\n[4] SQL Injection Tester:")
            if self.sql_data.get("error"):
                report.append(f"    Error running SQL injection checks: {self.sql_data['error']}")
            else:
                report.append(f"    Forms Found:       {self.sql_data.get('forms_found', 0)}")
                report.append(f"    Vectors Tested:    {self.sql_data.get('tested_vectors', 0)}")
                findings = self.sql_data.get("findings", [])
                report.append(f"    Findings:          {len(findings)}")
                for finding in findings:
                    report.append(
                        f"    - {finding.get('type')} in {finding.get('location')} "
                        f"'{finding.get('parameter')}': {finding.get('evidence')}"
                    )

        report.append("=" * 60)
        return "\n".join(report)

    def generate_html_report(self) -> str:
        target_url = self.header_data.get("url", "Unknown Target")
        status_code = self.header_data.get("status_code", "N/A")
        server_info = self.header_data.get("server", "Not Disclosed")
        
        header_rows = ""
        if self.header_data.get("error"):
            header_rows = f"<tr><td colspan='2' style='color: red;'>Error: {self.header_data['error']}</td></tr>"
        else:
            for header, info in self.header_data["security_headers"].items():
                status_class = "configured" if info["present"] else "missing"
                status_text = "Configured" if info["present"] else "Missing"
                header_rows += f"""
                <tr>
                    <td><strong>{header}</strong></td>
                    <td><span class="status-badge {status_class}">{status_text}</span></td>
                </tr>
                """

        ssl_details = ""
        if self.ssl_data.get("error"):
            ssl_details = f"<p style='color: red;'>Error establishing TLS: {self.ssl_data['error']}</p>"
        else:
            valid_class = "configured" if self.ssl_data["valid"] else "missing"
            valid_text = "Valid" if self.ssl_data["valid"] else "Expired/Invalid"
            ssl_details = f"""
            <table class="report-table">
                <tr>
                    <td><strong>Certificate Status</strong></td>
                    <td><span class="status-badge {valid_class}">{valid_text}</span></td>
                </tr>
                <tr>
                    <td><strong>TLS Version</strong></td>
                    <td>{self.ssl_data.get('tls_version')}</td>
                </tr>
                <tr>
                    <td><strong>Issuer</strong></td>
                    <td>{self.ssl_data['issuer'].get('commonName', 'Unknown')}</td>
                </tr>
                <tr>
                    <td><strong>Expiry Date</strong></td>
                    <td>{self.ssl_data.get('expiry_date')}</td>
                </tr>
                <tr>
                    <td><strong>Days Remaining</strong></td>
                    <td>{self.ssl_data.get('days_remaining')} days</td>
                </tr>
            </table>
            """

        xss_details = self._generate_test_details(self.xss_data, "XSS", "No reflected XSS evidence found.")
        sql_details = self._generate_test_details(self.sql_data, "SQL Injection", "No SQL injection evidence found.")

        html_template = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Security Configuration Audit Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f4f7f6;
            color: #333;
            margin: 0;
            padding: 40px;
        }}
        .container {{
            max-width: 800px;
            margin: 0 auto;
            background: #fff;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 10px;
            margin-top: 0;
        }}
        h2 {{
            color: #2980b9;
            margin-top: 30px;
        }}
        .meta-info {{
            font-size: 0.9em;
            color: #7f8c8d;
            margin-bottom: 20px;
        }}
        .report-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            table-layout: fixed;
        }}
        .report-table th, .report-table td {{
            border: 1px solid #ecf0f1;
            padding: 12px;
            text-align: left;
            overflow-wrap: anywhere;
            word-break: break-word;
            vertical-align: top;
        }}
        .report-table th {{
            background-color: #f8f9fa;
        }}
        .status-badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
            max-width: 100%;
            white-space: normal;
        }}
        .configured {{
            background-color: #d4edda;
            color: #155724;
        }}
        .missing {{
            background-color: #f8d7da;
            color: #721c24;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Configuration Audit Report</h1>
        <div class="meta-info">
            <strong>Target:</strong> {target_url}<br>
            <strong>Scan Time:</strong> {self.timestamp}
        </div>

        <h2>HTTP Security Headers</h2>
        <p><strong>Response Status Code:</strong> {status_code} | <strong>Server:</strong> {server_info}</p>
        <table class="report-table">
            <thead>
                <tr>
                    <th>Security Header</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {header_rows}
            </tbody>
        </table>

        <h2>SSL/TLS Certificate Status</h2>
        {ssl_details}

        <h2>XSS Detection</h2>
        {xss_details}

        <h2>SQL Injection Tester</h2>
        {sql_details}
    </div>
</body>
</html>
"""
        return html_template

    def _generate_test_details(self, data: Dict[str, Any], label: str, clean_message: str) -> str:
        if not data:
            return f"<p>{label} checks were not included in this report.</p>"
        if data.get("error"):
            return f"<p style='color: red;'>Error running {label} checks: {html.escape(data['error'])}</p>"

        findings = data.get("findings", [])
        rows = ""
        if findings:
            for finding in findings:
                rows += f"""
                <tr>
                    <td><span class="status-badge missing">Finding</span></td>
                    <td>{html.escape(str(finding.get('location', 'Unknown')))}</td>
                    <td>{html.escape(str(finding.get('parameter', 'Unknown')))}</td>
                    <td>{html.escape(str(finding.get('evidence', 'Evidence detected')))}</td>
                </tr>
                """
        else:
            rows = f"""
            <tr>
                <td><span class="status-badge configured">Clear</span></td>
                <td colspan="3">{clean_message}</td>
            </tr>
            """

        return f"""
        <p><strong>Forms Found:</strong> {data.get('forms_found', 0)} |
        <strong>Vectors Tested:</strong> {data.get('tested_vectors', 0)}</p>
        <table class="report-table">
            <thead>
                <tr>
                    <th>Status</th>
                    <th>Location</th>
                    <th>Parameter</th>
                    <th>Evidence</th>
                </tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>
        """
