import requests
import re
from urllib.parse import urlparse
from typing import Dict, Any

class HeaderAuditor:
    def __init__(self, url: str):
        if not url.startswith(("http://", "https://")):
            self.url = "https://" + url
        else:
            self.url = url

    def analyze_url_heuristics(self) -> Dict[str, Any]:
        analysis = {
            "suspicious": False,
            "reasons": []
        }
        
        parsed = urlparse(self.url)
        host = parsed.netloc

        if not host:
            analysis["suspicious"] = True
            analysis["reasons"].append("Malformed URL or invalid host format.")
            return analysis

        if len(self.url) > 100:
            analysis["suspicious"] = True
            analysis["reasons"].append("URL length exceeds 100 characters (potential obfuscation).")

        ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        host_no_port = host.split(":")[0]
        if re.match(ip_pattern, host_no_port):
            analysis["suspicious"] = True
            analysis["reasons"].append("Host uses a raw numerical IP address instead of a domain name.")

        if "@" in host:
            analysis["suspicious"] = True
            analysis["reasons"].append("URL contains credentials symbol '@' in authority section.")

        suspicious_keywords = ["login", "secure", "verify", "update", "bank", "free", "signin", "account"]
        for keyword in suspicious_keywords:
            if keyword in host_no_port.lower():
                analysis["suspicious"] = True
                analysis["reasons"].append(f"Host contains high-risk phishing keyword: '{keyword}'")
                break

        return analysis

    def audit_headers(self) -> Dict[str, Any]:
        heuristics = self.analyze_url_heuristics()
        
        results = {
            "url": self.url,
            "status_code": None,
            "redirects": [],
            "server": "Not Disclosed",
            "heuristics": heuristics,
            "security_headers": {
                "Strict-Transport-Security": {"present": False, "value": None},
                "Content-Security-Policy": {"present": False, "value": None},
                "X-Frame-Options": {"present": False, "value": None},
                "X-Content-Type-Options": {"present": False, "value": None},
                "Referrer-Policy": {"present": False, "value": None}
            },
            "error": None
        }

        try:
            response = requests.get(
                self.url, 
                timeout=5, 
                allow_redirects=True,
                headers={"User-Agent": "SecurityAuditor/1.0"}
            )
            results["status_code"] = response.status_code
            
            if response.history:
                results["redirects"] = [r.url for r in response.history]

            results["server"] = response.headers.get("Server", "Not Disclosed")

            headers_to_check = results["security_headers"].keys()
            for header in headers_to_check:
                match = next((h for h in response.headers if h.lower() == header.lower()), None)
                if match:
                    results["security_headers"][header]["present"] = True
                    results["security_headers"][header]["value"] = response.headers[match]

        except requests.exceptions.RequestException as e:
            results["error"] = str(e)

        return results
