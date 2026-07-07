import socket
import ssl
from datetime import datetime
from typing import Dict, Any
from urllib.parse import urlparse

class SSLChecker:
    def __init__(self, target_url: str):
        parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
        self.hostname = parsed.netloc or parsed.path

    def check_certificate(self) -> Dict[str, Any]:
        context = ssl.create_default_context()
        results = {
            "hostname": self.hostname,
            "valid": False,
            "issuer": {},
            "subject": {},
            "expiry_date": None,
            "days_remaining": None,
            "tls_version": "Unknown",
            "error": None
        }

        try:
            with socket.create_connection((self.hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    results["tls_version"] = cipher[1] if cipher else "Unknown"

                    if cert:
                        results["issuer"] = {item[0][0]: item[0][1] for item in cert.get("issuer", [])}
                        results["subject"] = {item[0][0]: item[0][1] for item in cert.get("subject", [])}

                        not_after_str = cert.get("notAfter")
                        if not_after_str:
                            expiry = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                            results["expiry_date"] = expiry.strftime("%Y-%m-%d %H:%M:%S UTC")
                            
                            delta = expiry - datetime.utcnow()
                            results["days_remaining"] = delta.days
                            results["valid"] = delta.days > 0
                        else:
                            results["error"] = "No expiration date found on certificate"
                    else:
                        results["error"] = "Failed to retrieve certificate details"
        except Exception as e:
            results["error"] = str(e)
            results["valid"] = False

        return results
