import re
from typing import Any, Dict
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests

from auditor.form_parser import extract_forms


class SQLInjectionTester:
    ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"SQL syntax",
        r"Warning.*mysql_",
        r"valid MySQL result",
        r"MySqlClient\.",
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_",
        r"SQLite/JDBCDriver",
        r"SQLite.Exception",
        r"System\.Data\.SqlClient\.SqlException",
        r"Microsoft OLE DB Provider for SQL Server",
        r"ORA-\d{5}",
        r"ODBC SQL Server Driver",
        r"Unclosed quotation mark after the character string",
    ]

    PAYLOADS = ["'", '"', "' OR '1'='1", '" OR "1"="1']

    def __init__(self, target_url: str, max_checks: int = 10):
        self.scheme_provided = target_url.startswith(("http://", "https://"))
        if not self.scheme_provided:
            self.url = "https://" + target_url
        else:
            self.url = target_url
        self.max_checks = max_checks
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "SecurityAuditor-SQLi/1.0"})

    def run_scan(self) -> Dict[str, Any]:
        results = {
            "url": self.url,
            "tested_vectors": 0,
            "forms_found": 0,
            "findings": [],
            "error": None,
        }

        try:
            baseline = self._fetch_initial_page()
        except requests.exceptions.RequestException as exc:
            results["error"] = str(exc)
            return results
        results["url"] = self.url

        forms = extract_forms(baseline.text)
        results["forms_found"] = len(forms)

        self._test_query_parameters(baseline, results)

        for form in forms:
            if results["tested_vectors"] >= self.max_checks:
                break
            self._test_form(form, baseline, results)

        return results

    def _fetch_initial_page(self) -> requests.Response:
        urls_to_try = [self.url]
        if not self.scheme_provided and self.url.startswith("https://"):
            urls_to_try.append("http://" + self.url[len("https://"):])

        last_error = None
        for candidate_url in urls_to_try:
            try:
                response = self.session.get(candidate_url, timeout=6, allow_redirects=True)
                response.raise_for_status()
                self.url = response.url
                return response
            except requests.exceptions.RequestException as exc:
                last_error = exc

        raise last_error

    def _same_host(self, candidate_url: str) -> bool:
        source = urlparse(self.url)
        candidate = urlparse(candidate_url)
        return candidate.netloc == "" or candidate.netloc == source.netloc

    def _test_query_parameters(self, baseline: requests.Response, results: Dict[str, Any]) -> None:
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            params = {"sql_probe": ["1"]}

        for name in list(params.keys()):
            for payload in self.PAYLOADS:
                if results["tested_vectors"] >= self.max_checks:
                    return
                test_params = {key: values[:] for key, values in params.items()}
                test_params[name] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                self._request_and_record("GET parameter", name, test_url, baseline, results)

    def _test_form(self, form: Dict[str, Any], baseline: requests.Response, results: Dict[str, Any]) -> None:
        action = form.get("action") or self.url
        method = (form.get("method") or "get").lower()
        action_url = urljoin(self.url, action)
        if not self._same_host(action_url):
            return

        data = {}
        probe_field = None
        for field in form.get("fields", []):
            name = field.get("name")
            if not name:
                continue
            field_type = (field.get("type") or "text").lower()
            if field_type in {"submit", "button", "image", "reset", "file"}:
                continue
            value = field.get("value", "1")
            if probe_field is None and field_type not in {"hidden", "checkbox", "radio"}:
                probe_field = name
            data[name] = value

        if not data:
            return
        if probe_field is None:
            probe_field = next(iter(data))

        for payload in self.PAYLOADS:
            if results["tested_vectors"] >= self.max_checks:
                return
            test_data = data.copy()
            test_data[probe_field] = payload
            results["tested_vectors"] += 1
            try:
                if method == "post":
                    response = self.session.post(action_url, data=test_data, timeout=6, allow_redirects=True)
                else:
                    response = self.session.get(action_url, params=test_data, timeout=6, allow_redirects=True)
            except requests.exceptions.RequestException:
                continue
            self._record_if_suspicious(response, baseline, f"{method.upper()} form field", probe_field, results)

    def _request_and_record(
        self,
        vector: str,
        parameter: str,
        test_url: str,
        baseline: requests.Response,
        results: Dict[str, Any],
    ) -> None:
        results["tested_vectors"] += 1
        try:
            response = self.session.get(test_url, timeout=6, allow_redirects=True)
        except requests.exceptions.RequestException:
            return
        self._record_if_suspicious(response, baseline, vector, parameter, results)

    def _record_if_suspicious(
        self,
        response: requests.Response,
        baseline: requests.Response,
        vector: str,
        parameter: str,
        results: Dict[str, Any],
    ) -> None:
        evidence = self._sql_error_evidence(response.text)
        if not evidence and response.status_code >= 500 and baseline.status_code < 500:
            evidence = f"Server error changed from {baseline.status_code} to {response.status_code}."

        if evidence:
            duplicate = any(
                item["location"] == vector and item["parameter"] == parameter
                for item in results["findings"]
            )
            if not duplicate:
                results["findings"].append({
                    "type": "Potential SQL Injection",
                    "location": vector,
                    "parameter": parameter,
                    "evidence": evidence,
                })

    def _sql_error_evidence(self, body: str) -> str:
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                return f"Response matched SQL error pattern: {pattern}"
        return ""
