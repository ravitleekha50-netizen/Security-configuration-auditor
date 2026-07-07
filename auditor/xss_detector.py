from typing import Any, Dict, List
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests

from auditor.form_parser import extract_forms


class XSSDetector:
    def __init__(self, target_url: str, max_checks: int = 8):
        self.scheme_provided = target_url.startswith(("http://", "https://"))
        if not self.scheme_provided:
            self.url = "https://" + target_url
        else:
            self.url = target_url
        self.max_checks = max_checks
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "SecurityAuditor-XSS/1.0"})
        self.payload = "<script>ready_nest_xss_probe</script>"

    def run_scan(self) -> Dict[str, Any]:
        results = {
            "url": self.url,
            "tested_vectors": 0,
            "forms_found": 0,
            "findings": [],
            "error": None,
        }

        try:
            response = self._fetch_initial_page()
        except requests.exceptions.RequestException as exc:
            results["error"] = str(exc)
            return results
        results["url"] = self.url

        forms = extract_forms(response.text)
        results["forms_found"] = len(forms)

        self._test_query_parameters(results)

        for form in forms:
            if results["tested_vectors"] >= self.max_checks:
                break
            self._test_form(form, results)

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

    def _test_query_parameters(self, results: Dict[str, Any]) -> None:
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            params = {"xss_probe": [""]}

        for name in list(params.keys()):
            if results["tested_vectors"] >= self.max_checks:
                break
            test_params = {key: values[:] for key, values in params.items()}
            test_params[name] = [self.payload]
            test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
            self._request_and_record("GET parameter", name, test_url, results)

    def _test_form(self, form: Dict[str, Any], results: Dict[str, Any]) -> None:
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
            value = field.get("value", "")
            if probe_field is None and field_type not in {"hidden", "checkbox", "radio"}:
                probe_field = name
                value = self.payload
            data[name] = value

        if not data:
            return
        if probe_field is None:
            probe_field = next(iter(data))
            data[probe_field] = self.payload

        results["tested_vectors"] += 1
        try:
            if method == "post":
                response = self.session.post(action_url, data=data, timeout=6, allow_redirects=True)
            else:
                response = self.session.get(action_url, params=data, timeout=6, allow_redirects=True)
        except requests.exceptions.RequestException:
            return

        if self.payload in response.text:
            results["findings"].append({
                "type": "Reflected XSS",
                "location": f"{method.upper()} form field",
                "parameter": probe_field,
                "evidence": "Probe script was reflected unencoded in the response.",
            })

    def _request_and_record(self, vector: str, parameter: str, test_url: str, results: Dict[str, Any]) -> None:
        results["tested_vectors"] += 1
        try:
            response = self.session.get(test_url, timeout=6, allow_redirects=True)
        except requests.exceptions.RequestException:
            return

        if self.payload in response.text:
            results["findings"].append({
                "type": "Reflected XSS",
                "location": vector,
                "parameter": parameter,
                "evidence": "Probe script was reflected unencoded in the response.",
            })
