from html.parser import HTMLParser
from typing import Dict, List


class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms: List[Dict[str, object]] = []
        self._active_form = None

    def handle_starttag(self, tag: str, attrs):
        attrs_dict = dict(attrs)
        if tag == "form":
            self._active_form = {
                "action": attrs_dict.get("action", ""),
                "method": attrs_dict.get("method", "get"),
                "fields": [],
            }
            return

        if self._active_form is None:
            return

        if tag in {"input", "textarea", "select"}:
            self._active_form["fields"].append({
                "name": attrs_dict.get("name"),
                "type": attrs_dict.get("type", "text"),
                "value": attrs_dict.get("value", ""),
            })

    def handle_endtag(self, tag: str):
        if tag == "form" and self._active_form is not None:
            self.forms.append(self._active_form)
            self._active_form = None


def extract_forms(html: str) -> List[Dict[str, object]]:
    parser = FormParser()
    parser.feed(html)
    return parser.forms
