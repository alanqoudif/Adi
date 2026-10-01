"""Deterministic HTML/response extraction (spec Phase 3D, 3G).

The LLM never parses HTML. Everything here uses the standard library's
`html.parser` plus a handful of well-known, documented heuristics for
technology fingerprinting — no guesswork is ever reported as a fact (a
heuristic hint carries an explicit, honest confidence level).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser

from adi.http.normalization import join_url

# Static regex-based extraction of `fetch(...)`/XHR-style calls from inline
# <script> content. This is a deliberately modest substitute for real
# browser network capture (Playwright, Phase 3K/3L) — it only sees what is
# littered directly in the HTML response, never what JS computes at
# runtime, so it is lower-confidence than an observed browser request.
_FETCH_CALL_RE = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|\$\.(?:get|post|ajax))\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)

_FORM_INPUT_TAGS = {"input", "textarea", "select"}

# name -> (technology, confidence)
_COOKIE_TECH_HINTS = {
    "connect.sid": ("Express", "medium"),
    "phpsessid": ("PHP", "medium"),
    "jsessionid": ("Java (Servlet container)", "medium"),
    "laravel_session": ("Laravel", "medium"),
    "csrftoken": ("Django", "low"),
}

# header value substring -> (technology, confidence)
_HEADER_TECH_HINTS = {
    "server": [],  # populated dynamically — the raw value itself is the fact
    "x-powered-by": [],
}


@dataclass
class FormField:
    name: str
    type: str = "text"
    required: bool = False


@dataclass
class FormInfo:
    action: str  # resolved absolute URL
    method: str = "GET"
    fields: list[FormField] = field(default_factory=list)


@dataclass
class TechHint:
    name: str
    confidence: str  # "high" | "medium" | "low"
    source: str


@dataclass
class HTMLExtractionResult:
    title: str | None = None
    links: list[str] = field(default_factory=list)
    forms: list[FormInfo] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    js_fetch_calls: list[str] = field(default_factory=list)
    tech_hints: list[TechHint] = field(default_factory=list)


class _Parser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.result = HTMLExtractionResult()
        self._in_title = False
        self._current_form: FormInfo | None = None
        self._script_buffer: list[str] = []
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        attrs_d = dict(attrs)
        if tag == "title":
            self._in_title = True
        elif tag == "a" and attrs_d.get("href"):
            self.result.links.append(join_url(self.base_url, attrs_d["href"]))
        elif tag == "form":
            self._current_form = FormInfo(
                action=join_url(self.base_url, attrs_d.get("action", self.base_url)),
                method=(attrs_d.get("method") or "GET").upper(),
            )
        elif tag in _FORM_INPUT_TAGS and self._current_form is not None:
            name = attrs_d.get("name")
            if name:
                self._current_form.fields.append(FormField(
                    name=name,
                    type=attrs_d.get("type", "text"),
                    required="required" in attrs_d,
                ))
        elif tag == "script":
            self._in_script = True
            self._script_buffer = []
            src = attrs_d.get("src")
            if src:
                self.result.scripts.append(join_url(self.base_url, src))
        elif tag == "meta":
            name = (attrs_d.get("name") or "").lower()
            content = attrs_d.get("content", "")
            if name == "generator" and content:
                self.result.tech_hints.append(TechHint(content, "medium", "meta_generator"))
        elif tag == "div" and attrs_d.get("id") == "__next":
            self.result.tech_hints.append(TechHint("Next.js", "medium", "dom_marker"))
        elif tag.startswith(("ng-", "v-")) or any(k.startswith(("ng-", "v-", "data-reactroot")) for k in attrs_d):
            if "data-reactroot" in attrs_d:
                self.result.tech_hints.append(TechHint("React", "low", "dom_marker"))

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            if self._current_form is not None:
                self.result.forms.append(self._current_form)
                self._current_form = None
        elif tag == "script":
            self._in_script = False
            script_text = "".join(self._script_buffer)
            for match in _FETCH_CALL_RE.finditer(script_text):
                self.result.js_fetch_calls.append(join_url(self.base_url, match.group(1)))

    def handle_data(self, data):
        if self._in_title:
            self.result.title = (self.result.title or "") + data
        if self._in_script:
            self._script_buffer.append(data)


def extract_html(base_url: str, html: str) -> HTMLExtractionResult:
    parser = _Parser(base_url)
    parser.feed(html)
    if parser.result.title:
        parser.result.title = parser.result.title.strip()
    return parser.result


def fingerprint_from_headers(headers: dict[str, str]) -> list[TechHint]:
    """High-confidence technology hints — the server told us directly."""
    hints: list[TechHint] = []
    lower = {k.lower(): v for k, v in headers.items()}
    if lower.get("server"):
        hints.append(TechHint(lower["server"], "high", "server_header"))
    if lower.get("x-powered-by"):
        hints.append(TechHint(lower["x-powered-by"], "high", "x_powered_by_header"))
    return hints


def fingerprint_from_cookies(cookie_names: list[str]) -> list[TechHint]:
    hints: list[TechHint] = []
    for name in cookie_names:
        hit = _COOKIE_TECH_HINTS.get(name.lower())
        if hit:
            hints.append(TechHint(hit[0], hit[1], "cookie_name"))
    return hints
