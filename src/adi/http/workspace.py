"""HTTPWorkspace: the single path from "fetch this URL" to persisted,
typed knowledge — ties the HTTP client, HTML/tech extractors, and the
canonical Endpoint/Parameter/Session model together (spec Phase 3A/3D/3G).

Browser-driven discovery (Phase 3K/3L) and tool-driven discovery (ffuf,
feroxbuster, Phase 3I) both funnel through the same `_create_endpoint`
path used here, so the knowledge graph never ends up with two competing
models of "what endpoints exist."
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from adi.runtime.browser import BrowserVisitResult

from adi.http.client import HTTPClient
from adi.http.extractors import extract_html, fingerprint_from_cookies, fingerprint_from_headers
from adi.http.models import HTTPExchange, HTTPMethod
from adi.http.normalization import canonicalize_url, host_of, path_only
from adi.knowledge.observations import Observation, ObservationType
from adi.knowledge.workspace import Workspace

_SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)
_ROBOTS_PATH_RE = re.compile(r"^(?:Allow|Disallow)\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)


class HTTPWorkspace:
    def __init__(self, client: HTTPClient, workspace: Workspace, evidence_dir: Path):
        self.client = client
        self.workspace = workspace
        self.evidence_dir = evidence_dir
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    async def fetch(
        self,
        method: HTTPMethod | str,
        url: str,
        *,
        session_id: str = "anonymous",
        headers: dict[str, str] | None = None,
        body: str | None = None,
        follow_redirects: bool = False,
        source: str = "http_client",
    ) -> list[Observation]:
        _exchange, observations = await self.fetch_with_exchange(
            method, url, session_id=session_id, headers=headers, body=body,
            follow_redirects=follow_redirects, source=source,
        )
        return observations

    async def fetch_with_exchange(
        self,
        method: HTTPMethod | str,
        url: str,
        *,
        session_id: str = "anonymous",
        headers: dict[str, str] | None = None,
        body: str | None = None,
        follow_redirects: bool = False,
        source: str = "http_client",
    ) -> tuple[HTTPExchange, list[Observation]]:
        """Like `fetch`, but also returns the raw `HTTPExchange` — used by
        the orchestrator, which needs `exchange.error` to decide whether an
        `http_request` action was scope-blocked vs. simply failed."""
        exchange, body_text = await self.client.request(
            method, url, session_id=session_id, headers=headers, body=body,
            follow_redirects=follow_redirects, source=source,
        )
        self.workspace.get_or_create_session(session_id)
        observations = self._record(exchange, body_text, url)
        return exchange, observations

    def _record(self, exchange: HTTPExchange, body_text: str, requested_url: str) -> list[Observation]:
        canonical = canonicalize_url(exchange.request.url)
        host = host_of(canonical)

        evidence_path = None
        if body_text:
            evidence_path = str(self.evidence_dir / f"{self.workspace.assessment_id[-8:]}-{abs(hash(canonical))}.body")
            try:
                Path(evidence_path).write_text(body_text)
            except OSError:
                evidence_path = None

        title = None
        extraction = None
        if exchange.response and "html" in (exchange.response.content_type or "") and body_text:
            extraction = extract_html(canonical, body_text)
            title = extraction.title

        exchange.id = self.workspace.record_http_exchange(
            method=exchange.request.method.value,
            url=canonical,
            session_id=exchange.request.session_id,
            status=exchange.response.status if exchange.response else None,
            content_type=exchange.response.content_type if exchange.response else "",
            content_length=exchange.response.content_length if exchange.response else 0,
            body_hash=exchange.response.body_hash if exchange.response else "",
            title=title,
            error=exchange.error,
            source=exchange.source,
            evidence_path=evidence_path,
            redirects_json=json.dumps([r.model_dump() for r in exchange.redirects]),
            started_at=exchange.started_at,
            completed_at=exchange.completed_at,
        )

        observations: list[Observation] = []

        if exchange.error:
            observations.append(Observation(
                type=ObservationType.TOOL_ERROR, subject=requested_url,
                value={"tool": "http_client", "error": exchange.error}, source=exchange.source,
            ))
            self.workspace.record_observations(observations)
            return observations

        # the fetched URL itself is an endpoint
        observations.append(self._endpoint_observation(
            host, path_only(canonical), [exchange.request.method.value],
            requires_auth=False, source=exchange.source,
        ))

        for hop in exchange.redirects:
            if not hop.authorized:
                observations.append(Observation(
                    type=ObservationType.TOOL_ERROR, subject=hop.to_url,
                    value={"tool": "http_client", "note": "external redirect not followed",
                           "reason": hop.reason},
                    source=exchange.source,
                ))

        if exchange.response:
            for hint in fingerprint_from_headers(exchange.response.headers):
                observations.append(Observation(
                    type=ObservationType.TECHNOLOGY_FINGERPRINT, subject=host,
                    value={"name": hint.name, "confidence": hint.confidence, "source": hint.source},
                    source=exchange.source,
                    confidence={"high": 1.0, "medium": 0.6, "low": 0.3}[hint.confidence],
                ))
            cookie_names = [c.name for c in exchange.response.cookies]
            for hint in fingerprint_from_cookies(cookie_names):
                observations.append(Observation(
                    type=ObservationType.TECHNOLOGY_FINGERPRINT, subject=host,
                    value={"name": hint.name, "confidence": hint.confidence, "source": hint.source},
                    source=exchange.source,
                    confidence={"high": 1.0, "medium": 0.6, "low": 0.3}[hint.confidence],
                ))

        if extraction is not None:
            for hint in extraction.tech_hints:
                observations.append(Observation(
                    type=ObservationType.TECHNOLOGY_FINGERPRINT, subject=host,
                    value={"name": hint.name, "confidence": hint.confidence, "source": hint.source},
                    source=exchange.source,
                    confidence={"high": 1.0, "medium": 0.6, "low": 0.3}[hint.confidence],
                ))

            for link in extraction.links:
                if host_of(link) == host:
                    observations.append(self._endpoint_observation(
                        host, path_only(link), ["GET"], requires_auth=False, source="html_link",
                    ))

            for form in extraction.forms:
                if host_of(form.action) != host:
                    continue
                ep_obs = self._endpoint_observation(
                    host, path_only(form.action), [form.method], requires_auth=False, source="html_form",
                )
                observations.append(ep_obs)
                endpoint_id = ep_obs.value.get("_endpoint_id")
                for field_ in form.fields:
                    observations.append(Observation(
                        type=ObservationType.ENDPOINT_PARAMETER, subject=field_.name,
                        value={"endpoint_id": endpoint_id, "name": field_.name,
                               "location": "query" if form.method == "GET" else "body",
                               "required": field_.required},
                        source="html_form", confidence=1.0,
                    ))

            for js_url in extraction.js_fetch_calls:
                if host_of(js_url) == host:
                    observations.append(self._endpoint_observation(
                        host, path_only(js_url), ["GET"], requires_auth=False,
                        source="js_static_analysis", confidence=0.6,
                    ))

        self.workspace.record_observations(observations)
        return observations

    def _endpoint_observation(
        self, host: str, path: str, methods: list[str], *, requires_auth: bool,
        source: str, confidence: float = 1.0,
    ) -> Observation:
        """Creates the endpoint immediately (so callers can attach
        parameters to it in the same pass) and returns an Observation that
        documents the fact — `_endpoint_id` in its value is bookkeeping for
        `_record`, not part of the public Observation contract."""
        endpoint_id = self.workspace.upsert_endpoint(
            host_address=host, path=path, methods=methods, requires_auth=requires_auth,
            source=source, confidence=confidence,
        )
        return Observation(
            type=ObservationType.WEB_ENDPOINT, subject=f"{host}{path}",
            value={"host": host, "path": path, "methods": methods, "requires_auth": requires_auth,
                   "_endpoint_id": endpoint_id},
            source=source, confidence=confidence,
        )

    def record_browser_visit(self, result: BrowserVisitResult) -> list[Observation]:
        """Folds a `adi.runtime.browser.BrowserVisitResult` into the SAME
        canonical Endpoint/Parameter model used by direct HTTP requests,
        HTML link/form extraction, robots.txt/sitemap.xml, and ffuf/
        feroxbuster (spec Phase 3L) — browser-driven and HTTP-driven
        discovery are never two separate databases.

        The highest-value part of this is `result.network_requests`: real
        XHR/fetch calls the page actually made, observed by the browser —
        strictly higher confidence than the static regex-based JS-fetch
        extraction `adi.http.extractors` falls back to when no browser is
        available.
        """
        observations: list[Observation] = []
        host = host_of(result.url)

        observations.append(self._endpoint_observation(
            host, path_only(result.url), ["GET"], requires_auth=False, source="browser",
        ))

        for link in result.links:
            if host_of(link) == host:
                observations.append(self._endpoint_observation(
                    host, path_only(link), ["GET"], requires_auth=False, source="browser",
                ))

        for form in result.forms:
            if host_of(form.action) != host:
                continue
            ep_obs = self._endpoint_observation(
                host, path_only(form.action), [form.method], requires_auth=False, source="browser",
            )
            observations.append(ep_obs)
            endpoint_id = ep_obs.value.get("_endpoint_id")
            for field_name in form.field_names:
                observations.append(Observation(
                    type=ObservationType.ENDPOINT_PARAMETER, subject=field_name,
                    value={"endpoint_id": endpoint_id, "name": field_name,
                           "location": "query" if form.method == "GET" else "body", "required": True},
                    source="browser", confidence=1.0,
                ))

        for req in result.network_requests:
            if req.resource_type not in ("xhr", "fetch"):
                continue
            if host_of(req.url) != host:
                continue
            observations.append(self._endpoint_observation(
                host, path_only(req.url), [req.method], requires_auth=False,
                source="browser_network_capture", confidence=1.0,  # an observed request, not a guess
            ))

        self.workspace.record_observations(observations)
        return observations

    def _persist_exchange_only(self, exchange: HTTPExchange) -> None:
        """For lightweight discovery requests (robots.txt, sitemap.xml) that
        don't go through full HTML extraction but should still appear in
        the HTTP audit trail."""
        exchange.id = self.workspace.record_http_exchange(
            method=exchange.request.method.value,
            url=canonicalize_url(exchange.request.url),
            session_id=exchange.request.session_id,
            status=exchange.response.status if exchange.response else None,
            content_type=exchange.response.content_type if exchange.response else "",
            content_length=exchange.response.content_length if exchange.response else 0,
            body_hash=exchange.response.body_hash if exchange.response else "",
            title=None, error=exchange.error, source=exchange.source, evidence_path=None,
            redirects_json=json.dumps([r.model_dump() for r in exchange.redirects]),
            started_at=exchange.started_at, completed_at=exchange.completed_at,
        )

    async def discover_robots_and_sitemap(self, base_url: str, session_id: str = "anonymous") -> list[Observation]:
        """Phase 3E: low-cost discovery the planner can choose to run."""
        observations: list[Observation] = []
        host = host_of(base_url)

        netloc = urlsplit(base_url).netloc
        robots_url = canonicalize_url(f"{urlsplit(base_url).scheme}://{netloc}/robots.txt")
        exchange, body = await self.client.request("GET", robots_url, session_id=session_id, source="robots_txt")
        self._persist_exchange_only(exchange)
        if exchange.response and exchange.response.status == 200 and body:
            for match in _ROBOTS_PATH_RE.finditer(body):
                path = match.group(1).strip()
                if path and path != "/":
                    observations.append(self._endpoint_observation(
                        host, path, ["GET"], requires_auth=False, source="robots_txt", confidence=0.7,
                    ))
            sitemap_match = re.search(r"Sitemap:\s*(\S+)", body, re.IGNORECASE)
            if sitemap_match:
                observations += await self._discover_sitemap(sitemap_match.group(1), session_id)

        self.workspace.record_observations([o for o in observations if o.source == "robots_txt"])

        default_sitemap_url = canonicalize_url(f"{urlsplit(base_url).scheme}://{netloc}/sitemap.xml")
        observations += await self._discover_sitemap(default_sitemap_url, session_id)
        return observations

    async def _discover_sitemap(self, sitemap_url: str, session_id: str) -> list[Observation]:
        observations: list[Observation] = []
        exchange, body = await self.client.request("GET", sitemap_url, session_id=session_id, source="sitemap_xml")
        self._persist_exchange_only(exchange)
        if exchange.response and exchange.response.status == 200 and body:
            host = host_of(sitemap_url)
            for match in _SITEMAP_LOC_RE.finditer(body):
                loc = match.group(1).strip()
                if host_of(loc) == host:
                    observations.append(self._endpoint_observation(
                        host, path_only(loc), ["GET"], requires_auth=False,
                        source="sitemap_xml", confidence=0.9,
                    ))
            self.workspace.record_observations(observations)
        return observations
