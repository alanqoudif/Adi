"""BrowserRuntime: Playwright-driven browser automation (spec Phase 3K/3L).

Not mandatory for simple static HTTP/HTML inspection — `adi.http` works
fully without it. This exists for JavaScript-heavy applications where
content only appears after client-side code runs (an SPA's XHR/fetch
calls, a form submitted via JS, etc).

`playwright` is imported lazily, exactly like `adi.runtime.docker_runtime`
imports `docker` lazily — the rest of Adi must work with this package (and
its browser binaries) absent. Typed operations only: there is no "ask the
LLM to write arbitrary JavaScript" interaction mode.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

try:
    from playwright.async_api import Error as PlaywrightError
    from playwright.async_api import TimeoutError as PlaywrightTimeoutError
    from playwright.async_api import async_playwright

    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False


class BrowserUnavailableError(RuntimeError):
    pass


class NetworkRequestCapture(BaseModel):
    """One request the browser made while a page was loaded/interacted
    with — a document load, an XHR, or a fetch() call. This is what lets
    Adi observe `GET /api/orders` firing from client-side JS without
    guessing at it via static regex (see `adi.http.extractors` for the
    lower-confidence static fallback used when no browser is available)."""

    method: str
    url: str
    resource_type: str  # "document" | "xhr" | "fetch" | "script" | ...


class FormSnapshot(BaseModel):
    action: str
    method: str = "GET"
    field_names: list[str] = Field(default_factory=list)


class BrowserVisitResult(BaseModel):
    url: str
    title: str | None = None
    html: str = ""
    links: list[str] = Field(default_factory=list)
    forms: list[FormSnapshot] = Field(default_factory=list)
    network_requests: list[NetworkRequestCapture] = Field(default_factory=list)
    screenshot_path: str | None = None


class BrowserRuntime:
    """One Chromium instance, reused across visits within an assessment."""

    def __init__(self, headless: bool = True):
        self.headless = headless
        self._playwright = None
        self._browser = None

    async def is_available(self) -> bool:
        if not _PLAYWRIGHT_AVAILABLE:
            return False
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                await browser.close()
            return True
        except (PlaywrightError, OSError):
            # covers "playwright installed but `playwright install` (the
            # browser binaries) was never run" and any other launch failure
            return False

    async def start(self) -> None:
        if not _PLAYWRIGHT_AVAILABLE:
            raise BrowserUnavailableError(
                "the 'playwright' package is not installed (pip install adi[browser] "
                "&& playwright install chromium)"
            )
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(headless=self.headless)

    async def stop(self) -> None:
        if self._browser is not None:
            await self._browser.close()
            self._browser = None
        if self._playwright is not None:
            await self._playwright.stop()
            self._playwright = None

    async def visit(
        self, url: str, *, timeout_ms: int = 15000, screenshot_path: str | None = None,
    ) -> BrowserVisitResult:
        """Navigate to `url`, wait for network activity to settle, and
        capture the DOM, links, forms, and every XHR/fetch/document request
        the page made — this is the browser-driven counterpart to
        `adi.http.workspace.HTTPWorkspace.fetch`."""
        if self._browser is None:
            raise BrowserUnavailableError("call start() before visit()")

        context = await self._browser.new_context()
        page = await context.new_page()
        captured: list[NetworkRequestCapture] = []

        def _on_request(request):
            captured.append(NetworkRequestCapture(
                method=request.method, url=request.url, resource_type=request.resource_type,
            ))

        page.on("request", _on_request)
        try:
            await page.goto(url, timeout=timeout_ms)
            try:
                await page.wait_for_load_state("networkidle", timeout=timeout_ms)
            except PlaywrightTimeoutError:
                pass  # best-effort — a page with long-polling never goes idle

            html = await page.content()
            title = await page.title()
            links = await page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
            raw_forms = await page.eval_on_selector_all(
                "form",
                "els => els.map(f => ({action: f.action, method: f.method, "
                "fields: Array.from(f.elements).map(e => e.name).filter(Boolean)}))",
            )
            forms = [
                FormSnapshot(action=f["action"], method=(f.get("method") or "GET").upper(),
                              field_names=f.get("fields", []))
                for f in raw_forms
            ]
            if screenshot_path:
                await page.screenshot(path=screenshot_path)
        finally:
            await context.close()

        return BrowserVisitResult(
            url=url, title=title, html=html, links=links, forms=forms,
            network_requests=captured, screenshot_path=screenshot_path,
        )
