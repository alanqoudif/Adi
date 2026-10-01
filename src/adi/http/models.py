"""Typed HTTP models — the first-class HTTP subsystem (spec Phase 3A).

Nothing in Adi should treat HTTP as "a curl command." A request/response
pair becomes a typed `HTTPExchange`, persisted with sensitive headers
already redacted, so secrets never reach planner context, logs, or reports.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class HTTPMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class HTTPActionParameters(BaseModel):
    """Structured parameters for an `ActionType.HTTP_REQUEST` PlannedAction.
    The planner fills this in — it never generates a shell/curl command."""

    method: HTTPMethod = HTTPMethod.GET
    url: str
    session_id: str = "anonymous"
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    follow_redirects: bool = False
    max_redirects: int = 5


class CookieMetadata(BaseModel):
    name: str
    domain: str = ""
    path: str = "/"
    secure: bool = False
    http_only: bool = False
    # the value itself is never stored — only that this cookie exists


class HTTPParameterMetadata(BaseModel):
    name: str
    location: str = "body"  # body | query | path | header
    required: bool = True


class RedirectHop(BaseModel):
    from_url: str
    to_url: str
    status: int
    authorized: bool
    reason: str = ""


class HTTPRequest(BaseModel):
    method: HTTPMethod
    url: str
    headers: dict[str, str] = Field(default_factory=dict)  # already redacted
    body_size: int = 0
    session_id: str = "anonymous"


class HTTPResponse(BaseModel):
    status: int
    headers: dict[str, str] = Field(default_factory=dict)  # already redacted
    content_type: str = ""
    content_length: int = 0
    body_hash: str = ""
    body_preview: str = ""  # redacted, truncated, safe for logs/context
    title: str | None = None
    cookies: list[CookieMetadata] = Field(default_factory=list)


class HTTPExchange(BaseModel):
    """A single request/response pair, fully persisted. See
    `adi.http.workspace.HTTPWorkspace.record_exchange`."""

    id: str | None = None
    request: HTTPRequest
    response: HTTPResponse | None = None
    redirects: list[RedirectHop] = Field(default_factory=list)
    error: str | None = None
    source: str = "http_client"
    started_at: datetime
    completed_at: datetime
    evidence_path: str | None = None

    @property
    def elapsed_seconds(self) -> float:
        return (self.completed_at - self.started_at).total_seconds()

    @property
    def canonical_url(self) -> str:
        return self.request.url
