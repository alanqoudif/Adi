"""Conservative data-flow-lite: patterns are observations, never proof of bypass."""
import re

from adi.source.models import (
    DataFlowStep,
    SourceAuthControl,
    SourceConfig,
    SourceDatabaseAccess,
    SourceLocation,
    SourceMiddleware,
)
from adi.source.retrieval import retrieve_route_context

PATTERNS = {
    'request_input': r'req\.(?:params|query|body)|request\.(?:args|json|form)|\b(?:order_id|item_id|id):\s*(?:int|str)',
    'validation': r'\b(?:sanitize|validate|escape|isnumeric|fullmatch)\b',
    'database': r'\.(?:findUnique|findById|findOne|query|execute|filter|get|fetchone)\s*\(',
    'authorization': r'(?:owner|user_id|tenant_id|organization_id|role|permission).*(?:!=|==|===|!==|in\b)|\b(?:authorize|check_owner|check_permission)\s*\(',
    'response': r'\breturn\b|res\.(?:json|send)\(',
}


def inspect_route(snapshot, route):
    slices = retrieve_route_context(snapshot, route)
    controls, flows = [], []
    for slice in slices:
        loc = SourceLocation.model_validate(slice['location'])
        for line in slice['code'].splitlines():
            n, _, text = line.partition(': ')
            if not n.isdigit():
                continue
            line_loc = loc.model_copy(update={'start_line': int(n), 'end_line': int(n)})
            for kind, pattern in PATTERNS.items():
                if re.search(pattern, text) and not text.lstrip().startswith('@'):
                    flows.append(DataFlowStep(kind=kind, expression=text.strip()[:400], location=line_loc))
                    if kind == 'authorization':
                        controls.append(SourceAuthControl(type='authorization',
                            behavior='ownership/role/tenant guard pattern observed; semantics require validation',
                            location=line_loc, confidence=0.65, route_id=route.id))
            for pattern, kind, behavior in [
                (r'Cookie\(|req\.cookies|request\.cookies|Authorization|authorization', 'session_extraction', 'cookie/header token extraction pattern observed'),
                (r'set_cookie|res\.cookie', 'cookie_configuration', 'cookie configuration inspected'),
                (r'jwt\.verify|verify_token|decode_token', 'token_verification', 'token verification call observed; parameters require review')]:
                if re.search(pattern, text):
                    controls.append(SourceAuthControl(type=kind, behavior=behavior,
                        location=line_loc, confidence=0.75, route_id=route.id))
            if re.search(r'HTTPException.*401|abort\(401|jwt\.verify|verify_token|status\(401\)|raise.*Unauthorized', text):
                controls.append(SourceAuthControl(type='authentication',
                    behavior='token/session verification or unauthorized rejection observed',
                    location=line_loc, confidence=0.8, route_id=route.id))
    return controls, flows, slices


def analyze(snapshot):
    for route in snapshot.routes:
        controls, flows, _slices = inspect_route(snapshot, route)
        snapshot.auth_controls.extend(controls)
        for name in route.middleware:
            symbols = [s for s in snapshot.symbols if s.name == name.split('.')[-1]]
            snapshot.middleware.append(SourceMiddleware(name=name,
                location=symbols[0].location if symbols else None,
                behavior=[c.behavior for c in controls], inspected=bool(symbols)))
        for step in flows:
            if step.kind == 'database':
                snapshot.database_access.append(SourceDatabaseAccess(kind='query_or_ORM',
                    location=step.location, expression=step.expression))
    for f in snapshot.files:
        for n, line in enumerate(f.content.splitlines(), 1):
            kind = ''
            if re.search(r'(?i)\bdebug\s*[=:]\s*(?:true|1)', line):
                kind = 'debug_enabled'
            elif re.search(r'(?i)(?:httponly|secure)\s*[=:]\s*false', line):
                kind = 'insecure_cookie'
            elif re.search(r'0\.0\.0\.0|::0', line):
                kind = 'public_bind'
            elif (f.path.endswith(('.tf', '.yaml', '.yml')) or f.path.split('/')[-1] == 'Dockerfile') and re.search(r'privileged:\s*true|USER\s+root|0\.0\.0\.0/0', line):
                kind = 'infra_unsafe_default'
            if kind:
                environment = 'development' if any(x in f.path.lower() for x in ('example', 'dev', 'test')) else 'unknown'
                snapshot.configs.append(SourceConfig(kind=kind, behavior=line.strip()[:300],
                    environment=environment, location=SourceLocation(file=f.path, start_line=n,
                    end_line=n, hash=f.hash)))
