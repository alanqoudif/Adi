"""Method + template + explicitly associated application origin correlation."""
import json
from urllib.parse import urlsplit

from adi.source.models import SourceRuntimeCorrelation
from adi.source.routes import route_matches


def correlate(snapshot, workspace):
    if snapshot.repository.stale:
        raise ValueError('stale source correlations cannot be used')
    origin = snapshot.repository.application_origin
    if not origin:
        return []
    host = urlsplit(origin).hostname
    hosts = {h.id: h.address for h in workspace.list_hosts()}
    exchanges = workspace.list_http_exchanges()
    result = []
    for endpoint in workspace.list_endpoints():
        if hosts.get(endpoint.host_id) != host:
            continue
        for route in snapshot.routes:
            if route.method not in json.loads(endpoint.methods_json) or not route_matches(route.path, endpoint.path):
                continue
            # Require a real exchange at this exact origin, not merely a similarly named host.
            if not any(e.method == route.method and urlsplit(e.url)._replace(path='', query='', fragment='').geturl() == origin
                       and urlsplit(e.url).path == endpoint.path for e in exchanges):
                continue
            result.append(SourceRuntimeCorrelation(route_id=route.id, endpoint_id=endpoint.id,
                method=route.method, runtime_path=endpoint.path, application_origin=origin,
                confidence=0.98 if route.confidence >= 0.9 else 0.9,
                reasons=['method matches', 'normalized route matches', 'operator application binding and observed origin match'],
                fingerprint=snapshot.repository.fingerprint))
    return result
