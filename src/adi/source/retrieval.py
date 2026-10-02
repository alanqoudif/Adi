"""Bounded route -> handler -> middleware -> service/policy context."""
from adi.source.index import SourceIndex


def retrieve_route_context(snapshot, route, max_chars: int = 12000, max_slices: int = 8):
    index = SourceIndex(snapshot)
    locations = [route.location]
    queue = [route.handler, *route.middleware]
    visited = set()
    while queue and len(locations) < max_slices:
        name = queue.pop(0).split('.')[-1]
        if name in visited:
            continue
        visited.add(name)
        for symbol in index.search_symbol(name):
            if symbol.location not in locations:
                locations.append(symbol.location)
            queue.extend(symbol.calls)
            if len(locations) >= max_slices:
                break
    result, budget = [], min(max_chars, 16000)
    for loc in locations[:max_slices]:
        code = index.retrieve_context(loc, max_chars=min(4000, budget))
        if not code or budget <= 0:
            break
        code = code[:budget]
        result.append({'location': loc.model_dump(), 'code': code})
        budget -= len(code)
    return result
