"""Local, provider-independent index over sanitized source."""
import re

from adi.source.models import SourceLocation, SourceSnapshot


class SourceIndex:
    def __init__(self, snapshot: SourceSnapshot):
        if snapshot.repository.stale:
            raise ValueError('source index stale: re-index repository first')
        self.snapshot = snapshot

    def search_text(self, query: str, limit: int = 20) -> list[SourceLocation]:
        return self._search(lambda line: query.casefold() in line.casefold(), limit)

    def search_regex(self, pattern: str, limit: int = 20) -> list[SourceLocation]:
        if len(pattern) > 256:
            raise ValueError('regex too long')
        # Python re has no timeout: reject nested/repeated quantifiers and lookaround.
        if re.search(r'\)[*+{]|\(\?|\\[1-9]', pattern):
            raise ValueError('complex regex unsupported; use text search')
        regex = re.compile(pattern)
        return self._search(lambda line: regex.search(line[:2000]) is not None, limit)

    def _search(self, predicate, limit):
        results = []
        for f in self.snapshot.files:
            for n, line in enumerate(f.content.splitlines(), 1):
                if predicate(line):
                    results.append(SourceLocation(file=f.path, start_line=n, end_line=n, hash=f.hash))
                    if len(results) >= min(max(limit, 1), 100):
                        return results
        return results

    def search_symbol(self, name: str):
        return [s for s in self.snapshot.symbols if s.name == name][:20]

    def find_route(self, path: str, method: str = 'GET'):
        from adi.source.routes import route_matches
        return [r for r in self.snapshot.routes if r.method == method.upper() and route_matches(r.path, path)]

    def find_middleware(self, name: str):
        return [m for m in self.snapshot.middleware if m.name == name]

    def find_config(self, kind: str):
        return [c for c in self.snapshot.configs if kind.casefold() in c.kind.casefold()]

    def retrieve_context(self, location: SourceLocation, max_lines: int = 60, max_chars: int = 6000):
        f = next((f for f in self.snapshot.files if f.path == location.file and f.indexed), None)
        if f is None:
            return ''
        lines = f.content.splitlines()
        start = max(1, location.start_line)
        end = min(len(lines), location.end_line, start + min(max_lines, 100) - 1)
        return '\n'.join(f'{n}: {lines[n-1]}' for n in range(start, end + 1))[:min(max_chars, 10000)]
