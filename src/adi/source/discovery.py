"""Bounded repository walk, without symlink traversal or executable imports."""
from __future__ import annotations

import fnmatch
import hashlib
import os
from dataclasses import asdict, dataclass
from pathlib import Path

from adi.source.languages import detect_language
from adi.source.models import SourceFile
from adi.source.secrets import redact_code, scan_secrets, secret_matches

EXCLUDED = {'.git', 'node_modules', 'dist', 'build', 'coverage', 'vendor', '.venv', 'venv',
            '__pycache__', '.adi', '.pytest_cache', '.ruff_cache'}


@dataclass(frozen=True)
class DiscoveryLimits:
    max_file_size: int = 512_000
    max_indexed_files: int = 5000
    max_total_indexed_bytes: int = 20_000_000
    max_discovered_files: int = 20_000

    def __post_init__(self):
        if any(v <= 0 for v in asdict(self).values()):
            raise ValueError('source limits must be positive')


def ignored(path: str, rules: list[tuple[str, str]], directory: bool = False) -> bool:
    result = False
    for base, rule in rules:
        if base and not path.startswith(base + '/'):
            continue
        rel = path[len(base) + 1:] if base else path
        negate = rule.startswith('!')
        pattern = rule[1:] if negate else rule
        anchored = pattern.startswith('/')
        pattern = pattern.strip('/')
        if not pattern:
            continue
        if '/' in pattern or anchored:
            matches = fnmatch.fnmatchcase(rel, pattern) or rel.startswith(pattern + '/')
            if pattern.startswith('**/'):
                matches = matches or fnmatch.fnmatchcase(rel, pattern[3:])
        else:
            matches = any(fnmatch.fnmatchcase(part, pattern) for part in rel.split('/'))
        if matches:
            result = not negate
    return result


def discover(root: Path, limits: DiscoveryLimits, previous_files=None):
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError('source repository must be a readable directory')
    files, secrets, rules = [], [], []
    previous = {f.path: f for f in previous_files or []}
    total, indexed, discovered = 0, 0, 0
    values = set()
    digest = hashlib.sha256()
    for directory, dirs, names in os.walk(root, followlinks=False):
        base = Path(directory).relative_to(root).as_posix()
        base = '' if base == '.' else base
        for ignore_name in ('.gitignore', '.adiignore'):
            ignore_file = Path(directory) / ignore_name
            if (ignore_file.is_file() and not ignore_file.is_symlink()
                    and ignore_file.stat().st_size <= limits.max_file_size):
                data = ignore_file.read_bytes()
                digest.update(data)
                rules.extend((base, r.strip()) for r in data.decode('utf-8', errors='replace').splitlines()
                                 if r.strip() and not r.lstrip().startswith('#'))
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED
                         and not (Path(directory) / d).is_symlink()
                         and not ignored('/'.join(filter(None, (base, d))), rules, True))
        for name in sorted(names):
            discovered += 1
            if discovered > limits.max_discovered_files:
                digest.update(b'DISCOVERY_LIMIT')
                _scrub_duplicates(files, values)
                return files, secrets, digest.hexdigest(), ['discovery limit reached; index incomplete']
            path = Path(directory) / name
            rel = path.relative_to(root).as_posix()
            if path.is_symlink() or not path.is_file() or ignored(rel, rules):
                continue
            size = path.stat().st_size
            f = SourceFile(path=rel, language=detect_language(rel), size=size, mtime_ns=path.stat().st_mtime_ns)
            digest.update(f'{rel}:{size}:{path.stat().st_mtime_ns}'.encode())
            if size > limits.max_file_size:
                f.skip_reason = 'max_file_size'
            elif indexed >= limits.max_indexed_files:
                f.skip_reason = 'max_indexed_files'
            elif total + size > limits.max_total_indexed_bytes:
                f.skip_reason = 'max_total_indexed_bytes'
            elif (rel in previous and previous[rel].indexed and previous[rel].size == size
                  and previous[rel].mtime_ns == f.mtime_ns):
                f = previous[rel]
                digest.update(f.hash.encode())
                indexed += 1
                total += size
            else:
                try:
                    # Bounded read even when a file grows between stat and read.
                    allowance = min(limits.max_file_size, limits.max_total_indexed_bytes - total)
                    with path.open('rb') as stream:
                        raw = stream.read(allowance + 1)
                    total += len(raw)
                    f.hash = hashlib.sha256(raw).hexdigest()
                    digest.update(f.hash.encode())
                    if len(raw) > limits.max_file_size:
                        f.skip_reason = 'max_file_size'
                    elif len(raw) > allowance:
                        f.skip_reason = 'max_total_indexed_bytes'
                    elif len(raw) != size or path.stat().st_mtime_ns != f.mtime_ns:
                        f.skip_reason = 'changed_during_discovery'
                    elif b'\x00' in raw:
                        f.skip_reason = 'binary'
                    else:
                        text = raw.decode('utf-8')
                        secrets.extend(scan_secrets(text, rel))
                        values.update(value for _, _, _, value in secret_matches(text))
                        f.content = redact_code(text)
                        f.indexed = True
                        indexed += 1
                except (UnicodeDecodeError, OSError):
                    f.skip_reason = 'binary_or_unreadable'
            files.append(f)
    _scrub_duplicates(files, values)
    return files, secrets, digest.hexdigest(), []


def _scrub_duplicates(files, values):
    if not values:
        return
    import re
    pattern = re.compile('|'.join(re.escape(v) for v in sorted(values, key=len, reverse=True)))
    for file in files:
        file.content = pattern.sub(lambda m: '<redacted>' + '\n' * m.group().count('\n'), file.content)
