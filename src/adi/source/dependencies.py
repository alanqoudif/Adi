"""Manifest and lockfile parsing, without executing package managers."""
from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET

import yaml

from adi.source.models import SourceDependency, SourceFramework, SourceLocation

MANIFESTS = {'package.json', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'requirements.txt',
             'poetry.lock', 'pyproject.toml', 'Pipfile.lock', 'go.mod', 'go.sum', 'pom.xml',
             'build.gradle', 'composer.json', 'composer.lock', 'Gemfile.lock'}
FRAMEWORKS = {'express': 'Express', 'fastapi': 'FastAPI', 'flask': 'Flask', 'django': 'Django',
              'next': 'Next.js', 'react': 'React', '@nestjs/core': 'NestJS',
              'laravel/framework': 'Laravel', 'spring-boot': 'Spring Boot', 'rails': 'Rails'}


def parse_dependencies(files):
    deps, diagnostics = [], []
    for f in files:
        name = f.path.split('/')[-1]
        if not f.indexed or name not in MANIFESTS:
            continue
        def add(package, version, ecosystem, direct='unknown', f=f):
            version = str(version)
            line = next((n for n, text in enumerate(f.content.splitlines(), 1)
                         if str(package) in text), 1)
            deps.append(SourceDependency(package=str(package), installed_version=version,
                ecosystem=ecosystem, source_manifest=f.path, direct_or_transitive=direct,
                location=SourceLocation(file=f.path, start_line=line, end_line=line, hash=f.hash)))
        try:
            if name == 'package.json':
                data = json.loads(f.content)
                for section in ('dependencies', 'devDependencies', 'optionalDependencies'):
                    for pkg, ver in data.get(section, {}).items():
                        add(pkg, ver, 'npm', 'direct')
            elif name == 'package-lock.json':
                data = json.loads(f.content)
                root_deps = data.get('packages', {}).get('', {}).get('dependencies', {})
                for path, meta in data.get('packages', {}).items():
                    if not path:
                        continue
                    pkg = meta.get('name') or path.rsplit('node_modules/', 1)[-1]
                    add(pkg, meta.get('version', ''), 'npm', 'direct' if pkg in root_deps else 'transitive')
                if not data.get('packages'):
                    def walk(entries, direct):
                        for pkg, meta in entries.items():
                            add(pkg, meta.get('version', ''), 'npm', direct)
                            walk(meta.get('dependencies', {}), 'transitive')
                    walk(data.get('dependencies', {}), 'direct')
            elif name == 'pnpm-lock.yaml':
                data = yaml.safe_load(f.content)
                for key in data.get('packages', {}):
                    key = key.lstrip('/')
                    match = re.match(r'(.+?)(?:@|/)(\d[^()]*)', key)
                    if match:
                        add(*match.groups(), 'npm')
            elif name == 'yarn.lock':
                for match in re.finditer(r'(?m)^([^\s#][^\n]+):\n\s+version\s+["\']([^"\']+)', f.content):
                    key, version = match.groups()
                    package = key.split(',')[0].strip('"\'').rsplit('@', 1)[0]
                    add(package, version, 'npm')
            elif name == 'requirements.txt':
                for line in f.content.splitlines():
                    match = re.match(r'\s*([\w.-]+)(?:\[[^]]+\])?\s*(==|>=|~=|<=|>|<)?\s*([^;#\s]*)', line)
                    if match and not line.lstrip().startswith(('#', '-')):
                        pkg, op, version = match.groups()
                        add(pkg, version if op == '==' else (op or '') + version, 'PyPI', 'direct')
            elif name in ('poetry.lock', 'pyproject.toml'):
                data = tomllib.loads(f.content)
                if name == 'poetry.lock':
                    for pkg in data.get('package', []):
                        add(pkg['name'], pkg['version'], 'PyPI', 'transitive')
                else:
                    for spec in data.get('project', {}).get('dependencies', []):
                        match = re.match(r'([\w.-]+)(.*)', spec)
                        if match:
                            add(match[1], match[2], 'PyPI', 'direct')
                    for pkg, spec in data.get('tool', {}).get('poetry', {}).get('dependencies', {}).items():
                        if pkg != 'python':
                            add(pkg, spec.get('version', '') if isinstance(spec, dict) else spec, 'PyPI', 'direct')
            elif name == 'Pipfile.lock':
                data = json.loads(f.content)
                for section in ('default', 'develop'):
                    for pkg, meta in data.get(section, {}).items():
                        add(pkg, meta.get('version', '').removeprefix('=='), 'PyPI')
            elif name in ('go.mod', 'go.sum'):
                for pkg, version in re.findall(r'(?m)^\s*(?:require\s+)?([\w./-]+)\s+(v[^\s]+)', f.content):
                    add(pkg, version.removesuffix('/go.mod'), 'Go', 'transitive' if name == 'go.sum' else 'unknown')
            elif name == 'pom.xml':
                tree = ET.fromstring(f.content)
                for d in tree.iter():
                    if d.tag.split('}')[-1] != 'dependency':
                        continue
                    values = {c.tag.split('}')[-1]: c.text or '' for c in d}
                    if values.get('artifactId'):
                        add(values.get('groupId', '') + ':' + values['artifactId'], values.get('version', ''), 'Maven')
            elif name == 'build.gradle':
                for group, pkg, ver in re.findall(r'''["']([\w.-]+):([\w.-]+):([^"']+)["']''', f.content):
                    add(group + ':' + pkg, ver, 'Maven')
            elif name.startswith('composer.'):
                data = json.loads(f.content)
                if name == 'composer.lock':
                    for pkg in data.get('packages', []) + data.get('packages-dev', []):
                        add(pkg['name'], pkg['version'], 'Packagist', 'transitive')
                else:
                    for pkg, ver in data.get('require', {}).items():
                        if pkg != 'php':
                            add(pkg, ver, 'Packagist', 'direct')
            elif name == 'Gemfile.lock':
                for pkg, ver in re.findall(r'(?m)^    ([\w.-]+) \(([^)]+)\)', f.content):
                    add(pkg, ver, 'RubyGems')
        except (ValueError, TypeError, KeyError, yaml.YAMLError, ET.ParseError):
            diagnostics.append(f'malformed manifest: {f.path}')
    unique = {(d.package, d.installed_version, d.source_manifest): d for d in deps}
    return list(unique.values()), diagnostics


def detect_frameworks(files, dependencies):
    found = {}
    for dep in dependencies:
        for name, framework in FRAMEWORKS.items():
            if name == dep.package.lower() or (name == 'spring-boot' and name in dep.package):
                found[framework] = SourceFramework(name=framework, confidence=0.95,
                    location=dep.location, signal='manifest dependency')
    for f in files:
        for name, framework in FRAMEWORKS.items():
            if framework in found:
                continue
            pattern = rf'''(?:from|import)\s+{re.escape(name)}\b|(?:require\(|from\s+)["']{re.escape(name)}["']'''
            match = re.search(pattern, f.content)
            if match:
                n = f.content.count('\n', 0, match.start()) + 1
                found[framework] = SourceFramework(name=framework, confidence=0.85,
                    location=SourceLocation(file=f.path, start_line=n, end_line=n, hash=f.hash),
                    signal='source import')
    return list(found.values())
