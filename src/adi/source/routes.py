"""Deterministic AST (Python) and conservative syntax (Express) route plugins."""
from __future__ import annotations

import ast
import hashlib
import re
from urllib.parse import unquote, urlsplit

from adi.source.models import SourceLocation, SourceRoute, SourceSymbol


def normalize_route(path: str) -> str:
    path = re.sub(r'(?<=/):([A-Za-z_]\w*)(?:\([^)]*\))?', r'{\1}', path)
    path = re.sub(r'<(?:\w+:)?(\w+)>', r'{\1}', path)
    path = re.sub(r'\{(\w+):[^}]+\}', r'{\1}', path)
    return '/' + path.strip('/') if path != '/' else '/'


def route_matches(template: str, path: str) -> bool:
    path = unquote(urlsplit(path).path).rstrip('/') or '/'
    pattern = re.escape(normalize_route(template))
    pattern = re.sub(r'\\\{\w+\\\}', '[^/]+', pattern)
    return re.fullmatch(pattern, path) is not None


def _id(file, method, path):
    return 'route-' + hashlib.sha256(f'{file}:{method}:{path}'.encode()).hexdigest()[:16]


def python_routes(file):
    routes, symbols = [], []
    try:
        tree = ast.parse(file.content)
    except SyntaxError:
        return routes, symbols
    prefixes, router_middleware = {}, {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            for kw in node.value.keywords:
                if kw.arg == 'dependencies':
                    names = [ast.unparse(n.args[0]) for n in ast.walk(kw.value)
                             if isinstance(n, ast.Call) and n.args and ast.unparse(n.func).split('.')[-1] in ('Depends', 'Security')]
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            router_middleware[target.id] = names
                if kw.arg == 'prefix' and isinstance(kw.value, ast.Constant):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            prefixes[target.id] = str(kw.value.value)
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in ('include_router', 'register_blueprint') and node.args):
            obj = ast.unparse(node.args[0])
            for kw in node.keywords:
                if kw.arg == 'dependencies':
                    router_middleware.setdefault(obj, []).extend(ast.unparse(n.args[0]) for n in ast.walk(kw.value)
                        if isinstance(n, ast.Call) and n.args and ast.unparse(n.func).split('.')[-1] in ('Depends', 'Security'))
                if kw.arg in ('prefix', 'url_prefix') and isinstance(kw.value, ast.Constant):
                    prefixes[obj] = str(kw.value.value) + prefixes.get(obj, '')
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        location = SourceLocation(file=file.path, start_line=node.lineno,
                                  end_line=node.end_lineno, symbol=node.name, hash=file.hash)
        calls = sorted({ast.unparse(n.func) for n in ast.walk(node) if isinstance(n, ast.Call)})
        symbols.append(SourceSymbol(name=node.name, kind='function', location=location, calls=calls))
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                continue
            attr = decorator.func.attr.lower()
            if attr not in ('get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'route'):
                continue
            if not decorator.args or not isinstance(decorator.args[0], ast.Constant):
                continue
            if not isinstance(decorator.args[0].value, str):
                continue
            methods = [attr.upper()] if attr != 'route' else ['GET']
            for kw in decorator.keywords:
                if kw.arg == 'methods' and isinstance(kw.value, (ast.List, ast.Tuple)):
                    methods = [str(n.value).upper() for n in kw.value.elts if isinstance(n, ast.Constant)]
            middleware = []
            for n in ast.walk(node.args):
                if isinstance(n, ast.Call) and ast.unparse(n.func).split('.')[-1] in ('Depends', 'Security'):
                    middleware.extend(ast.unparse(a) for a in n.args)
            for kw in decorator.keywords:
                if kw.arg == 'dependencies':
                    for n in ast.walk(kw.value):
                        if isinstance(n, ast.Call) and n.args:
                            middleware.append(ast.unparse(n.args[0]))
            middleware += [ast.unparse(d.func) if isinstance(d, ast.Call) else ast.unparse(d)
                           for d in node.decorator_list if d is not decorator
                           and not (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                                    and d.func.attr.lower() in ('get', 'post', 'put', 'patch', 'delete', 'route'))]
            framework = 'FastAPI' if 'fastapi' in file.content.lower() else 'Flask'
            router = ast.unparse(decorator.func.value)
            middleware += router_middleware.get(router, [])
            path = normalize_route(prefixes.get(router, '') + decorator.args[0].value)
            for method in methods:
                routes.append(SourceRoute(id=_id(file.path, method, path), method=method,
                    path=path, handler=node.name, middleware=list(dict.fromkeys(middleware)),
                    location=location.model_copy(update={'start_line': decorator.lineno}),
                    framework=framework))
    return routes, symbols


def _closing(text: str, start: int, opening='(', closing=')') -> int:
    depth, quote, escape = 0, '', False
    for i in range(start, min(len(text), start + 20000)):
        char = text[i]
        if quote:
            if escape:
                escape = False
            elif char == '\\':
                escape = True
            elif char == quote:
                quote = ''
            continue
        if char in ('"', "'", '`'):
            quote = char
        elif char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return i
    return start


def express_routes(file):
    text, routes, symbols = file.content, [], []
    for match in re.finditer(r'(?:function\s+(\w+)\s*\(|(?:const|let|export\s+const)\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)', text):
        start = text.find('{', match.end())
        end = _closing(text, start, '{', '}') if start >= 0 else match.end()
        name = match.group(1) or match.group(2)
        loc = SourceLocation(file=file.path, start_line=text.count('\n', 0, match.start()) + 1,
            end_line=text.count('\n', 0, end) + 1, symbol=name, hash=file.hash)
        calls = re.findall(r'([\w.]+)\s*\(', text[match.start():end])
        symbols.append(SourceSymbol(name=name, kind='function', location=loc, calls=calls))
    global_middleware, mounts = {}, {}
    for match in re.finditer(r'(\w+)\.use\s*\(', text):
        end = _closing(text, match.end()-1)
        args = text[match.end():end].strip()
        mount = re.fullmatch(r'''["']([^"']+)["']\s*,\s*(\w+)''', args)
        if mount:
            mounts[mount.group(2)] = mount.group(1)
        elif re.fullmatch(r'[\w,\s]+', args):
            global_middleware.setdefault(match.group(1), []).extend(a.strip() for a in args.split(','))
    for match in re.finditer(r'''(\w+)\.(get|post|put|patch|delete|head|options)\s*\(\s*["']([^"']+)["']\s*,''', text):
        open_pos = text.find('(', match.start())
        end = _closing(text, open_pos)
        args = text[match.end():end].strip()
        named = re.fullmatch(r'[\w,\s]+', args)
        parts = [a.strip() for a in args.split(',')] if named else []
        handler = parts[-1] if parts else '<inline>'
        middleware = global_middleware.get(match.group(1), []) + (parts[:-1] if parts else [])
        loc = SourceLocation(file=file.path, start_line=text.count('\n', 0, match.start()) + 1,
            end_line=text.count('\n', 0, end) + 1, symbol=handler, hash=file.hash)
        path = normalize_route(mounts.get(match.group(1), '') + match.group(3))
        method = match.group(2).upper()
        routes.append(SourceRoute(id=_id(file.path, method, path), method=method, path=path,
            handler=handler, middleware=middleware, location=loc, framework='Express',
            confidence=0.85))
    return routes, symbols


ROUTE_PLUGINS = {'Python': python_routes, 'JavaScript': express_routes, 'TypeScript': express_routes}


def discover_routes(files):
    routes, symbols = [], []
    for file in files:
        if file.indexed and file.language in ROUTE_PLUGINS:
            r, s = ROUTE_PLUGINS[file.language](file)
            routes.extend(r)
            symbols.extend(s)
    return routes, symbols
