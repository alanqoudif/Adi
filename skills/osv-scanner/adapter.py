def build_argv(target: str, parameters: dict, binary: str) -> list[str]:
    return [binary, 'scan', 'source', '--format', 'json', '--offline',
            '--recursive', target]
