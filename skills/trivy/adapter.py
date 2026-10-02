def build_argv(target: str, parameters: dict, binary: str) -> list[str]:
    return [binary, 'fs', '--format', 'json', '--scanners', 'vuln,misconfig',
            '--offline-scan', '--skip-db-update', '--skip-java-db-update',
            '--skip-check-update', target]
