def build_argv(target: str, parameters: dict, binary: str) -> list[str]:
    return [binary, 'dir', target, '--report-format', 'json', '--report-path',
            parameters['report_path'], '--redact=100', '--no-banner']
