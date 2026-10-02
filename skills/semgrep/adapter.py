from pathlib import Path


def build_argv(target: str, parameters: dict, binary: str) -> list[str]:
    rules = Path(__file__).parent / 'rules.yaml'
    return [binary, 'scan', '--config', str(rules), '--json', '--metrics=off',
            '--disable-version-check', '--no-git-ignore', target]
