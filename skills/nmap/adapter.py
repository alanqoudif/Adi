"""nmap argv construction. Always XML-to-stdout so the parser never has to
deal with nmap's human-readable text format."""

from __future__ import annotations


def build_argv(target: str, parameters: dict, binary: str) -> list[str]:
    from adi.tools.intelligence import safe_target
    from adi.tools.reviewed import ports_spec
    safe_target(target)
    argv = [binary, "-sV", "-oX", "-", "--open"]
    if parameters.get("max_rate"):
        argv += ["--max-rate", str(parameters["max_rate"])]
    ports = parameters.get("ports")
    if ports:
        argv += ["-p", ports_spec(ports)]
    argv.append(target)
    return argv
