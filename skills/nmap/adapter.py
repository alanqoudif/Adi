"""nmap argv construction. Always XML-to-stdout so the parser never has to
deal with nmap's human-readable text format."""

from __future__ import annotations


def build_argv(target: str, parameters: dict, binary: str) -> list[str]:
    argv = [binary, "-sV", "-oX", "-", "--open"]
    ports = parameters.get("ports")
    if ports:
        argv += ["-p", str(ports)]
    argv.append(target)
    return argv
