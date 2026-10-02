"""Reviewed enum4linux-ng typed adapter."""
from adi.tools.reviewed import build


def build_argv(target, parameters, binary):
    return build('enum4linux-ng', target, parameters, binary)
