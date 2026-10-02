"""Reviewed openssl typed adapter."""
from adi.tools.reviewed import build


def build_argv(target, parameters, binary):
    return build('openssl', target, parameters, binary)
