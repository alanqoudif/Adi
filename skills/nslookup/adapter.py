"""Reviewed nslookup typed adapter."""
from adi.tools.reviewed import build


def build_argv(target, parameters, binary):
    return build('nslookup', target, parameters, binary)
