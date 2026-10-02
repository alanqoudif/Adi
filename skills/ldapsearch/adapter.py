"""Reviewed ldapsearch typed adapter."""
from adi.tools.reviewed import build


def build_argv(target, parameters, binary):
    return build('ldapsearch', target, parameters, binary)
