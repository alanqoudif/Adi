"""Reviewed ssh-keyscan typed adapter."""
from adi.tools.reviewed import build


def build_argv(target, parameters, binary):
    return build('ssh-keyscan', target, parameters, binary)
