"""Reviewed smbclient typed adapter."""
from adi.tools.reviewed import build


def build_argv(target, parameters, binary):
    return build('smbclient', target, parameters, binary)
