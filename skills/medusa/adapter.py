"""Authentication uses CredentialAuditRequest through the central executor."""
from adi.tools.authentication import build_auth_argv


def build_argv(target, parameters, binary):
    raise ValueError("use the gated CredentialAuditRequest executor")


def build_candidate(request, account, candidate, binary):
    return build_auth_argv('medusa', request, account, candidate, binary)
