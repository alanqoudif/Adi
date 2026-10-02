"""Common metadata entities. These carry observations, never unverified findings."""
from pydantic import BaseModel, Field


class DNSRecord(BaseModel):
    name: str
    record_type: str
    value: str
    ttl: int | None = None


class TLSObservation(BaseModel):
    protocol: str | None = None
    cipher: str | None = None
    subject: str | None = None
    issuer: str | None = None
    not_after: str | None = None
    hostname_match: bool | None = None
    verification: str | None = None


class SMBShare(BaseModel):
    host: str
    port: int = 445
    name: str
    kind: str = 'unknown'
    comment: str = ''


class LDAPObservation(BaseModel):
    naming_contexts: list[str] = Field(default_factory=list)
    ldap_versions: list[str] = Field(default_factory=list)
    sasl_mechanisms: list[str] = Field(default_factory=list)


class NetworkFlowObservation(BaseModel):
    source_ip: str
    destination_ip: str
    source_port: str = ''
    destination_port: str = ''
    protocol: str = ''


class CredentialAuditObservation(BaseModel):
    success: bool
    account: str = ''
    service: str = ''
    candidate_reference: str = ''
