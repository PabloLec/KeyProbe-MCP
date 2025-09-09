# keyprobe/mcp_contracts.py
from __future__ import annotations
from typing import List, Optional
from pydantic import BaseModel, Field


class WarningItem(BaseModel):
    code: str = Field(..., examples=["CERT_SOON_EXPIRES"])
    message: str


class CertificateMeta(BaseModel):
    subject: str
    issuer: str
    not_before: str
    not_after: str
    algorithm: str
    san: List[str] = []


class FileSummary(BaseModel):
    format: str = Field(..., examples=["PEM", "DER", "PKCS12", "JKS", "PKCS7", "OPENSSH"])
    entries: int = 1
    digest_sha256: Optional[str] = None
    warnings: List[WarningItem] = []
