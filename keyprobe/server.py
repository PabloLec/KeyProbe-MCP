import base64
import hashlib
from pathlib import Path
from typing import Annotated, Optional

from fastmcp import FastMCP
from pydantic import Field

from .path_utils import resolve_path
from .summary import summarize_bytes

mcp = FastMCP(
    name="KeyProbe",
    instructions=(
        "Purpose: analyze certificate/keystore files and return structured JSON metadata. "
        "No network access, no file writes.\n\n"
        "Use me when: you need to identify the file format, list entries, and extract "
        "subjects/issuers, validity dates, key/signature algorithms, SANs/usages, and entry counts.\n"
        "Do NOT use me for: TLS handshakes, chain/revocation validation, conversions, or exporting private keys.\n\n"
        "How to call:\n"
        "- Local file → `analyze_from_local_path(path=...)` (path must resolve inside the server's sandbox/allowlist).\n"
        "- Base64 file → `analyze_from_b64_string(filename=..., content_b64=..., password=?)`.\n"
        "  `content_b64` MUST be RFC 4648 raw base64 of the file bytes (no data: URI, no whitespace/newlines).\n\n"
        "Inputs:\n"
        "- Supported: PEM, DER, PKCS#12, JKS/JCEKS/BKS/UBER, PKCS#7 (P7B), PKCS#8, OpenSSH.\n"
        "- `password` is optional and only required for protected PKCS#12/JKS/JCEKS/BKS.\n\n"
        "Outputs (both tools): a JSON object including `size`, `digest_sha256`, `format`, and—when available—"
        "`entries` with fields such as `type`, `subject`, `issuer`, `not_before`, `not_after`, "
        "`fingerprint_sha256`, `key_algo`, `key_size`, `sig_algo`, `san`, and `usages`.\n\n"
        "Prompts:\n"
        "- `audit_local_file` — audit a local path and produce a two-part report (bullets + compact JSON).\n"
        "- `audit_base64_file` — audit base64 content with the same output shape.\n\n"
        "Safety: read-only and idempotent; passwords are never logged or persisted; raw private key material is never returned."
    ),
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _analyze_from_bytes(
    name_key: str,
    name_val: str,
    data: bytes,
    password: Optional[str],
) -> dict:
    """
    Internal helper: calls the format analyzer and ensures stable top-level fields.
    """
    meta = summarize_bytes(data, filename=name_val, password=password)
    meta.setdefault("size", len(data))
    meta.setdefault("digest_sha256", _sha256(data))
    return {name_key: name_val, **meta}


@mcp.tool(
    description=(
        "Analyze a local certificate/keystore file and return a detailed JSON summary. "
        "Read-only and idempotent. Best for sandboxed setups where the server can read files."
    ),
    tags={"keyprobe", "x509", "analysis", "filesystem"},
    annotations={
        "title": "Analyze local file",
        "readOnlyHint": True,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
def analyze_from_local_path(
    path: Annotated[
        Path,
        Field(description="Local path to the target file."),
    ],
    password: Annotated[
        Optional[str],
        Field(
            description="Optional password for protected containers (e.g., PKCS#12) or keystores (JKS/JCEKS/BKS). Leave null if not required."
        ),
    ] = None,
) -> dict:
    """
    Analyze a file (PEM, DER, PKCS#12, JKS/JCEKS/BKS/UBER, PKCS#7, PKCS#8, OpenSSH)
    and return a JSON summary. Examples:

    - Minimal (no password):
      { "path": "/tmp/certs/server.pem" }

    - With password (PKCS#12 / JKS):
      { "path": "/tmp/keystore.p12", "password": "s3cr3t" }
    """
    p = resolve_path(str(path))
    data = p.read_bytes()
    return _analyze_from_bytes("path", str(p), data, password)


@mcp.tool(
    description=(
        "Analyze a certificate/keystore provided as base64 and return a JSON summary. "
        "Use this when the client cannot expose a local path (e.g., remote deployment). "
        "Read-only and idempotent."
    ),
    tags={"keyprobe", "x509", "analysis", "binary"},
    annotations={
        "title": "Analyze base64 content",
        "readOnlyHint": True,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
def analyze_from_b64_string(
    filename: Annotated[
        str,
        Field(
            description="Original filename (used for type heuristics only, not for reading from disk)."
        ),
    ],
    content_b64: Annotated[
        str,
        Field(description="RFC 4648 raw base64-encoded bytes of the file"),
    ],
    password: Annotated[
        Optional[str],
        Field(
            description="Optional password for protected containers (e.g., PKCS#12) or keystores (JKS/JCEKS/BKS). Leave null if not required."
        ),
    ] = None,
) -> dict:
    """
    Base64 variant of analysis. Examples:

    - PEM/DER without password:
      { "filename": "leaf.der", "content_b64": "<BASE64>" }

    - PKCS#12 with password:
      { "filename": "bundle.p12", "content_b64": "<BASE64>", "password": "s3cr3t" }
    """
    data = base64.b64decode(content_b64, validate=True)  # recommended explicit decode
    return _analyze_from_bytes("filename", filename, data, password)


@mcp.prompt(
    name="audit_local_file",
    description=(
        "Audit a local certificate/keystore by calling `analyze_from_local_path`, "
        "then produce a concise human-readable report and a compact JSON summary."
    ),
    tags={"keyprobe", "prompt", "audit"},
)
def audit_local_file(
    path: Annotated[
        str, Field(description="Local path within the server's sandbox/allowlist.")
    ],
    password: Annotated[
        str, Field(description="Password if required; empty string if not.")
    ] = "",
) -> str:
    return (
        "Task: Audit the certificate/keystore at the given local path.\n\n"
        "1) Call the MCP tool `analyze_from_local_path` with the following JSON arguments:\n"
        "```json\n"
        "{\n"
        f'  "path": "{path}",\n'
        f'  "password": ' + (f'"{password}"' if password else "null") + "\n"
        "}\n"
        "```\n\n"
        "2) From the returned JSON, extract: format, primary subject and issuer, not_before, "
        "not_after, key_algo, key_size, sig_algo, SANs, usages, and entry count. Flag issues:\n"
        "- expires within 30 days; SHA-1 signatures; RSA < 2048 bits; missing SAN for TLS; unknown key usages.\n\n"
        "OUTPUT EXACTLY TWO SECTIONS:\n"
        "A) Summary (2–4 bullet points)\n"
        "B) JSON on one line with keys: subject, issuer, not_after, key_algo, key_size, sig_algo, usages\n"
        "If the tool call fails or returns an error, output ERROR: <message> and stop. Do not invent results.\n"
    )


@mcp.prompt(
    name="audit_base64_file",
    description=(
        "Audit a base64-encoded certificate/keystore by calling `analyze_from_b64_string`, "
        "then produce a concise human-readable report and a compact JSON summary."
    ),
    tags={"keyprobe", "prompt", "audit"},
)
def audit_base64_file(
    filename: Annotated[
        str, Field(description="Logical filename, e.g., 'bundle.p12' or 'leaf.pem'.")
    ],
    content_b64: Annotated[
        str,
        Field(description="Base64-encoded raw file bytes (RFC 4648). No data: URI."),
    ],
    password: Annotated[
        str, Field(description="Password if required; empty string if not.")
    ] = "",
) -> str:
    return (
        "Task: Audit the provided base64-encoded certificate/keystore.\n\n"
        "IMPORTANT: `content_b64` MUST be the Base64 of the file's raw bytes (RFC 4648), "
        "without any `data:` URI prefix and without line breaks. "
        "If you start from a local path instead of base64, first read the file as binary "
        "and base64-encode it client-side, then pass the resulting string.\n\n"
        "1) Call the MCP tool `analyze_from_b64_string` with the following JSON arguments:\n"
        "```json\n"
        "{\n"
        f'  "filename": "{filename}",\n'
        f'  "content_b64": "{content_b64}",\n'
        f'  "password": ' + (f'"{password}"' if password else "null") + "\n"
        "}\n"
        "```\n\n"
        "2) From the returned JSON, extract: format, primary subject and issuer, not_before, "
        "not_after, key_algo, key_size, sig_algo, SANs, usages, and entry count. Flag issues:\n"
        "- expires within 30 days; SHA-1 signatures; RSA < 2048 bits; missing SAN for TLS; unknown key usages.\n\n"
        "OUTPUT EXACTLY TWO SECTIONS:\n"
        "A) Summary (2–4 bullet points)\n"
        "B) JSON on one line with keys: subject, issuer, not_after, key_algo, key_size, sig_algo, usages\n"
        "If the tool call fails or returns an error, output ERROR: <message> and stop. Do not invent results.\n"
    )


@mcp.prompt(
    name="explain_summary_json",
    description=(
        "Turn a previously returned KeyProbe summary JSON into a clear human-readable explanation, "
        "including expiry risk and weak-algorithm notes."
    ),
    tags={"keyprobe", "prompt", "explain"},
)
def explain_summary_json(
    summary_json: Annotated[
        str, Field(description="A JSON string as returned by KeyProbe tools.")
    ],
) -> str:
    return (
        "Given this KeyProbe JSON summary, explain it to a non-expert:\n"
        f"{summary_json}\n"
        "Explain: file format; number of entries; main certificate subject/issuer; "
        "validity window; key and signature algorithms; SANs/usages; and any risks "
        "(e.g., expires soon, weak algorithms). Keep it under 150 words."
    )


if __name__ == "__main__":
    mcp.run()
