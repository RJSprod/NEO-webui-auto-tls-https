"""Dependency setup for the AutoTLS extension.

AutoTLS needs three things: PyCA ``cryptography`` to build the self-signed
key/certificate pair, ``certifi`` for the public CA trust store it fuses that
certificate into, and ``hypercorn`` to serve the WebUI over HTTP/2 once TLS is on
(see scripts/auto_tls_http2.py; without it the WebUI simply stays on HTTP/1.1).

Earlier releases installed ``certipie==0.2.0`` instead.  That package pins an old
dependency generation (FastAPI, Hypercorn, Trio 0.20-era) and installing it into a
Forge Neo venv drags Trio backwards far enough that it can no longer be imported on
Python 3.13, which kills the WebUI during ``gradio -> httpx -> httpcore -> trio``
before startup ever reaches TLS.  It is deliberately not installed any more.

Nothing here touches Forge's own dependencies: an already-usable ``cryptography``
is left exactly as it is, and no package is ever pinned, downgraded or removed to
satisfy certificate generation.
"""

import launch

# Only used when nothing usable is installed yet; an existing install that passes the
# capability check below is never upgraded.  The floor is the first release that
# declares support for the Python 3.13 Forge Neo runs on - older releases still work
# and are still reused, they just are not what a fresh install should reach for.
CRYPTOGRAPHY_REQUIREMENT = "cryptography>=43.0.0"


def cryptography_is_usable() -> bool:
    """Whether the installed cryptography exposes everything scripts/auto_tls.py uses.

    Capability check rather than a version comparison, so a host that ships an
    older-but-working cryptography keeps it instead of being upgraded underneath
    the rest of its environment.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    except Exception:
        return False

    required = (
        (x509, ("CertificateBuilder", "SubjectAlternativeName", "DNSName", "IPAddress",
                "BasicConstraints", "KeyUsage", "ExtendedKeyUsage", "SubjectKeyIdentifier",
                "random_serial_number", "load_pem_x509_certificate")),
        (hashes, ("SHA256",)),
        (serialization, ("Encoding", "PrivateFormat", "PublicFormat", "NoEncryption",
                         "load_pem_private_key")),
        (rsa, ("generate_private_key",)),
        (NameOID, ("COMMON_NAME", "ORGANIZATION_NAME")),
        (ExtendedKeyUsageOID, ("SERVER_AUTH",)),
    )
    return all(hasattr(module, name) for module, names in required for name in names)


if not cryptography_is_usable():
    launch.run_pip(f'install "{CRYPTOGRAPHY_REQUIREMENT}"', "requirements for auto-tls")

if not launch.is_installed("certifi"):
    launch.run_pip("install certifi", "requirements for auto-tls")

# Pure Python, and it pins nothing the WebUI already has: Hypercorn wants h11 (which
# httpx and uvicorn already brought), h2, priority and wsproto.  The floor is the
# first release that supports every Python Forge Neo runs on.
HYPERCORN_REQUIREMENT = "hypercorn>=0.17"

if not launch.is_installed("hypercorn"):
    launch.run_pip(f'install "{HYPERCORN_REQUIREMENT}"', "requirements for auto-tls (HTTP/2)")
