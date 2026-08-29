"""AutoTLS - automatic HTTPS for AUTOMATIC1111-style WebUIs, including Forge Neo.

The user-facing objectives are unchanged from the original extension:

* automatic mode generates (and then reuses) a ``webui.key``/``webui.cert`` pair,
  fuses the certificate into the certifi trust store as ``webui.bundle`` and points
  Python's HTTP clients at that bundle, so the WebUI comes up on https:// with no
  TLS command line flags at all;
* bring-your-own mode (``--tls-keyfile``/``--tls-certfile``, ``--self-sign``) keeps
  using the user's files and never overwrites them;
* ``--autotls-certs`` and ``--autotls-bundle`` keep their meaning.

Browser trust is deliberately out of scope - the generated certificate is
self-signed, so the browser warning is expected and has to be dismissed once.
Nothing here touches the operating system trust store.

Two host details make this work on Forge Neo specifically:

* the certificate is built with PyCA cryptography instead of certipie, which would
  otherwise drag the venv's async/HTTP stack backwards (see install.py);
* Neo hands ``cmd_opts.disable_tls_verify`` to Gradio as ``ssl_verify``, and Gradio
  4.40 uses that value for the internal httpx request it makes to its own
  ``/startup-events`` endpoint right after the HTTPS server starts.  Left unset that
  request verifies, rejects the self-signed certificate and the WebUI never finishes
  starting, so extension-managed mode sets the value to ``False``.  That is what
  removes the need for a manual ``--disable-tls-verify``; it is scoped to Gradio's
  own call and never disables SSL verification globally.
"""

import datetime
import importlib
import ipaddress
import os
import socket
import sys
import traceback

from modules.shared import cmd_opts

PREFIX = "[AutoTLS]"

KEY_NAME = "webui.key"
CERT_NAME = "webui.cert"
BUNDLE_NAME = "webui.bundle"

RSA_KEY_SIZE = 2048
CERT_VALIDITY_DAYS = 365

# Set on cmd_opts once we have pointed it at our own pair.  A UI reload re-runs every
# script module, and by then cmd_opts.tls_keyfile/tls_certfile hold the paths we wrote
# there - without this marker the second pass would mistake them for user-supplied
# files and switch into bring-your-own mode.
MANAGED_MARKER = "autotls_managed_pair"

# Addresses that are bind targets rather than something a client connects to; they
# must never end up as a certificate identity.
WILDCARD_BINDS = ("", "*", "0.0.0.0", "::", "[::]")


def log(message):
    print(f"{PREFIX} {message}")


def error(message):
    print(f"{PREFIX} ERROR: {message}", file=sys.stderr)


def host_label():
    """Name of the host WebUI, for logging only - never used to pick behaviour."""
    try:
        from modules_forge import forge_version
    except Exception:
        return "the WebUI"

    return "Forge Neo" if getattr(forge_version, "version", "") == "neo" else "Forge"


def opt(name, default=None):
    value = getattr(cmd_opts, name, default)
    return default if value is None else value


def webui_root():
    """Directory the generated artifacts live in.

    The original extension wrote to ``./webui.key`` and friends, i.e. the working
    directory.  The WebUI root is the same place in a normal launch but survives a
    process that was started from elsewhere, so prefer it - unless a pair from an
    older release is already sitting in the working directory, in which case keep
    using that one rather than silently generating a second pair.
    """
    cwd = os.path.abspath(os.getcwd())

    try:
        from modules.paths_internal import script_path
    except Exception:
        return cwd

    if not script_path:
        return cwd

    root = os.path.abspath(script_path)
    if root != cwd and os.path.exists(os.path.join(cwd, KEY_NAME)) and os.path.exists(os.path.join(cwd, CERT_NAME)):
        return cwd

    return root


def clean_path(value):
    """Normalise a path taken from the command line to an absolute path or None."""
    if not value:
        return None

    return os.path.abspath(os.path.expanduser(str(value).strip()))


def add_identity(dns_names, ip_addresses, value, discovered=False):
    """Record one certificate identity, sorting it into the DNS or IP bucket.

    ``discovered`` marks values that came out of interface probing rather than the
    command line, and are filtered down to addresses a client could realistically
    connect to.  Values we or the user asked for are taken as given - ``::1`` for
    instance is "reserved" as far as ipaddress is concerned, but it is exactly the
    identity https://[::1]:PORT/ needs.
    """
    if not value:
        return

    value = str(value).strip()
    if value.lower() in WILDCARD_BINDS:
        return

    # getaddrinfo hands back scoped IPv6 literals such as fe80::1%eth0
    address = value.split("%", 1)[0].strip("[]")

    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        lowered = value.lower()
        if lowered not in dns_names:
            dns_names.append(lowered)
        return

    if parsed.is_unspecified or parsed.is_multicast:
        return

    if discovered and (parsed.is_link_local or parsed.is_reserved):
        return

    if parsed not in ip_addresses:
        ip_addresses.append(parsed)


def discover_local_addresses():
    """Best-effort list of names/addresses a LAN client might use to reach this host.

    Everything here is optional: no extra dependency, and every probe is allowed to
    fail without stopping HTTPS from coming up on localhost.
    """
    found = []

    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = ""

    if hostname:
        found.append(hostname)

    # A connect() on a UDP socket sends no packets; it just asks the routing table
    # which local address would be used, which is the address LAN clients see.
    for family, probe in ((socket.AF_INET, ("10.255.255.255", 1)), (socket.AF_INET6, ("fd00::1", 1))):
        sock = None
        try:
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.settimeout(0.2)
            sock.connect(probe)
            found.append(sock.getsockname()[0])
        except Exception:
            pass
        finally:
            if sock is not None:
                sock.close()

    if hostname:
        try:
            for info in socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_UDP):
                found.append(info[4][0])
        except Exception:
            pass

    return found


def certificate_identities():
    """The identities the generated certificate has to cover."""
    dns_names = []
    ip_addresses = []

    # Always present, so https://localhost:PORT/ works no matter how Forge is launched.
    for value in ("localhost", "127.0.0.1", "::1"):
        add_identity(dns_names, ip_addresses, value)

    server_name = opt("server_name")
    add_identity(dns_names, ip_addresses, server_name)

    # Only reach for LAN identities when the user has already asked for remote access.
    # The extension never enables --listen itself.
    if opt("listen", False) or server_name:
        for value in discover_local_addresses():
            add_identity(dns_names, ip_addresses, value, discovered=True)

    return dns_names, ip_addresses


def common_name():
    server_name = opt("server_name")
    if server_name and str(server_name).strip().lower() not in WILDCARD_BINDS:
        # CN is capped at 64 characters; SANs carry the real identities anyway.
        return str(server_name).strip()[:64]

    return "localhost"


def build_self_signed(dns_names, ip_addresses, cn):
    """Build a self-signed server key/certificate pair, returned as PEM bytes."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)

    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Stable Diffusion WebUI AutoTLS"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    subject_alt_names = [x509.DNSName(n) for n in dns_names] + [x509.IPAddress(a) for a in ip_addresses]

    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        # a day of slack absorbs clock skew between this machine and its clients
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=CERT_VALIDITY_DAYS))
        .add_extension(x509.SubjectAlternativeName(subject_alt_names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )

    # Unencrypted, because nothing in the launch path can supply a key password and
    # the whole point of automatic mode is zero configuration.
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return key_pem, certificate.public_bytes(serialization.Encoding.PEM)


def write_atomic(path, data, mode=None):
    """Replace a file in one step, so a failure can never leave a half-written one."""
    temporary = f"{path}.autotls-tmp"

    with open(temporary, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())

    if mode is not None:
        try:
            os.chmod(temporary, mode)
        except OSError:
            pass

    os.replace(temporary, path)


def public_key_bytes(key_or_cert):
    from cryptography.hazmat.primitives import serialization

    return key_or_cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def managed_pair_problem(key_path, cert_path, dns_names, ip_addresses):
    """Why the existing managed pair cannot be reused, or None if it can be.

    Anything wrong here means the pair gets rebuilt.  The original code only
    regenerated when *both* files were missing, which left a half-deleted pair
    looking valid.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    missing = [path for path in (key_path, cert_path) if not os.path.exists(path)]
    if missing:
        return f"missing {', '.join(os.path.basename(path) for path in missing)}"

    try:
        with open(cert_path, "rb") as handle:
            certificate = x509.load_pem_x509_certificate(handle.read())
    except Exception as exception:
        return f"{os.path.basename(cert_path)} could not be read ({exception})"

    try:
        with open(key_path, "rb") as handle:
            key = serialization.load_pem_private_key(handle.read(), password=None)
    except Exception as exception:
        return f"{os.path.basename(key_path)} could not be read ({exception})"

    if public_key_bytes(key) != public_key_bytes(certificate):
        return f"{os.path.basename(key_path)} does not match {os.path.basename(cert_path)}"

    expires = getattr(certificate, "not_valid_after_utc", None)
    if expires is None:
        expires = certificate.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    if expires <= datetime.datetime.now(datetime.timezone.utc):
        return f"{os.path.basename(cert_path)} expired on {expires:%Y-%m-%d}"

    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return f"{os.path.basename(cert_path)} has no subject alternative names"

    covered = {name.lower() for name in san.get_values_for_type(x509.DNSName)}
    covered.update(san.get_values_for_type(x509.IPAddress))

    uncovered = [str(value) for value in list(dns_names) + list(ip_addresses) if value not in covered]
    if uncovered:
        return f"{os.path.basename(cert_path)} does not cover {', '.join(uncovered)}"

    return None


def ensure_managed_pair(key_path, cert_path):
    """Generate or reuse the extension's own key/certificate pair."""
    try:
        importlib.import_module("cryptography")
    except ImportError:
        error(
            "the 'cryptography' package is missing, so no certificate can be generated"
            " - restart without --skip-install so the extension installer can add it"
        )
        return False

    dns_names, ip_addresses = certificate_identities()

    problem = managed_pair_problem(key_path, cert_path, dns_names, ip_addresses)
    if problem is None:
        log("Existing key/certificate pair found")
        return True

    if os.path.exists(key_path) or os.path.exists(cert_path):
        log(f"Regenerating key/certificate pair: {problem}")
    else:
        log("Generating key/certificate pair...")

    try:
        key_pem, cert_pem = build_self_signed(dns_names, ip_addresses, common_name())
    except Exception as exception:
        error(f"could not build a self-signed certificate: {exception}")
        return False

    # Both blobs exist before either file is touched, so a failure above leaves any
    # previously working pair exactly as it was.
    for path, data, mode in ((key_path, key_pem, 0o600), (cert_path, cert_pem, 0o644)):
        try:
            write_atomic(path, data, mode)
        except OSError as exception:
            error(f"could not write '{path}': {exception}")
            return False

    identities = ", ".join([*dns_names, *(str(address) for address in ip_addresses)])
    log(f"Certificate covers {identities}")
    return True


def check_user_pair(key_path, cert_path):
    """Validate a user-supplied pair.  These files are never written to."""
    if not key_path and not cert_path:
        error("--self-sign needs a certificate to trust; pass --tls-keyfile and --tls-certfile too")
        return False

    if not key_path or not cert_path:
        missing = "--tls-certfile" if key_path else "--tls-keyfile"
        error(f"{missing} is missing; a key and a certificate are both needed to enable TLS")
        return False

    ok = True
    for flag, path in (("--tls-keyfile", key_path), ("--tls-certfile", cert_path)):
        if not os.path.exists(path):
            error(f"invalid path to {flag}: '{path}'")
            ok = False

    return ok


def build_bundle(bundle_path, cert_path, extra_certs):
    """Fuse the certifi trust store, the active certificate and any --autotls-certs."""
    import certifi

    sources = [certifi.where(), cert_path]
    sources.extend(extra_certs or [])

    chunks = []
    for source in sources:
        with open(source, "r", encoding="utf-8", errors="replace") as handle:
            chunk = handle.read()
        if not chunk.endswith("\n"):
            chunk += "\n"
        chunks.append(chunk)

    write_atomic(bundle_path, "".join(chunks).encode("utf-8"))


def apply_python_trust(bundle_path):
    """Point Python's HTTP clients at a trust bundle.

    REQUESTS_CA_BUNDLE is what the extension has always set.  SSL_CERT_FILE is the
    equivalent for httpx, which is what Gradio 4 / Forge Neo actually use.  Both point
    at the same fused bundle, so ordinary public CA trust is preserved.
    """
    os.environ["REQUESTS_CA_BUNDLE"] = bundle_path
    os.environ["SSL_CERT_FILE"] = bundle_path


def apply_ssl_verify():
    """Set the runtime value Forge forwards to Gradio as ssl_verify.

    Only ever called for the extension-managed self-signed pair.  Gradio 4.40 calls
    its own /startup-events endpoint over HTTPS using this value, and left unset
    (``--disable-tls-verify`` is a store_false argument, so the default is None) that
    request verifies and rejects our self-signed certificate, leaving the WebUI
    half-started.  False is scoped to that one internal call - it is not a global
    switch, and it has no effect on what the browser trusts.

    A user-supplied pair is left entirely alone: it is trusted through the bundle
    exported below, so the value the user's own command line produced still works.
    """
    if not hasattr(cmd_opts, "disable_tls_verify"):
        return

    cmd_opts.disable_tls_verify = False


def configure_trust(bundle_path, active_cert):
    """Select or build the Python trust bundle and export it.  Returns whether it worked."""
    user_bundle = clean_path(getattr(cmd_opts, "autotls_bundle", None))
    if user_bundle is not None:
        if not os.path.exists(user_bundle):
            error(f"could not open bundle file '{user_bundle}'; Python trust store left unchanged")
            return False

        apply_python_trust(user_bundle)
        return True

    extra_certs = [clean_path(path) for path in (getattr(cmd_opts, "autotls_certs", None) or [])]
    for path in extra_certs:
        if not os.path.exists(path):
            error(f"could not open certificate '{path}'; Python trust store left unchanged")
            return False

    try:
        build_bundle(bundle_path, active_cert, extra_certs)
    except Exception as exception:
        error(f"could not build the trust bundle '{bundle_path}': {exception}")
        return False

    apply_python_trust(bundle_path)
    return True


def report_listen(managed):
    if not opt("listen", False) and not opt("server_name"):
        return

    port = opt("port")
    where = f"https://<this host>:{port}/" if port else "https://<this host>:<port>/"
    log(f"Remote access is already enabled; LAN clients should use {where}")
    if managed:
        log("Remote browsers will show the same self-signed warning and have to accept it once")


def main():
    root = webui_root()
    key_path = os.path.join(root, KEY_NAME)
    cert_path = os.path.join(root, CERT_NAME)
    bundle_path = os.path.join(root, BUNDLE_NAME)

    user_key = clean_path(getattr(cmd_opts, "tls_keyfile", None))
    user_cert = clean_path(getattr(cmd_opts, "tls_certfile", None))

    # A UI reload re-runs this module with cmd_opts already pointing at our own pair.
    if getattr(cmd_opts, MANAGED_MARKER, False) and user_key == key_path and user_cert == cert_path:
        user_key = user_cert = None

    bring_your_own = bool(getattr(cmd_opts, "self_sign", None) or user_key or user_cert)

    if bring_your_own:
        if not check_user_pair(user_key, user_cert):
            return
        active_cert = user_cert
        log("Using the supplied key/certificate pair")
    else:
        if not ensure_managed_pair(key_path, cert_path):
            error("HTTPS not enabled; the WebUI will start over HTTP")
            return
        cmd_opts.tls_keyfile = key_path
        cmd_opts.tls_certfile = cert_path
        setattr(cmd_opts, MANAGED_MARKER, True)
        active_cert = cert_path

    if configure_trust(bundle_path, active_cert):
        log("Certificate trust store ready")

    # The certificate itself is sound either way, so HTTPS still goes ahead - a trust
    # bundle that could not be built is reported above rather than silently leaving
    # the WebUI unable to complete its own startup handshake.
    if not bring_your_own:
        apply_ssl_verify()

    log(f"HTTPS enabled for {host_label()}")
    report_listen(managed=not bring_your_own)


try:
    main()
except Exception:
    # Never take the WebUI down over TLS setup; say what happened instead.
    error("unexpected failure while configuring TLS")
    traceback.print_exc()
