"""Regression tests for scripts/auto_tls.py.

The extension is a script module: the host imports it and it configures cmd_opts as
a side effect.  These tests reproduce that exactly - a fake ``modules.shared`` is put
in place, the real file is executed, and the resulting files/environment/cmd_opts are
inspected.

Two host shapes are covered:

* Forge Neo - Gradio 4.40 / httpx 0.28, where the WebUI's own startup request
  verifies the certificate it just started serving;
* AUTOMATIC1111 - the baseline the repository has always claimed support for.

Run with ``python tests/test_auto_tls.py`` or ``pytest tests/test_auto_tls.py``.
"""

import contextlib
import datetime
import importlib.util
import io
import ipaddress
import os
import shutil
import ssl
import sys
import tempfile
import types
import unittest
from argparse import Namespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

AUTO_TLS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "auto_tls.py")

TLS_ENVIRONMENT = ("REQUESTS_CA_BUNDLE", "SSL_CERT_FILE")


def neo_cmd_opts(**overrides):
    """cmd_opts as Forge Neo builds it: --disable-tls-verify is store_false/default None."""
    options = dict(
        tls_keyfile=None,
        tls_certfile=None,
        disable_tls_verify=None,
        server_name=None,
        listen=False,
        port=None,
        self_sign=None,
        autotls_certs=None,
        autotls_bundle=None,
    )
    options.update(overrides)
    return Namespace(**options)


# AUTOMATIC1111 exposes the same TLS fields, so the shapes only differ in the stack
# behind them; the fake httpx module below is what distinguishes the two hosts.
a1111_cmd_opts = neo_cmd_opts


def read_bytes(path):
    with open(path, "rb") as handle:
        return handle.read()


def write_certificate(cert_path, key_path=None, common_name="example.invalid", days=365):
    """Write a standalone self-signed pair, standing in for user-supplied files."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=2))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )

    with open(cert_path, "wb") as handle:
        handle.write(certificate.public_bytes(serialization.Encoding.PEM))

    if key_path is not None:
        with open(key_path, "wb") as handle:
            handle.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))

    return certificate


class AutoTLSTestCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="autotls-test-")
        self.addCleanup(shutil.rmtree, self.root, True)

        self.previous_cwd = os.getcwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, self.previous_cwd)

        self.previous_environment = {name: os.environ.get(name) for name in TLS_ENVIRONMENT}
        self.addCleanup(self.restore_environment)

        self.previous_modules = {
            name: sys.modules.get(name)
            for name in ("modules", "modules.shared", "modules.paths_internal", "modules_forge")
        }
        self.addCleanup(self.restore_modules)

    def restore_environment(self):
        for name, value in self.previous_environment.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    def restore_modules(self):
        for name, value in self.previous_modules.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value

    # helpers -----------------------------------------------------------------

    def run_extension(self, cmd_opts, root=None):
        """Execute scripts/auto_tls.py the way the host does and return the module."""
        root = root or self.root

        modules = types.ModuleType("modules")
        modules.__path__ = []
        shared = types.ModuleType("modules.shared")
        shared.cmd_opts = cmd_opts
        paths_internal = types.ModuleType("modules.paths_internal")
        paths_internal.script_path = root

        sys.modules["modules"] = modules
        sys.modules["modules.shared"] = shared
        sys.modules["modules.paths_internal"] = paths_internal
        sys.modules.pop("modules_forge", None)

        spec = importlib.util.spec_from_file_location("autotls_under_test", AUTO_TLS)
        module = importlib.util.module_from_spec(spec)

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            spec.loader.exec_module(module)
        self.stdout, self.stderr = out.getvalue(), err.getvalue()

        return module

    def path(self, name):
        return os.path.join(self.root, name)

    def load_generated_certificate(self):
        with open(self.path("webui.cert"), "rb") as handle:
            return x509.load_pem_x509_certificate(handle.read())

    def san_values(self, certificate):
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        return set(san.get_values_for_type(x509.DNSName)) | set(san.get_values_for_type(x509.IPAddress))

    def assert_pair_matches(self):
        certificate = self.load_generated_certificate()
        with open(self.path("webui.key"), "rb") as handle:
            key = serialization.load_pem_private_key(handle.read(), password=None)

        as_der = lambda item: item.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.assertEqual(as_der(key), as_der(certificate))

    # automatic mode ----------------------------------------------------------

    def test_automatic_mode_generates_pair_and_enables_https(self):
        cmd_opts = neo_cmd_opts()
        self.run_extension(cmd_opts)

        self.assertTrue(os.path.exists(self.path("webui.key")))
        self.assertTrue(os.path.exists(self.path("webui.cert")))
        self.assert_pair_matches()

        self.assertEqual(cmd_opts.tls_keyfile, self.path("webui.key"))
        self.assertEqual(cmd_opts.tls_certfile, self.path("webui.cert"))
        self.assertTrue(os.path.isabs(cmd_opts.tls_keyfile))
        self.assertTrue(os.path.isabs(cmd_opts.tls_certfile))

    def test_automatic_mode_sets_gradio_ssl_verify_to_false(self):
        # Forge forwards this to Gradio as ssl_verify; False is what lets Gradio 4.40
        # reach its own /startup-events endpoint over the self-signed certificate.
        cmd_opts = neo_cmd_opts()
        self.run_extension(cmd_opts)

        self.assertIs(cmd_opts.disable_tls_verify, False)

    def test_generated_certificate_always_covers_loopback(self):
        self.run_extension(neo_cmd_opts())

        covered = self.san_values(self.load_generated_certificate())
        self.assertIn("localhost", covered)
        self.assertIn(ipaddress.ip_address("127.0.0.1"), covered)
        self.assertIn(ipaddress.ip_address("::1"), covered)

    def test_generated_certificate_is_a_server_certificate(self):
        self.run_extension(neo_cmd_opts())
        certificate = self.load_generated_certificate()

        basic = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        self.assertFalse(basic.ca)

        usages = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        self.assertIn(x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, usages)

        expires = getattr(certificate, "not_valid_after_utc", None)
        if expires is None:
            expires = certificate.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        remaining = expires - datetime.datetime.now(datetime.timezone.utc)
        self.assertGreater(remaining.days, 360)

    def test_private_key_is_unencrypted(self):
        self.run_extension(neo_cmd_opts())

        with open(self.path("webui.key"), "rb") as handle:
            serialization.load_pem_private_key(handle.read(), password=None)

    def test_existing_pair_is_reused(self):
        self.run_extension(neo_cmd_opts())
        first = self.load_generated_certificate().serial_number

        self.run_extension(neo_cmd_opts())
        self.assertEqual(self.load_generated_certificate().serial_number, first)

    def test_partial_pair_is_repaired(self):
        self.run_extension(neo_cmd_opts())
        first = self.load_generated_certificate().serial_number

        # The legacy code only regenerated when *both* files were gone, so a lone
        # surviving certificate was reported as a complete pair.
        os.remove(self.path("webui.key"))
        self.run_extension(neo_cmd_opts())

        self.assertTrue(os.path.exists(self.path("webui.key")))
        self.assertNotEqual(self.load_generated_certificate().serial_number, first)
        self.assert_pair_matches()

    def test_mismatched_pair_is_repaired(self):
        self.run_extension(neo_cmd_opts())
        write_certificate(self.path("webui.cert"), common_name="localhost")

        self.run_extension(neo_cmd_opts())
        self.assert_pair_matches()

    def test_expired_pair_is_repaired(self):
        self.run_extension(neo_cmd_opts())
        write_certificate(self.path("webui.cert"), self.path("webui.key"), common_name="localhost", days=-1)

        self.run_extension(neo_cmd_opts())
        certificate = self.load_generated_certificate()
        expires = getattr(certificate, "not_valid_after_utc", None)
        if expires is None:
            expires = certificate.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        self.assertGreater(expires, datetime.datetime.now(datetime.timezone.utc))

    def test_ui_reload_reuses_the_managed_pair(self):
        # A UI reload re-runs every script module with cmd_opts already pointing at
        # our own files; that must not read as a user-supplied pair.
        cmd_opts = neo_cmd_opts()
        self.run_extension(cmd_opts)
        first = self.load_generated_certificate().serial_number

        os.remove(self.path("webui.key"))
        self.run_extension(cmd_opts)

        self.assertTrue(os.path.exists(self.path("webui.key")))
        self.assertNotEqual(self.load_generated_certificate().serial_number, first)
        self.assertEqual(cmd_opts.tls_keyfile, self.path("webui.key"))

    # --listen ----------------------------------------------------------------

    def test_listen_adds_lan_identities_without_enabling_remote_access(self):
        cmd_opts = neo_cmd_opts(listen=True)
        self.run_extension(cmd_opts)

        covered = self.san_values(self.load_generated_certificate())
        self.assertIn("localhost", covered)
        self.assertIn(ipaddress.ip_address("127.0.0.1"), covered)
        self.assertIn(ipaddress.ip_address("::1"), covered)
        # localhost/127.0.0.1/::1 plus at least the machine hostname
        self.assertGreater(len(covered), 3)
        # 0.0.0.0 is a bind address, never a certificate identity
        self.assertNotIn(ipaddress.ip_address("0.0.0.0"), covered)
        # the extension must not turn remote access on by itself
        self.assertTrue(cmd_opts.listen)

    def test_server_name_becomes_the_common_name_and_a_san(self):
        self.run_extension(neo_cmd_opts(server_name="sd.lan"))

        certificate = self.load_generated_certificate()
        common = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        self.assertEqual(common, "sd.lan")
        self.assertIn("sd.lan", self.san_values(certificate))

    def test_wildcard_server_name_falls_back_to_localhost(self):
        self.run_extension(neo_cmd_opts(server_name="0.0.0.0", listen=True))

        certificate = self.load_generated_certificate()
        common = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        self.assertEqual(common, "localhost")
        self.assertNotIn(ipaddress.ip_address("0.0.0.0"), self.san_values(certificate))

    def test_custom_port_is_not_touched(self):
        cmd_opts = neo_cmd_opts(port=7865)
        self.run_extension(cmd_opts)

        self.assertEqual(cmd_opts.port, 7865)

    # trust bundle ------------------------------------------------------------

    def test_bundle_fuses_certifi_with_the_webui_certificate(self):
        import certifi

        self.run_extension(neo_cmd_opts())

        with open(self.path("webui.bundle"), encoding="utf-8") as handle:
            bundle = handle.read()
        with open(certifi.where(), encoding="utf-8") as handle:
            self.assertIn(handle.read().strip(), bundle)
        with open(self.path("webui.cert"), encoding="utf-8") as handle:
            self.assertIn(handle.read().strip(), bundle)

    def test_bundle_is_exported_to_requests_and_httpx(self):
        self.run_extension(neo_cmd_opts())

        self.assertEqual(os.environ["REQUESTS_CA_BUNDLE"], self.path("webui.bundle"))
        self.assertEqual(os.environ["SSL_CERT_FILE"], self.path("webui.bundle"))

    def test_bundle_verifies_the_generated_certificate(self):
        self.run_extension(neo_cmd_opts())

        context = ssl.create_default_context(cafile=self.path("webui.bundle"))
        context.load_verify_locations(cafile=self.path("webui.bundle"))
        self.assertTrue(context.get_ca_certs())

    def test_autotls_certs_are_appended_to_the_bundle(self):
        extra = self.path("extra.cert")
        write_certificate(extra, common_name="extra.invalid")

        self.run_extension(neo_cmd_opts(autotls_certs=[extra]))

        with open(self.path("webui.bundle"), encoding="utf-8") as handle:
            bundle = handle.read()
        with open(extra, encoding="utf-8") as handle:
            self.assertIn(handle.read().strip(), bundle)

    def test_autotls_bundle_replaces_the_generated_bundle(self):
        user_bundle = self.path("mine.bundle")
        write_certificate(user_bundle, common_name="mine.invalid")

        self.run_extension(neo_cmd_opts(autotls_bundle=user_bundle))

        self.assertEqual(os.environ["REQUESTS_CA_BUNDLE"], user_bundle)
        self.assertEqual(os.environ["SSL_CERT_FILE"], user_bundle)
        self.assertFalse(os.path.exists(self.path("webui.bundle")))

    def test_missing_autotls_bundle_is_reported_and_trust_is_left_alone(self):
        for name in TLS_ENVIRONMENT:
            os.environ.pop(name, None)

        self.run_extension(neo_cmd_opts(autotls_bundle=self.path("nope.bundle")))

        for name in TLS_ENVIRONMENT:
            self.assertNotIn(name, os.environ)
        self.assertIn("nope.bundle", self.stderr)
        # a failed bundle must never be reported as a working one
        self.assertNotIn("trust store ready", self.stdout)

    def test_missing_autotls_certs_are_reported_and_trust_is_left_alone(self):
        for name in TLS_ENVIRONMENT:
            os.environ.pop(name, None)

        self.run_extension(neo_cmd_opts(autotls_certs=[self.path("nope.cert")]))

        self.assertFalse(os.path.exists(self.path("webui.bundle")))
        for name in TLS_ENVIRONMENT:
            self.assertNotIn(name, os.environ)
        self.assertNotIn("trust store ready", self.stdout)

    def test_failed_bundle_still_enables_https(self):
        # The certificate is sound; only the Python trust bundle failed.  HTTPS still
        # goes ahead, including the value Gradio needs to reach its own endpoint.
        cmd_opts = neo_cmd_opts(autotls_bundle=self.path("nope.bundle"))
        self.run_extension(cmd_opts)

        self.assertEqual(cmd_opts.tls_certfile, self.path("webui.cert"))
        self.assertIs(cmd_opts.disable_tls_verify, False)

    # bring your own certificate ---------------------------------------------

    def test_supplied_pair_is_not_overwritten(self):
        key_path, cert_path = self.path("mine.key"), self.path("mine.cert")
        write_certificate(cert_path, key_path)
        before = (read_bytes(key_path), read_bytes(cert_path))

        cmd_opts = neo_cmd_opts(tls_keyfile=key_path, tls_certfile=cert_path)
        self.run_extension(cmd_opts)

        self.assertEqual((read_bytes(key_path), read_bytes(cert_path)), before)
        self.assertEqual(cmd_opts.tls_keyfile, key_path)
        self.assertEqual(cmd_opts.tls_certfile, cert_path)
        # the legacy branch only respected supplied files when --self-sign was passed
        self.assertFalse(os.path.exists(self.path("webui.key")))
        self.assertFalse(os.path.exists(self.path("webui.cert")))

    def test_supplied_pair_with_self_sign_is_not_overwritten(self):
        key_path, cert_path = self.path("mine.key"), self.path("mine.cert")
        write_certificate(cert_path, key_path)

        cmd_opts = neo_cmd_opts(tls_keyfile=key_path, tls_certfile=cert_path, self_sign=True)
        self.run_extension(cmd_opts)

        self.assertEqual(cmd_opts.tls_certfile, cert_path)
        self.assertFalse(os.path.exists(self.path("webui.cert")))

    def test_supplied_certificate_is_fused_into_the_bundle(self):
        key_path, cert_path = self.path("mine.key"), self.path("mine.cert")
        write_certificate(cert_path, key_path)

        self.run_extension(neo_cmd_opts(tls_keyfile=key_path, tls_certfile=cert_path, self_sign=True))

        with open(self.path("webui.bundle"), encoding="utf-8") as handle:
            bundle = handle.read()
        with open(cert_path, encoding="utf-8") as handle:
            self.assertIn(handle.read().strip(), bundle)

    def test_invalid_supplied_path_is_reported_and_nothing_is_generated(self):
        cmd_opts = neo_cmd_opts(tls_keyfile=self.path("missing.key"), tls_certfile=self.path("missing.cert"))
        self.run_extension(cmd_opts)

        self.assertFalse(os.path.exists(self.path("webui.key")))
        self.assertFalse(os.path.exists(self.path("webui.cert")))
        self.assertFalse(os.path.exists(self.path("webui.bundle")))
        # the message has to say which file is wrong
        self.assertIn("missing.key", self.stderr)
        self.assertIn("missing.cert", self.stderr)

    def test_self_sign_without_a_pair_is_reported(self):
        self.run_extension(neo_cmd_opts(self_sign=True))

        self.assertIn("--tls-keyfile", self.stderr)
        self.assertFalse(os.path.exists(self.path("webui.cert")))

    def test_unwritable_location_reports_the_path_and_leaves_tls_off(self):
        cmd_opts = neo_cmd_opts()
        self.run_extension(cmd_opts, root=os.path.join(self.root, "does", "not", "exist"))

        self.assertIn("webui.key", self.stderr)
        self.assertNotIn("trust store ready", self.stdout)
        self.assertIsNone(cmd_opts.tls_keyfile)
        self.assertIsNone(cmd_opts.tls_certfile)

    def test_half_supplied_pair_is_reported_and_nothing_is_generated(self):
        cert_path = self.path("mine.cert")
        write_certificate(cert_path)

        self.run_extension(neo_cmd_opts(tls_certfile=cert_path))

        self.assertFalse(os.path.exists(self.path("webui.cert")))

    def test_supplied_pair_leaves_ssl_verify_untouched(self):
        # The supplied certificate is trusted through the exported bundle, so the
        # value the user's own command line produced keeps working and is not
        # rewritten behind their back.
        key_path, cert_path = self.path("mine.key"), self.path("mine.cert")
        write_certificate(cert_path, key_path)

        cmd_opts = neo_cmd_opts(tls_keyfile=key_path, tls_certfile=cert_path)
        self.run_extension(cmd_opts)

        self.assertIsNone(cmd_opts.disable_tls_verify)

    def test_supplied_pair_is_exported_to_requests_and_httpx(self):
        # What makes leaving ssl_verify alone safe on Neo: Gradio's startup request
        # resolves trust through SSL_CERT_FILE.
        key_path, cert_path = self.path("mine.key"), self.path("mine.cert")
        write_certificate(cert_path, key_path)

        self.run_extension(neo_cmd_opts(tls_keyfile=key_path, tls_certfile=cert_path))

        self.assertEqual(os.environ["REQUESTS_CA_BUNDLE"], self.path("webui.bundle"))
        self.assertEqual(os.environ["SSL_CERT_FILE"], self.path("webui.bundle"))

    def test_explicit_disable_tls_verify_is_respected(self):
        key_path, cert_path = self.path("mine.key"), self.path("mine.cert")
        write_certificate(cert_path, key_path)

        # store_false: passing --disable-tls-verify yields False
        cmd_opts = neo_cmd_opts(tls_keyfile=key_path, tls_certfile=cert_path, disable_tls_verify=False)
        self.run_extension(cmd_opts)

        self.assertIs(cmd_opts.disable_tls_verify, False)

    # AUTOMATIC1111 regression ------------------------------------------------

    def test_a1111_automatic_mode_still_works(self):
        cmd_opts = a1111_cmd_opts()
        self.run_extension(cmd_opts)

        self.assertTrue(os.path.exists(self.path("webui.key")))
        self.assertTrue(os.path.exists(self.path("webui.cert")))
        self.assertEqual(cmd_opts.tls_certfile, self.path("webui.cert"))
        self.assertEqual(os.environ["REQUESTS_CA_BUNDLE"], self.path("webui.bundle"))
        self.assertIs(cmd_opts.disable_tls_verify, False)

    def test_a1111_supplied_pair_leaves_ssl_verify_untouched(self):
        key_path, cert_path = self.path("mine.key"), self.path("mine.cert")
        write_certificate(cert_path, key_path)

        cmd_opts = a1111_cmd_opts(tls_keyfile=key_path, tls_certfile=cert_path, self_sign=True)
        self.run_extension(cmd_opts)

        self.assertIsNone(cmd_opts.disable_tls_verify)

    def test_missing_cryptography_is_reported_clearly(self):
        # e.g. a WebUI launched with --skip-install before the extension was set up
        self.previous_modules["cryptography"] = sys.modules.get("cryptography")
        sys.modules["cryptography"] = None

        cmd_opts = neo_cmd_opts()
        self.run_extension(cmd_opts)

        self.assertIn("cryptography", self.stderr)
        self.assertIn("--skip-install", self.stderr)
        self.assertIsNone(cmd_opts.tls_certfile)
        self.assertNotIn("trust store ready", self.stdout)

    def test_certipie_is_never_imported(self):
        self.run_extension(neo_cmd_opts())

        self.assertNotIn("certipie", sys.modules)

    def test_ssl_verification_is_not_disabled_globally(self):
        self.run_extension(neo_cmd_opts())

        self.assertNotIn("PYTHONHTTPSVERIFY", os.environ)
        context = ssl.create_default_context()
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)


if __name__ == "__main__":
    unittest.main(verbosity=2)
