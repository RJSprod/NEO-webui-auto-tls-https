"""Regression tests for scripts/auto_tls_http2.py.

The module is a script module like auto_tls.py: the host imports it and, as a side
effect, it wraps Gradio's ``start_server``.  These tests execute the real file
against a fake ``modules.shared`` and either a fake Gradio server module (for the
wrapping rules, so they need no Gradio) or the real one (for the launch itself,
skipped where Gradio is not installed).

What is asserted, in order of importance:

* with TLS, the app is served over HTTP/2 - the ALPN answer is ``h2`` and an
  HTTP/2 client gets an HTTP/2 response - and HTTP/1.1 clients still work;
* without TLS, with ``--autotls-http1``, without Hypercorn, or when Hypercorn
  fails to start, Gradio's own ``start_server`` runs with the same arguments;
* the port rules are Gradio's: a taken port is skipped in a scan and refused
  when it was asked for by number;
* ``close()`` frees the port, which a UI reload depends on;
* a stream opened on the page's connection outlives a thousand other requests
  on it - Hypercorn's default would close the connection, and the page, there;
* a real ``gr.Blocks`` launched through the wrap comes up, answers over HTTP/2,
  closes, and launches again on the same port.

Run with ``python tests/test_auto_tls_http2.py`` or ``pytest tests/test_auto_tls_http2.py``.
"""

import asyncio
import contextlib
import datetime
import http.client
import importlib
import importlib.util
import io
import os
import shutil
import socket
import ssl
import sys
import tempfile
import types
import unittest
import unittest.mock
from argparse import Namespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

HTTP2_SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "auto_tls_http2.py")

HAVE_HYPERCORN = importlib.util.find_spec("hypercorn") is not None and importlib.util.find_spec("h2") is not None
HAVE_GRADIO = importlib.util.find_spec("gradio") is not None
try:
    import httpx  # noqa: F401
    HAVE_HTTPX_H2 = importlib.util.find_spec("h2") is not None
except Exception:  # pragma: no cover - environment without httpx
    HAVE_HTTPX_H2 = False


def cmd_opts_for(**overrides):
    options = dict(tls_keyfile=None, tls_certfile=None, autotls_http1=False)
    options.update(overrides)
    return Namespace(**options)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def port_is_free(port):
    try:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False


def write_pair(cert_path, key_path):
    """A self-signed localhost pair, the shape auto_tls.py generates."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1")),
        ]), critical=False)
        .sign(key, hashes.SHA256())
    )
    with open(cert_path, "wb") as handle:
        handle.write(certificate.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as handle:
        handle.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))


async def tiny_app(scope, receive, send):
    """The smallest ASGI app that answers HTTP and says which HTTP it was asked over."""
    if scope["type"] == "lifespan":
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
    if scope["type"] != "http":
        return
    body = b"ok"
    await send({"type": "http.response.start", "status": 200, "headers": [
        (b"content-type", b"text/plain"),
        (b"content-length", str(len(body)).encode()),
        (b"x-http-version", scope.get("http_version", "?").encode()),
    ]})
    await send({"type": "http.response.body", "body": body})


async def ticking_app(scope, receive, send):
    """tiny_app plus ``/stream``: a response that never ends, one tick every 50 ms.

    The shape of Gradio's heartbeat and queue streams - what a page keeps open
    on its connection for as long as the page is open.
    """
    if scope["type"] == "http" and scope["path"] == "/stream":
        await send({"type": "http.response.start", "status": 200, "headers": [
            (b"content-type", b"text/event-stream"),
        ]})
        while True:
            await send({"type": "http.response.body", "body": b"data: tick\n\n", "more_body": True})
            await asyncio.sleep(0.05)
    await tiny_app(scope, receive, send)


class FakeGradioServer:
    """A stand-in for gradio.http_server / gradio.networking: records what it was asked."""

    def __init__(self, module_name, initial_port=7860, port_count=100):
        self.module = types.ModuleType(module_name)
        self.module.LOCALHOST_NAME = "127.0.0.1"
        self.module.INITIAL_PORT_VALUE = initial_port
        self.module.TRY_NUM_PORTS = port_count
        self.calls = []

        def start_server(app, server_name=None, server_port=None, ssl_keyfile=None, ssl_certfile=None, ssl_keyfile_password=None):
            self.calls.append((app, server_name, server_port, ssl_keyfile, ssl_certfile, ssl_keyfile_password))
            return "127.0.0.1", server_port or 7860, "http://127.0.0.1:7860/", "gradio's own server"

        self.original = start_server
        self.module.start_server = start_server


class AutoTLSHttp2TestCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="autotls-http2-test-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.previous_modules = {
            name: sys.modules.get(name)
            for name in ("modules", "modules.shared", "gradio", "gradio.http_server", "gradio.networking", "hypercorn")
        }
        self.addCleanup(self.restore_modules)
        self.servers = []
        self.addCleanup(self.close_servers)

    def restore_modules(self):
        for name, value in self.previous_modules.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value

    def close_servers(self):
        for server in self.servers:
            with contextlib.suppress(Exception):
                server.close()

    # helpers -----------------------------------------------------------------

    def fake_gradio(self, where="gradio.http_server", **keywords):
        """Install a fake Gradio whose start_server lives at ``where``."""
        gradio = types.ModuleType("gradio")
        gradio.__path__ = []
        sys.modules["gradio"] = gradio
        for name in ("gradio.http_server", "gradio.networking"):
            sys.modules.pop(name, None)
        fake = FakeGradioServer(where, **keywords)
        sys.modules[where] = fake.module
        setattr(gradio, where.split(".")[1], fake.module)
        return fake

    def run_script(self, cmd_opts=None):
        """Execute scripts/auto_tls_http2.py the way the host does and return the module."""
        modules = types.ModuleType("modules")
        modules.__path__ = []
        shared = types.ModuleType("modules.shared")
        shared.cmd_opts = cmd_opts if cmd_opts is not None else cmd_opts_for()
        sys.modules["modules"] = modules
        sys.modules["modules.shared"] = shared

        spec = importlib.util.spec_from_file_location("autotls_http2_under_test", HTTP2_SCRIPT)
        module = importlib.util.module_from_spec(spec)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            spec.loader.exec_module(module)
        self.stdout, self.stderr = out.getvalue(), err.getvalue()
        return module

    def pair(self):
        cert_path, key_path = os.path.join(self.root, "webui.cert"), os.path.join(self.root, "webui.key")
        write_pair(cert_path, key_path)
        return key_path, cert_path

    def alpn_answer(self, port, cert_path):
        context = ssl.create_default_context(cafile=cert_path)
        context.set_alpn_protocols(["h2", "http/1.1"])
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname="localhost") as tls:
                return tls.selected_alpn_protocol()

    def http1_get(self, port, cert_path):
        context = ssl.create_default_context(cafile=cert_path)
        connection = http.client.HTTPSConnection("localhost", port, context=context, timeout=5)
        try:
            connection.request("GET", "/")
            response = connection.getresponse()
            return response.status, response.getheader("x-http-version"), response.read()
        finally:
            connection.close()

    # the wrap ----------------------------------------------------------------

    @unittest.skipUnless(HAVE_HYPERCORN, "hypercorn is not installed")
    def test_gradio_4_start_server_is_wrapped(self):
        fake = self.fake_gradio("gradio.http_server")
        self.run_script()

        self.assertIsNot(fake.module.start_server, fake.original)
        self.assertIs(getattr(fake.module.start_server, "_autotls_http2_original"), fake.original)
        self.assertIn("HTTP/2 is ready", self.stdout)

    @unittest.skipUnless(HAVE_HYPERCORN, "hypercorn is not installed")
    def test_gradio_3_networking_is_wrapped_where_that_is_where_it_lives(self):
        fake = self.fake_gradio("gradio.networking")
        self.run_script()

        self.assertIsNot(fake.module.start_server, fake.original)
        self.assertIs(getattr(fake.module.start_server, "_autotls_http2_original"), fake.original)

    @unittest.skipUnless(HAVE_HYPERCORN, "hypercorn is not installed")
    def test_a_ui_reload_wraps_once(self):
        # Every script module runs again on a UI reload; the second pass must find
        # the wrap in place rather than wrap the wrapper.
        fake = self.fake_gradio()
        self.run_script()
        wrapped = fake.module.start_server
        self.run_script()

        self.assertIs(fake.module.start_server, wrapped)
        self.assertIs(getattr(wrapped, "_autotls_http2_original"), fake.original)

    def test_without_gradio_nothing_is_wrapped_and_nothing_breaks(self):
        sys.modules["gradio"] = None
        for name in ("gradio.http_server", "gradio.networking"):
            sys.modules[name] = None
        self.run_script()

        self.assertIn("HTTP/2 is off", self.stdout)
        self.assertEqual(self.stderr, "")

    def test_without_hypercorn_gradio_keeps_its_own_server(self):
        fake = self.fake_gradio()
        sys.modules["hypercorn"] = None
        self.run_script()

        self.assertIs(fake.module.start_server, fake.original)
        self.assertIn("Hypercorn", self.stderr)
        self.assertIn("not installed", self.stderr)
        self.assertIn("HTTP/1.1", self.stderr)
        self.assertIn("--skip-install", self.stderr)

    @unittest.skipUnless(HAVE_HYPERCORN, "hypercorn is not installed")
    def test_a_hypercorn_older_than_the_floor_is_named_and_leaves_gradio_alone(self):
        # The first host this ran on had the Hypercorn 0.13 that the old certipie
        # dependency pinned, and the message blamed a missing install.  The
        # version has to be named, and the way out has to be the right one.
        fake = self.fake_gradio()
        with unittest.mock.patch("importlib.metadata.version", return_value="0.13.2"):
            self.run_script()

        self.assertIs(fake.module.start_server, fake.original)
        self.assertIn("0.13.2", self.stderr)
        self.assertIn("0.14 or newer", self.stderr)
        self.assertIn("--skip-install", self.stderr)
        self.assertNotIn("not installed", self.stderr)

    @unittest.skipUnless(HAVE_HYPERCORN, "hypercorn is not installed")
    def test_only_hypercorns_public_entry_points_are_used(self):
        # Hypercorn's internals moved between releases (wrap_app, worker_serve's
        # sockets); the public serve() and Config have not.  Nothing else is
        # allowed in, so the next host with an unexpected release still serves.
        with open(HTTP2_SCRIPT, encoding="utf-8") as handle:
            source = handle.read()
        for internal in ("wrap_app", "worker_serve", "create_sockets", "hypercorn.utils", "app_wrappers"):
            self.assertNotIn(internal, source, internal)

    # what still goes to gradio's own server -----------------------------------

    @unittest.skipUnless(HAVE_HYPERCORN, "hypercorn is not installed")
    def test_without_tls_gradios_own_server_runs_with_the_same_arguments(self):
        fake = self.fake_gradio()
        self.run_script()

        answer = fake.module.start_server(tiny_app, "0.0.0.0", 7861)

        self.assertEqual(fake.calls, [(tiny_app, "0.0.0.0", 7861, None, None, None)])
        self.assertEqual(answer[3], "gradio's own server")

    @unittest.skipUnless(HAVE_HYPERCORN, "hypercorn is not installed")
    def test_http1_flag_keeps_gradios_own_server_even_with_tls(self):
        fake = self.fake_gradio()
        key_path, cert_path = self.pair()
        self.run_script(cmd_opts_for(autotls_http1=True))

        fake.module.start_server(tiny_app, None, None, key_path, cert_path)

        self.assertEqual(len(fake.calls), 1)
        self.assertEqual(fake.calls[0][3:5], (key_path, cert_path))

    @unittest.skipUnless(HAVE_HYPERCORN, "hypercorn is not installed")
    def test_a_hypercorn_that_cannot_start_falls_back_to_gradios_own_server(self):
        fake = self.fake_gradio()
        key_path, cert_path = self.pair()
        with open(cert_path, "wb") as handle:
            handle.write(b"this is not a certificate\n")
        self.run_script()

        answer = fake.module.start_server(tiny_app, None, free_port(), key_path, cert_path)

        self.assertEqual(answer[3], "gradio's own server")
        self.assertEqual(len(fake.calls), 1)

    # serving -------------------------------------------------------------------

    @unittest.skipUnless(HAVE_HYPERCORN, "hypercorn is not installed")
    def test_with_tls_the_app_is_served_over_http2(self):
        fake = self.fake_gradio()
        key_path, cert_path = self.pair()
        self.run_script()
        port = free_port()

        server_name, chosen, url, server = fake.module.start_server(tiny_app, None, port, key_path, cert_path)
        self.servers.append(server)

        self.assertEqual(fake.calls, [])
        self.assertEqual((server_name, chosen, url), ("127.0.0.1", port, f"https://127.0.0.1:{port}/"))
        self.assertTrue(server.started)
        self.assertEqual(self.alpn_answer(port, cert_path), "h2")
        # HTTP/1.1 clients - Gradio's own startup request among them - still work.
        self.assertEqual(self.http1_get(port, cert_path), (200, "1.1", b"ok"))

    @unittest.skipUnless(HAVE_HYPERCORN and HAVE_HTTPX_H2, "hypercorn or an HTTP/2 client is not installed")
    def test_an_http2_client_gets_an_http2_answer(self):
        import httpx

        fake = self.fake_gradio()
        key_path, cert_path = self.pair()
        self.run_script()
        port = free_port()
        server = fake.module.start_server(tiny_app, None, port, key_path, cert_path)[3]
        self.servers.append(server)

        with httpx.Client(http2=True, verify=cert_path) as client:
            response = client.get(f"https://localhost:{port}/")

        self.assertEqual((response.status_code, response.http_version, response.text), (200, "HTTP/2", "ok"))
        self.assertEqual(response.headers["x-http-version"], "2")

    @unittest.skipUnless(HAVE_HYPERCORN and HAVE_HTTPX_H2, "hypercorn or an HTTP/2 client is not installed")
    def test_a_stream_on_the_pages_connection_outlives_a_thousand_requests(self):
        # Hypercorn closes a connection after keep_alive_max_requests, a thousand
        # by default - sized for HTTP/1.1, where that is one request at a time.
        # Over HTTP/2 it is the page's only connection, so the thousandth
        # progress poll or thumbnail sent GOAWAY and took the queue stream down
        # with it: "Connection errored out." in the browser, with the image
        # already generated on the server.  The connection lives as long as the
        # page does, and a stream opened on it is still flowing well past that.
        import httpx

        fake = self.fake_gradio()
        key_path, cert_path = self.pair()
        self.run_script()
        port = free_port()
        server = fake.module.start_server(ticking_app, None, port, key_path, cert_path)[3]
        self.servers.append(server)

        context = ssl.create_default_context(cafile=cert_path)
        with httpx.Client(http2=True, verify=context, timeout=10) as client:
            with client.stream("GET", f"https://localhost:{port}/stream") as stream:
                self.assertEqual(stream.http_version, "HTTP/2")
                ticks = stream.iter_raw()
                self.assertTrue(next(ticks))
                for _ in range(1100):
                    response = client.get(f"https://localhost:{port}/")
                    self.assertEqual((response.status_code, response.http_version), (200, "HTTP/2"))
                # The same connection, and the stream on it is still alive.
                self.assertTrue(next(ticks))
                self.assertTrue(next(ticks))

    @unittest.skipUnless(HAVE_HYPERCORN, "hypercorn is not installed")
    def test_close_frees_the_port(self):
        fake = self.fake_gradio()
        key_path, cert_path = self.pair()
        self.run_script()
        port = free_port()
        server = fake.module.start_server(tiny_app, None, port, key_path, cert_path)[3]

        server.close()

        self.assertFalse(server.thread.is_alive())
        self.assertTrue(port_is_free(port))
        # and the same port can be taken again, which is what a UI reload does
        again = fake.module.start_server(tiny_app, None, port, key_path, cert_path)[3]
        self.servers.append(again)
        self.assertEqual(self.alpn_answer(port, cert_path), "h2")

    # the port rules are gradio's ------------------------------------------------

    @unittest.skipUnless(HAVE_HYPERCORN, "hypercorn is not installed")
    def test_a_taken_port_is_skipped_in_a_scan(self):
        first = free_port()
        holder = socket.socket()
        holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        holder.bind(("127.0.0.1", first))
        holder.listen(1)
        self.addCleanup(holder.close)

        fake = self.fake_gradio(initial_port=first, port_count=4)
        key_path, cert_path = self.pair()
        self.run_script()

        _, chosen, _, server = fake.module.start_server(tiny_app, None, None, key_path, cert_path)
        self.servers.append(server)

        self.assertNotEqual(chosen, first)
        self.assertIn(chosen, range(first + 1, first + 4))

    @unittest.skipUnless(HAVE_HYPERCORN, "hypercorn is not installed")
    def test_a_port_asked_for_by_number_is_refused_when_taken(self):
        taken = free_port()
        holder = socket.socket()
        holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        holder.bind(("127.0.0.1", taken))
        holder.listen(1)
        self.addCleanup(holder.close)

        fake = self.fake_gradio()
        key_path, cert_path = self.pair()
        self.run_script()

        with self.assertRaises(OSError) as raised:
            fake.module.start_server(tiny_app, None, taken, key_path, cert_path)

        self.assertIn("Cannot find empty port", str(raised.exception))
        self.assertEqual(fake.calls, [])

    # the real thing ----------------------------------------------------------------

    @unittest.skipUnless(HAVE_HYPERCORN and HAVE_GRADIO and HAVE_HTTPX_H2, "gradio, hypercorn or an HTTP/2 client is not installed")
    def test_a_real_gradio_blocks_launches_over_http2_and_again_after_close(self):
        import gradio as gr
        import httpx

        os.environ["GRADIO_ANALYTICS_ENABLED"] = "False"
        key_path, cert_path = self.pair()
        module = self.run_script()
        http_server = importlib.import_module("gradio.http_server")
        self.assertIs(getattr(http_server.start_server, "_autotls_http2_original", None), getattr(http_server.start_server, "__wrapped__", None))
        port = free_port()

        with gr.Blocks(analytics_enabled=False) as demo:
            gr.Markdown("http2")

        for attempt in ("first", "again after close"):
            demo.launch(server_name="127.0.0.1", server_port=port, ssl_keyfile=key_path, ssl_certfile=cert_path,
                        ssl_verify=False, prevent_thread_lock=True, quiet=True, show_api=False)
            try:
                self.assertIsInstance(demo.server, module.Http2Server, attempt)
                with httpx.Client(http2=True, verify=cert_path) as client:
                    response = client.get(f"https://localhost:{port}/")
                self.assertEqual((response.status_code, response.http_version), (200, "HTTP/2"), attempt)
                self.assertIn("gradio", response.text.lower(), attempt)
            finally:
                demo.close()
            self.assertTrue(port_is_free(port), attempt)


if __name__ == "__main__":
    unittest.main(verbosity=2)
