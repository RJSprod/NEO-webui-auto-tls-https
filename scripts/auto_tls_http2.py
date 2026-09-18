"""AutoTLS HTTP/2 - one connection for the whole WebUI, once TLS is on.

WHY.  A browser allows six persistent HTTP/1.1 connections to one origin, and a
WebUI page spends most of them on streams that never close: the page's own
heartbeat and queue, and anything an extension keeps open on the same origin -
an event stream, an iframe with a heartbeat and a queue of its own.  On the day
this was written five of the six were such streams; when the process behind two
of them stopped answering they were held open for good, and every later request
from the page - a generation, a button, a poll - queued in the browser behind
them until the browser itself was restarted.  The server was fine throughout.

HTTP/2 multiplexes every request and stream of a page over ONE connection, with
no six-connection rule, and browsers speak it only over TLS - which is what this
extension already provides.  uvicorn, the server Gradio starts, does not speak
HTTP/2.  Hypercorn does.

WHAT.  This script module wraps Gradio's own ``start_server`` - the function
``Blocks.launch()`` calls to bring the HTTP server up.  When Gradio asks for TLS
(the pair this extension generated, or the user's own) the wrapper serves the
very same ASGI app through Hypercorn with ALPN ``h2`` and ``http/1.1``.  Without
TLS, with ``--autotls-http1``, or if Hypercorn cannot start, Gradio's own
``start_server`` runs exactly as before.  Nothing else changes: the same app
object (so everything Forge mounts on it afterwards is served), the same port
choice, the same URL, the same ``close()`` a UI reload relies on.

Gradio 4 (Forge Neo) keeps ``start_server`` in ``gradio.http_server``; Gradio 3
(AUTOMATIC1111) in ``gradio.networking``.  Both return ``(server_name, port,
url, server)`` and both use ``server`` only to close it, which is the whole of
the contract kept here.

Only Hypercorn's public entry point is used - ``hypercorn.asyncio.serve`` and
``Config`` - because the first host this ran on had a Hypercorn 0.13 left
behind by an older dependency, and the internals differ from one release to
the next.  Any release from 0.14 on serves; the installer brings a current one
when what is installed is older than that.
"""

import asyncio
import importlib
import socket
import sys
import threading
import time
import traceback

from modules.shared import cmd_opts

PREFIX = "[AutoTLS]"

#: Set on the wrapper, holding the function it wraps.  A UI reload re-runs every
#: script module; this is how the second pass sees that the wrap is already in
#: place rather than wrapping the wrapper.
MARKER = "_autotls_http2_original"

#: Where Gradio keeps start_server, newest first.
SERVER_MODULES = ("gradio.http_server", "gradio.networking")

#: How long run_in_thread waits for Hypercorn to say it is accepting.  Gradio's
#: own server is given the same five seconds.
START_TIMEOUT = 5.0

#: How long close() waits for the serving thread.  Gradio joins its own for five
#: seconds; Hypercorn's graceful shutdown is three.
CLOSE_TIMEOUT = 5.0

#: Hypercorn announces each listening socket with this line.  It is hooked on the
#: logger rather than parsed from a stream, and it is the readiness signal.
READY_TEXT = "Running on"

#: An idle connection is kept this long.  uvicorn keeps one for five seconds;
#: with HTTP/2 the page's one connection is rarely idle, and a kept one spares a
#: TLS handshake for the next click.
KEEP_ALIVE_SECONDS = 30.0

#: How many requests one connection may carry before Hypercorn closes it.
#: Hypercorn's own figure is a thousand, sized for HTTP/1.1, where a connection
#: carries one request at a time and a thousand is a long life.  Over HTTP/2
#: the page's ONE connection carries every request the page ever makes - each
#: progress poll, each thumbnail, each click - and the thousandth arrives within
#: minutes of a Generate.  On it Hypercorn sends GOAWAY, then reads the browser's
#: next frame as a protocol error and closes the connection under the streams
#: still open on it: the page's heartbeat, and the queue stream a generation's
#: result travels on.  Gradio's client answers a broken queue stream with
#: "Connection errored out." and drops the finished image.  The connection is
#: meant to live as long as the page, so the figure is effectively no limit.
KEEP_ALIVE_MAX_REQUESTS = 2**31 - 1

#: The oldest Hypercorn this will serve through.  Everything below is asked of
#: its public API only, and 0.14 is the oldest release that API was tested on.
#: install.py brings a newer one than this; the floor is what to accept when
#: the installer could not run.
MINIMUM_HYPERCORN = (0, 14)

#: How often, and for how long in total, run_in_thread asks the port whether
#: anything is listening yet.  A connection that is accepted is the proof.
PROBE_INTERVAL = 0.02


def log(message):
    print(f"{PREFIX} {message}")


def error(message):
    print(f"{PREFIX} ERROR: {message}", file=sys.stderr)


def opt(name, default=None):
    value = getattr(cmd_opts, name, default)
    return default if value is None else value


def server_module():
    """The Gradio module that owns start_server, or None when there is none."""
    for name in SERVER_MODULES:
        try:
            module = importlib.import_module(name)
        except Exception:
            continue
        if callable(getattr(module, "start_server", None)):
            return module
    return None


def hypercorn_version():
    """The installed Hypercorn's version as a tuple of ints, or None when unknown."""
    try:
        import importlib.metadata

        text = importlib.metadata.version("hypercorn")
    except Exception:
        return None
    parts = []
    for piece in str(text).split("."):
        digits = ""
        for character in piece:
            if not character.isdigit():
                break
            digits += character
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts) or None


def hypercorn_problem():
    """Why Hypercorn cannot serve here, or None when it can.

    The two answers a person can act on are told apart: one that is not there
    at all, and one that is there but older than this file was written against.
    Both are what the installer fixes on a start without --skip-install.
    """
    try:
        import hypercorn  # noqa: F401
    except Exception as exception:
        return f"it is not installed ({type(exception).__name__}: {exception})"

    version = hypercorn_version()
    if version is not None and version < MINIMUM_HYPERCORN:
        wanted = ".".join(str(part) for part in MINIMUM_HYPERCORN)
        return f"version {'.'.join(str(part) for part in version)} is installed and {wanted} or newer is needed"

    try:
        import h2  # noqa: F401  - HTTP/2 itself; Hypercorn declares it, this checks it
        from hypercorn.asyncio import serve  # noqa: F401
        from hypercorn.config import Config  # noqa: F401
        from hypercorn.logging import Logger  # noqa: F401
    except Exception as exception:
        return f"it is installed but incomplete ({type(exception).__name__}: {exception})"

    return None


def http2_declined(ssl_keyfile, ssl_certfile):
    """Why this launch stays on Gradio's own server, or None to go HTTP/2."""
    if not ssl_keyfile or not ssl_certfile:
        return "no TLS pair for this launch; browsers speak HTTP/2 only over TLS"
    if opt("autotls_http1", False):
        return "--autotls-http1 was given"
    return None


def check_certificate(ssl_keyfile, ssl_certfile, ssl_keyfile_password=None):
    """Load the pair the way Hypercorn will, before anything is bound.

    A pair Hypercorn cannot load would otherwise fail inside the serving thread,
    after its listening socket was bound and with nothing left to close it; and
    ssl.SSLError is an OSError, which the port scan would read as "taken" and
    try again on the next ninety-nine ports.  Raises RuntimeError, which the
    wrapper answers with Gradio's own server - and Gradio's own words for the
    same broken pair.
    """
    from hypercorn.config import Config

    config = Config()
    config.certfile = ssl_certfile
    config.keyfile = ssl_keyfile
    config.keyfile_password = ssl_keyfile_password
    try:
        config.create_ssl_context()
    except Exception as exception:
        raise RuntimeError(f"the certificate pair could not be loaded ({type(exception).__name__}: {exception})") from None


def probe_port(host, port):
    """Bind and release, the way Gradio checks a port.  Raises OSError when it is taken."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))


class Http2Server:
    """Hypercorn in a thread, with the surface Gradio uses: run_in_thread(), close().

    The listening socket is bound on the caller's thread, in the constructor, so
    a port that is taken raises OSError right there - the answer Gradio's own port
    scan is written around - and never as a failure inside the serving thread.
    """

    def __init__(self, app, host, port, ssl_keyfile, ssl_certfile, ssl_keyfile_password=None):
        from hypercorn.config import Config
        from hypercorn.logging import Logger

        ready = threading.Event()

        # Hypercorn announces each listening socket through its logger.  Hooked
        # here as one of two readiness signals; the other is the port itself.
        class ReadyLogger(Logger):
            async def info(self, message, *args, **kwargs):
                if READY_TEXT in str(message):
                    ready.set()
                await super().info(message, *args, **kwargs)

        config = Config()
        config.bind = [f"[{host}]:{port}" if ":" in host else f"{host}:{port}"]
        config.certfile = ssl_certfile
        config.keyfile = ssl_keyfile
        config.keyfile_password = ssl_keyfile_password
        config.alpn_protocols = ["h2", "http/1.1"]
        config.keep_alive_timeout = KEEP_ALIVE_SECONDS
        config.keep_alive_max_requests = KEEP_ALIVE_MAX_REQUESTS
        # Hypercorn's own announcements are replaced by the one line below; its
        # warnings and errors still reach the console.
        config.loglevel = "WARNING"
        config.accesslog = None
        config.logger_class = ReadyLogger

        self.app = app
        self.config = config
        self.host = host
        self.port = port
        self.ready = ready
        # Asked here, on the caller's thread, so that a taken port is an OSError
        # right now - the answer Gradio's own port scan is written around - and
        # never a failure inside the serving thread.  Hypercorn binds for itself
        # a moment later.
        probe_port(host, port)
        self.thread = None
        self.loop = None
        self.stop = None
        self.error = None
        self.started = False

    def listening(self):
        """Whether something accepts on the port yet.  A refused connection is
        the answer while Hypercorn is still starting; an accepted one, closed
        again before any handshake, is the proof it is up."""
        family = socket.AF_INET6 if ":" in self.host else socket.AF_INET
        target = "127.0.0.1" if self.host in ("0.0.0.0", "") else ("::1" if self.host == "::" else self.host)
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.2)
                sock.connect((target, self.port))
            return True
        except OSError:
            return False

    def run_in_thread(self):
        self.thread = threading.Thread(target=self._run, name="autotls-http2", daemon=True)
        self.thread.start()

        deadline = time.time() + START_TIMEOUT
        while self.thread.is_alive() and time.time() < deadline:
            if self.ready.is_set() or self.listening():
                self.started = True
                return
            time.sleep(PROBE_INTERVAL)

        self.close()
        why = self.error if self.error is not None else "nothing was listening within %.0fs" % START_TIMEOUT
        raise RuntimeError(f"Hypercorn did not start: {why}")

    def _run(self):
        try:
            asyncio.run(self._serve())
        except BaseException as exception:  # reported to the thread that asked, never raised into nothing
            # The words, not the exception: an exception keeps its traceback,
            # and the traceback keeps every frame - and every socket - alive.
            self.error = f"{type(exception).__name__}: {exception}"

    async def _serve(self):
        from hypercorn.asyncio import serve

        self.loop = asyncio.get_running_loop()
        self.stop = asyncio.Event()
        await serve(self.app, self.config, shutdown_trigger=self.stop.wait)

    def close(self):
        loop, stop = self.loop, self.stop
        if loop is not None and stop is not None:
            try:
                loop.call_soon_threadsafe(stop.set)
            except RuntimeError:
                pass  # the loop has already gone
        if self.thread is not None and self.thread.is_alive():
            self.thread.join(timeout=CLOSE_TIMEOUT)


def start_http2(module, app, server_name, server_port, ssl_keyfile, ssl_certfile, ssl_keyfile_password):
    """Gradio's start_server, served by Hypercorn.  Same inputs, same outputs, same port rules."""
    localhost = getattr(module, "LOCALHOST_NAME", "127.0.0.1")
    first_port = int(getattr(module, "INITIAL_PORT_VALUE", 7860))
    port_count = int(getattr(module, "TRY_NUM_PORTS", 100))

    server_name = server_name or localhost
    url_host_name = "localhost" if server_name == "0.0.0.0" else server_name
    # http://[::1]:port/ is a valid browser address and not a valid bind address.
    host = server_name[1:-1] if server_name.startswith("[") and server_name.endswith("]") else server_name

    check_certificate(ssl_keyfile, ssl_certfile, ssl_keyfile_password)

    ports = [server_port] if server_port is not None else range(first_port, first_port + port_count)
    for port in ports:
        try:
            server = Http2Server(app, host, port, ssl_keyfile, ssl_certfile, ssl_keyfile_password)
        except OSError:
            continue  # taken; the next one, exactly as Gradio does
        server.run_in_thread()
        break
    else:
        raise OSError(
            f"Cannot find empty port in range: {min(ports)}-{max(ports)}. You can specify a different port "
            "by setting the GRADIO_SERVER_PORT environment variable or passing the `server_port` parameter to `launch()`."
        )

    url = f"https://{url_host_name}:{port}/"
    log(f"HTTPS is HTTP/2 through Hypercorn on {url} - one connection per page, no six-connection limit")
    return server_name, port, url, server


def install(module=None):
    """Wrap start_server on the Gradio module that owns it.  Returns whether it is wrapped.

    Safe to call again: a wrap already in place is left as it is.
    """
    module = module if module is not None else server_module()
    if module is None:
        log("HTTP/2 is off: Gradio's server module was not found; the WebUI keeps HTTP/1.1")
        return False

    current = module.start_server
    if getattr(current, MARKER, None) is not None:
        return True

    problem = hypercorn_problem()
    if problem is not None:
        error(
            f"HTTP/2 is off: Hypercorn {problem}; the WebUI keeps HTTP/1.1"
            " - a start without --skip-install lets the extension installer put a current Hypercorn in place"
        )
        return False

    original = current

    def start_server(app, server_name=None, server_port=None, ssl_keyfile=None, ssl_certfile=None, ssl_keyfile_password=None):
        declined = http2_declined(ssl_keyfile, ssl_certfile)
        if declined is not None:
            log(f"HTTP/1.1 through Gradio's own server: {declined}")
            return original(app, server_name, server_port, ssl_keyfile, ssl_certfile, ssl_keyfile_password)
        try:
            return start_http2(module, app, server_name, server_port, ssl_keyfile, ssl_certfile, ssl_keyfile_password)
        except OSError:
            # No free port.  The same failure, with the same words, that Gradio
            # raises; its own server would find no port either.
            raise
        except Exception:
            error("the HTTP/2 server could not be started; falling back to Gradio's own HTTP/1.1 server")
            traceback.print_exc()
            return original(app, server_name, server_port, ssl_keyfile, ssl_certfile, ssl_keyfile_password)

    setattr(start_server, MARKER, original)
    start_server.__wrapped__ = original
    module.start_server = start_server
    log("HTTP/2 is ready: the WebUI is served through Hypercorn whenever it starts with TLS")
    return True


try:
    install()
except Exception:
    # Never take the WebUI down over this; say what happened and leave Gradio's server alone.
    error("unexpected failure while preparing HTTP/2; the WebUI keeps HTTP/1.1")
    traceback.print_exc()
