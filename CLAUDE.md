# Working on AutoTLS

Two script modules, run by the WebUI in the order it finds them:
`scripts/auto_tls.py` makes or reuses a certificate and points the WebUI's TLS
options at it, and `scripts/auto_tls_http2.py` serves the result over HTTP/2.
`install.py` provides `cryptography`, `certifi` and `hypercorn`. The README is
the user-facing account; this file is what a session has to know that is
written nowhere else.

```
python tests/test_auto_tls.py        # 37 checks: certificates, trust, the modes
python tests/test_auto_tls_http2.py  # 17 checks: the wrap, the fallbacks, real HTTP/2
python tests/test_install.py         #  5 checks: what the installer asks pip for
```

## Why HTTP/2 is here at all

A browser allows six persistent HTTP/1.1 connections to one origin, and a
Stable Diffusion WebUI page spends most of them on streams that never close.
On 2026-09-17 a wedged child process behind an extension's proxy held two of
them for ever and the entire WebUI froze in the browser while the server was
perfectly healthy; only restarting the browser freed it. HTTP/2 multiplexes a
page over one connection with no such rule, and browsers speak it only over
TLS - which this extension already provides, which is why it lives here rather
than in the extension that suffered. The full account is in
`RJSprod/a1111-mini-paint-NEO`, `docs/wangp/BROWSER_CONNECTION_STARVATION_2026-09-17.txt`.

## The traps

**Use only Hypercorn's public API.** `serve()` and `Config`, nothing else. The
first host to run this had **Hypercorn 0.13.2** - the version the old
`certipie` dependency pinned (`>=0.13.2,<0.14.0`) and that nothing ever
removed - which has no `wrap_app` and whose `worker_serve` takes no `sockets`.
Internals move between releases; the entry point does not. The suite runs
against 0.14 through 0.18 for that reason.

**Check the version, not the presence.** `install.py` upgrades anything below
0.17. Asking `is_installed("hypercorn")` is exactly the question that left
that 0.13 in place and HTTP/2 off on a start with no `--skip-install`.

**Load the certificate before binding anything.** `ssl.SSLError` is an
`OSError`, and the port scan reads an `OSError` as "this port is taken" - so a
pair the server cannot read would be blamed on a hundred ports in turn, and a
failure raised inside the serving thread leaves a bound socket with nothing
left to close it. `check_certificate()` runs first, on the caller's thread.

**Keep Gradio's contract exactly.** Both Gradio generations return
`(server_name, port, url, server)` from `start_server` and use `server` only to
`close()` it; a UI reload depends on that close freeing the port. Gradio 4
keeps the function in `gradio.http_server`, Gradio 3 in `gradio.networking`.
Every script module runs again on a UI reload, so the wrap checks for itself
before wrapping.

**The page's connection must outlive a thousand requests.** Hypercorn closes a
connection after `keep_alive_max_requests` (1000 by default) - on HTTP/2 that is
the page's only connection, reached within minutes of a Generate, and Hypercorn
does not honour its own GOAWAY gracefully: the browser's next frame is read as a
protocol error and the connection is closed under the heartbeat and queue
streams still open on it. Gradio's client answers a broken queue stream with
*Connection errored out.* and drops the finished image. `KEEP_ALIVE_MAX_REQUESTS`
lifts the cap; the regression test opens a stream and makes 1,100 requests past
it. Anything that closes the connection on a schedule is this bug again.

**Never let this take the WebUI down.** Every failure path falls back to
Gradio's own server and says which; `--autotls-http1` is the user's one-flag
way back. TLS without HTTP/2 is a working WebUI, and that is always the
acceptable outcome here.
