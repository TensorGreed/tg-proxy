"""gRPC server scaffolding that fronts a Python scanner or redactor as a
tg-proxy plugin.

The serve_* entry points handle every piece of plumbing:

  * verify the hashicorp/go-plugin magic cookie env var
  * pick a free localhost port
  * start a gRPC server on it
  * print the handshake line so tg-proxy can connect
  * block until the host closes our stdin or sends SIGTERM
"""
from __future__ import annotations

import os
import signal
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, List, Optional

import grpc

from ._proto import plugin_pb2 as pb
from ._proto import plugin_pb2_grpc as pb_grpc
from .types import Finding, Hints

MAGIC_COOKIE_KEY = "TG_PROXY_PLUGIN"
MAGIC_COOKIE_VALUE = "tg-proxy.plugin.v1"

# These have to match pkg/plugin.Handshake on the Go side.
CORE_PROTOCOL_VERSION = 1
APP_PROTOCOL_VERSION = 1

ScanFunc = Callable[[bytes, Hints], List[Finding]]
RedactFunc = Callable[[bytes, List[Finding]], bytes]


def serve_scanner(name: str, scan: ScanFunc, *, version: str = "dev") -> None:
    """Serve a scanner plugin until the host shuts us down."""
    _check_cookie()
    servicer = _ScannerServicer(scan, name, version)
    _serve(servicer.register)


def serve_redactor(name: str, redact: RedactFunc, *, version: str = "dev") -> None:
    """Serve a redactor plugin until the host shuts us down."""
    _check_cookie()
    servicer = _RedactorServicer(redact, name, version)
    _serve(servicer.register)


# --- internals -----------------------------------------------------------


def _serve(register: Callable[[grpc.Server], None]) -> None:
    port = _pick_port()
    server = grpc.server(ThreadPoolExecutor(max_workers=8))
    register(server)
    server.add_insecure_port(f"127.0.0.1:{port}")
    server.start()

    handshake = f"{CORE_PROTOCOL_VERSION}|{APP_PROTOCOL_VERSION}|tcp|127.0.0.1:{port}|grpc\n"
    sys.stdout.write(handshake)
    sys.stdout.flush()

    _wait_for_shutdown(server)


def _pick_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def _check_cookie() -> None:
    got = os.environ.get(MAGIC_COOKIE_KEY)
    if got != MAGIC_COOKIE_VALUE:
        sys.stderr.write(
            "This is a tg-proxy plugin and is meant to be launched by tg-proxy itself.\n"
            f"To run it manually, set {MAGIC_COOKIE_KEY}={MAGIC_COOKIE_VALUE}.\n",
        )
        sys.exit(1)


def _wait_for_shutdown(server: grpc.Server) -> None:
    # hashicorp/go-plugin doesn't pipe stdin into the plugin (nor signals
    # an orderly shutdown); it just kills the subprocess. So we block on
    # signals, knowing that on Windows the kill arrives as termination of
    # the process directly. server.wait_for_termination() handles that
    # cleanly: when the gRPC server is GC'd / process exits, it returns.
    stop = threading.Event()

    def _on_sig(*_):
        stop.set()

    for sig in (signal.SIGTERM,):
        try:
            signal.signal(sig, _on_sig)
        except (ValueError, OSError):
            # Not all signals are settable everywhere (e.g. inside threads
            # or on Windows for SIGINT). Ignore.
            pass

    # wait_for_termination blocks until server.stop() is called or the
    # process is killed; the SIGTERM handler nudges us via the Event so
    # we shut down the gRPC server gracefully before exiting.
    waiter = threading.Thread(target=server.wait_for_termination, daemon=True)
    waiter.start()

    stop.wait()
    server.stop(grace=2).wait()


class _ScannerServicer(pb_grpc.ScannerServicer):
    def __init__(self, scan: ScanFunc, name: str, version: str) -> None:
        self.scan = scan
        self.name = name
        self.version = version

    def register(self, server: grpc.Server) -> None:
        pb_grpc.add_ScannerServicer_to_server(self, server)

    def Info(self, _request, _context):
        return pb.PluginInfo(name=self.name, version=self.version)

    def Scan(self, request, _context):
        hints = Hints(
            content_type=request.hints.content_type,
            url=request.hints.url,
            method=request.hints.method,
            direction=int(request.hints.direction),
        )
        findings = self.scan(request.data, hints) or []
        return pb.ScanResponse(findings=[_finding_to_proto(f) for f in findings])


class _RedactorServicer(pb_grpc.RedactorServicer):
    def __init__(self, redact: RedactFunc, name: str, version: str) -> None:
        self.redact = redact
        self.name = name
        self.version = version

    def register(self, server: grpc.Server) -> None:
        pb_grpc.add_RedactorServicer_to_server(self, server)

    def Info(self, _request, _context):
        return pb.PluginInfo(name=self.name, version=self.version)

    def Redact(self, request, _context):
        findings = [_finding_from_proto(f) for f in request.findings]
        out = self.redact(request.data, findings) or b""
        return pb.RedactResponse(data=out)


def _finding_to_proto(f: Finding) -> pb.Finding:
    return pb.Finding(
        type=f.type,
        severity=int(f.severity),
        start=int(f.start),
        end=int(f.end),
        confidence=float(f.confidence),
        scanner=f.scanner or "",
        metadata=(f.metadata or {}),
    )


def _finding_from_proto(p: pb.Finding) -> Finding:
    return Finding(
        type=p.type,
        severity=int(p.severity),
        start=int(p.start),
        end=int(p.end),
        confidence=float(p.confidence),
        scanner=p.scanner,
        metadata=dict(p.metadata) if p.metadata else None,
    )


def _unused(_: Optional[int]) -> None:
    """Kept so static checkers see Optional as used; harmless."""
