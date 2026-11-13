"""Offline test doubles shared by the safereq test-suite.

Nothing in this module performs real DNS or real TLS; TCP loopback servers
are the only live sockets used by the suite and they never leave the host.
"""

from __future__ import annotations

import socket
import socketserver
import threading
from dataclasses import dataclass, field

from safereq.connection import SafeConnection
from safereq.resolver import ResolvedAddress


class FakeClock:
    def __init__(self, start: float = 1000.0) -> None:
        self.current = start

    def now(self) -> float:
        return self.current

    def advance(self, seconds: float) -> None:
        self.current += seconds


class FakeResolver:
    """Returns scripted addresses and records every query."""

    def __init__(self, mapping: dict[str, list[str]]) -> None:
        self.mapping = mapping
        self.calls: list[tuple[str, int]] = []
        self._flip = False

    def resolve(self, target):
        self.calls.append((target.host, target.port))
        if target.host not in self.mapping:
            from safereq.errors import DNSResolutionError

            raise DNSResolutionError(
                f"no records for {target.host}", host=target.host
            )
        records = list(self.mapping[target.host])
        if self._flip:
            records.reverse()
        results = []
        for raw in records:
            family = socket.AF_INET6 if ":" in raw else socket.AF_INET
            results.append(ResolvedAddress(family=family, address=raw))
        return results

    def flip_next_order(self) -> None:
        self._flip = True


@dataclass
class ConnectionRecord:
    target: object
    approved: list
    timeout: float
    hop: int
    server_hostname: str | None = None
    closed: bool = False


class FakeConnector:
    """Connector that returns sockets from a scripted response factory."""

    def __init__(self, scripted: dict[str, list[bytes]] | None = None) -> None:
        self.scripted = {
            host: list(payload) for host, payload in (scripted or {}).items()
        }
        self.records: list[ConnectionRecord] = []
        self.fail_addresses: set[str] = set()
        self.peer_override: str | None = None
        self.last_request_bytes: list[bytes] = []
        self.peer_mismatch: str | None = None

    def connect(self, target, approved, timeout, hop):
        record = ConnectionRecord(target=target, approved=list(approved),
                                  timeout=timeout, hop=hop)
        self.records.append(record)
        pair = socket.socketpair()
        client_sock, server_sock = pair
        chosen = approved[0].address
        if self.peer_mismatch is not None:
            from safereq.errors import PeerMismatchError

            client_sock.close()
            server_sock.close()
            raise PeerMismatchError(
                f"peer {self.peer_mismatch} not approved",
                host=target.host,
                address=self.peer_mismatch,
                hop=hop,
            )
        if self.peer_override is not None:
            chosen = self.peer_override
        if chosen in self.fail_addresses:
            client_sock.close()
            server_sock.close()
            raise OSError(f"simulated failure to {chosen}")
        payload = self.scripted.get(target.host, self.scripted.get("*", []))
        if not payload:
            raise AssertionError(f"no scripted response for host {target.host}")
        data = payload.pop(0)

        class _ScriptedPeer:
            def __init__(self, sock, blob, record):
                self._sock = sock
                self._blob = blob
                self._record = record
                self._sent = bytearray()

            def run(self):
                self._sock.sendall(self._blob)
                try:
                    self._sock.settimeout(0.2)
                    while True:
                        chunk = self._sock.recv(4096)
                        if not chunk:
                            break
                        self._sent.extend(chunk)
                except OSError:
                    pass
                finally:
                    self._sock.close()

        peer = _ScriptedPeer(server_sock, data, record)
        thread = threading.Thread(target=peer.run, daemon=True)
        thread.start()

        wrapper = _RecordingSocket(client_sock, record, self)
        return SafeConnection(
            sock=wrapper,
            target=target,
            peer=chosen,
            tls=target.scheme == "https",
        )


class _RecordingSocket:
    def __init__(self, sock, record, owner: FakeConnector):
        self._sock = sock
        self._record = record
        self._owner = owner

    def settimeout(self, value):
        self._sock.settimeout(value)

    def sendall(self, data):
        self._sock.sendall(data)
        self._owner.last_request_bytes.append(bytes(data))

    def recv(self, size):
        return self._sock.recv(size)

    def close(self):
        self._record.closed = True
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._sock.close()


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        request = b""
        self.request.settimeout(2)
        try:
            while b"\r\n\r\n" not in request:
                chunk = self.request.recv(4096)
                if not chunk:
                    break
                request += chunk
            if b"Content-Length:" in request:
                header_part, _, body_part = request.partition(b"\r\n\r\n")
                length = 0
                for line in header_part.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        length = int(line.split(b":", 1)[1].strip())
                while len(body_part) < length:
                    chunk = self.request.recv(4096)
                    if not chunk:
                        break
                    body_part += chunk
                request = header_part + b"\r\n\r\n" + body_part
        except OSError:
            return
        self.server.requests.append(request)
        response = self.server.script.pop(0)
        if isinstance(response, list):
            for piece in response:
                self.request.sendall(piece)
        else:
            self.request.sendall(response)


class ThreadingLocalServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, script):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.script = list(script)
        self.requests: list[bytes] = []
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.shutdown()
        self.server_close()


class MappedConnector:
    """Connector that dials a local loopback server while pretending the
    approved peer is a scripted public IP, enabling full real-socket tests
    without touching the network."""

    def __init__(self, local_port: int, fake_peer: str = "8.8.8.7"):
        self.local_port = local_port
        self.fake_peer = fake_peer
        self.records: list[ConnectionRecord] = []

    def connect(self, target, approved, timeout, hop):
        self.records.append(
            ConnectionRecord(target=target, approved=list(approved),
                             timeout=timeout, hop=hop)
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(("127.0.0.1", self.local_port))
        return SafeConnection(
            sock=sock, target=target, peer=self.fake_peer,
            tls=target.scheme == "https",
        )


class PublicResolver:
    """Resolver for real-socket tests: every domain maps to scripted public IPs."""

    def __init__(self, mapping: dict[str, list[str]] | None = None,
                 default: str = "8.8.8.8") -> None:
        self.mapping = mapping or {}
        self.default = default
        self.calls: list[str] = []

    def resolve(self, target):
        self.calls.append(target.host)
        addresses = self.mapping.get(target.host, [self.default])
        return [
            ResolvedAddress(
                family=socket.AF_INET6 if ":" in raw else socket.AF_INET,
                address=raw,
            )
            for raw in addresses
        ]


def http_response(
    status: str = "HTTP/1.1 200 OK",
    headers: tuple[tuple[str, str], ...] = (),
    body: bytes = b"",
) -> bytes:
    lines = [status.encode("ascii")]
    has_length = any(name.lower() == "content-length" for name, _ in headers)
    for name, value in headers:
        lines.append(f"{name}: {value}".encode("ascii"))
    if not has_length and body:
        lines.append(f"Content-Length: {len(body)}".encode("ascii"))
    lines.append(b"")
    lines.append(b"")
    return b"\r\n".join(lines) + body
