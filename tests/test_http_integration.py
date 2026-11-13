import socket
import ssl
import unittest

from safereq import (
    LimitExceeded,
    ReadError,
    ResponseError,
    SafeHttpClient,
    Limits,
)
from safereq.connection import DefaultConnector

from tests.helpers import (
    MappedConnector,
    PublicResolver,
    ThreadingLocalServer,
    http_response,
)


class RealSocketHttpTest(unittest.TestCase):
    def _client(self, server, fake_peer="8.8.8.7", limits=None):
        connector = MappedConnector(server.server_address[1], fake_peer)
        return SafeHttpClient(
            connector=connector,
            resolver=PublicResolver(default=fake_peer),
            clock=_RealClock(),
            limits=limits or Limits(connect_timeout=2, read_timeout=2,
                                    total_timeout=5),
        ), connector

    def test_full_request_response_with_real_loopback_socket(self):
        body = b"x" * 5000
        with ThreadingLocalServer([http_response(body=body)]) as server:
            client, connector = self._client(server)
            response = client.get("http://api.example/resource")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.body, body)
        self.assertEqual(response.peer, "8.8.8.7")
        request = server.requests[0]
        self.assertTrue(request.startswith(b"GET /resource HTTP/1.1\r\n"))
        self.assertIn(b"Host: api.example\r\n", request)
        self.assertIn(b"Accept-Encoding: identity\r\n", request)
        self.assertEqual(len(connector.records), 1)

    def test_fragmented_response_is_reassembled(self):
        full = http_response(body=b"fragmented-body")
        pieces = [full[:10], full[10:25], full[25:]]
        with ThreadingLocalServer([pieces]) as server:
            client, _ = self._client(server)
            response = client.get("http://api.example/")
        self.assertEqual(response.body, b"fragmented-body")

    def test_chunked_transfer_decoded_with_byte_limit(self):
        chunked = (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
        )
        with ThreadingLocalServer([chunked]) as server:
            client, _ = self._client(server)
            response = client.get("http://api.example/")
        self.assertEqual(response.body, b"Wikipedia")

    def test_chunked_body_limit_rejected_before_server_close(self):
        chunked = (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
        )
        with ThreadingLocalServer([chunked]) as server:
            client, _ = self._client(server, limits=Limits(max_body_bytes=5))
            with self.assertRaises(LimitExceeded) as ctx:
                client.get("http://api.example/")
        self.assertEqual(ctx.exception.reason, "body_size")

    def test_body_limit_applies_without_content_length(self):
        raw = b"HTTP/1.1 200 OK\r\n\r\n" + b"abcdefghij"
        with ThreadingLocalServer([raw]) as server:
            client, _ = self._client(server, limits=Limits(max_body_bytes=4))
            with self.assertRaises(LimitExceeded) as ctx:
                client.get("http://api.example/")
        self.assertEqual(ctx.exception.reason, "body_size")
        self.assertEqual(ctx.exception.limit, 4)

    def test_unsupported_content_encoding_rejected(self):
        raw = http_response(
            headers=(("Content-Encoding", "gzip"),), body=b"\x1f\x8bxx")
        with ThreadingLocalServer([raw]) as server:
            client, _ = self._client(server)
            with self.assertRaises(ResponseError) as ctx:
                client.get("http://api.example/")
        self.assertIn("Content-Encoding", ctx.exception.args[0])

    def test_inaccurate_content_length_short_read_is_error(self):
        raw = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nonly-twelve"
        )
        with ThreadingLocalServer([raw]) as server:
            client, _ = self._client(server)
            with self.assertRaises(ReadError):
                client.get("http://api.example/")

    def test_header_size_limit(self):
        raw = b"HTTP/1.1 200 OK\r\nX-Big: " + b"a" * 2000 + b"\r\n\r\n"
        with ThreadingLocalServer([raw]) as server:
            client, _ = self._client(
                server, limits=Limits(max_header_bytes=256))
            with self.assertRaises(LimitExceeded) as ctx:
                client.get("http://api.example/")
        self.assertEqual(ctx.exception.reason, "header_size")

    def test_read_timeout_on_stalled_server(self):
        def stall_handler(request, client_sock):
            client_sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
            client_sock.recv(1)

        with _StallServer() as server:
            connector = MappedConnector(server.server_address[1])
            client = SafeHttpClient(
                connector=connector,
                resolver=PublicResolver(default="8.8.8.7"),
                clock=_RealClock(),
                limits=Limits(connect_timeout=2, read_timeout=0.3,
                              total_timeout=2),
            )
            with self.assertRaises(LimitExceeded) as ctx:
                client.get("http://api.example/")
        self.assertEqual(ctx.exception.reason, "read_timeout")


class _RealClock:
    def now(self):
        import time

        return time.monotonic()


class _StallServer(ThreadingLocalServer):
    def __init__(self):
        import socketserver

        class StallHandler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.recv(4096)
                self.request.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"
                )
                import time

                time.sleep(1.0)

        socketserver.TCPServer.__init__(
            self, ("127.0.0.1", 0), StallHandler
        )
        self.script = []
        self.requests = []
        import threading

        self.thread = threading.Thread(target=self.serve_forever, daemon=True)


class DefaultConnectorTest(unittest.TestCase):
    def test_default_ssl_context_verifies_hostname_and_cert(self):
        connector = DefaultConnector()
        context = connector._default_ssl_context()
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertGreaterEqual(
            context.minimum_version, ssl.TLSVersion.TLSv1_2
        )

    def test_connector_refuses_insecure_ssl_context(self):
        import ssl as ssl_module

        insecure = ssl_module.SSLContext(ssl_module.PROTOCOL_TLS_CLIENT)
        insecure.check_hostname = False
        insecure.verify_mode = ssl_module.CERT_NONE
        connector = DefaultConnector(ssl_context_factory=lambda: insecure)
        from safereq.errors import TLSError
        from safereq.resolver import ResolvedAddress
        from safereq.urlmodel import parse_url

        target = parse_url("https://api.example/")
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with self.assertRaises(TLSError):
            connector._wrap_tls(raw, target, 0)
        raw.close()

    def test_peer_mismatch_closes_socket_and_reports_address(self):
        from safereq.errors import PeerMismatchError
        from safereq.resolver import ResolvedAddress
        from safereq.urlmodel import parse_url

        target = parse_url("http://api.example/")

        class LyingSocket(socket.socket):
            def connect(self, address):
                self._real = socket.create_connection(
                    ("127.0.0.1", listener.getsockname()[1]))

            def getpeername(self):
                return ("127.0.0.1", 34567)

            def close(self):
                try:
                    self._real.close()
                except OSError:
                    pass
                super().close()

        with _NullTcpListener() as listener:
            connector = DefaultConnector(
                socket_factory=lambda family, type: LyingSocket(family, type))
            approved = [ResolvedAddress(socket.AF_INET, "8.8.8.55")]
            with self.assertRaises(PeerMismatchError) as ctx:
                connector.connect(target, approved, 1.0, 0)
        self.assertEqual(ctx.exception.address, "127.0.0.1")


class _NullTcpListener(socket.socket):
    def __init__(self):
        super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.bind(("127.0.0.1", 0))
        self.listen(1)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class SystemResolverTest(unittest.TestCase):
    def test_default_connector_falls_back_across_approved_addresses(self):
        from safereq.resolver import ResolvedAddress
        from safereq.urlmodel import parse_url

        with ThreadingLocalServer([http_response(body=b"ok")]) as server:
            live_port = server.server_address[1]
            dead = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            dead.bind(("127.0.0.1", 0))
            dead_port = dead.getsockname()[1]
            dead.close()

            attempts = {"n": 0}

            class SwitchSocket(socket.socket):
                def connect(self, address):
                    attempts["n"] += 1
                    port = dead_port if attempts["n"] == 1 else live_port
                    socket.socket.connect(self, ("127.0.0.1", port))

            target = parse_url("http://api.example/")
            approved = [
                ResolvedAddress(socket.AF_INET, "127.0.0.1"),
                ResolvedAddress(socket.AF_INET, "127.0.0.1"),
            ]
            connector = DefaultConnector(
                socket_factory=lambda family, kind: SwitchSocket(family, kind)
            )
            connection = connector.connect(target, approved, 2.0, 0)
            try:
                self.assertEqual(connection.peer, "127.0.0.1")
                self.assertEqual(attempts["n"], 2)
            finally:
                connection.close()

    def test_resolver_uses_getaddrinfo_results_and_dedupes(self):
        from safereq.resolver import SystemResolver
        from safereq.urlmodel import parse_url

        fake_infos = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
             ("8.8.8.5", 80)),
            (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
             ("2001:db8::5", 80, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
             ("8.8.8.5", 80)),
        ]
        resolver = SystemResolver(
            getaddrinfo=lambda *a, **k: fake_infos)
        results = resolver.resolve(parse_url("http://api.example/"))
        self.assertEqual(
            [entry.address for entry in results],
            ["8.8.8.5", "2001:db8::5"],
        )
        self.assertEqual(results[1].family, socket.AF_INET6)

    def test_resolver_maps_gaierror_to_dns_exception(self):
        from safereq.errors import DNSResolutionError
        from safereq.resolver import SystemResolver
        from safereq.urlmodel import parse_url

        def fail(*a, **k):
            raise socket.gaierror(-2, "Name or service not known")

        resolver = SystemResolver(getaddrinfo=fail)
        with self.assertRaises(DNSResolutionError) as ctx:
            resolver.resolve(parse_url("http://missing.example/"))
        self.assertEqual(ctx.exception.host, "missing.example")


if __name__ == "__main__":
    unittest.main()
