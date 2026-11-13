import socket
import ssl
import unittest

from safereq.connection import DefaultConnector
from safereq.errors import TLSError
from safereq.resolver import ResolvedAddress
from safereq.urlmodel import parse_url


class TlsBindingTest(unittest.TestCase):
    def test_sni_and_hostname_verification_use_original_domain(self):
        captured = {}

        class RecordingContext:
            check_hostname = True
            verify_mode = ssl.CERT_REQUIRED
            minimum_version = ssl.TLSVersion.TLSv1_2

            def wrap_socket(self, sock, *, server_hostname,
                            do_handshake_on_connect):
                captured["server_hostname"] = server_hostname
                captured["do_handshake_on_connect"] = do_handshake_on_connect
                return sock

        class RecordingSocket(socket.socket):
            def connect(self, address):
                self._peer_address = address

            def getpeername(self):
                return self._peer_address

        target = parse_url("https://service.example/")
        approved = [ResolvedAddress(socket.AF_INET, "8.8.8.5")]

        with _BoundListener() as listener:
            port = listener.port

            class BoundSocket(RecordingSocket):
                def connect(self, address):
                    self._peer_address = ("8.8.8.5", address[1])
                    socket.socket.connect(self, ("127.0.0.1", port))

            def socket_factory(family, socket_type):
                return BoundSocket(family, socket_type)

            connector = DefaultConnector(
                socket_factory=socket_factory,
                ssl_context_factory=RecordingContext,
            )
            conn = connector.connect(target, approved, 1.0, 0)
            try:
                self.assertEqual(captured["server_hostname"],
                                 "service.example")
                self.assertTrue(captured["do_handshake_on_connect"])
                self.assertEqual(conn.peer, "8.8.8.5")
                self.assertTrue(conn.tls)
            finally:
                conn.close()

    def test_context_without_hostname_check_is_refused(self):
        class InsecureContext:
            check_hostname = False
            verify_mode = ssl.CERT_REQUIRED

        connector = DefaultConnector(
            ssl_context_factory=InsecureContext)
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with self.assertRaises(TLSError) as ctx:
            connector._wrap_tls(raw, parse_url("https://a.example/"), 3)
        raw.close()
        self.assertIn("hostname checking disabled", ctx.exception.args[0])
        self.assertEqual(ctx.exception.host, "a.example")
        self.assertEqual(ctx.exception.hop, 3)

    def test_context_without_cert_required_is_refused(self):
        class InsecureContext:
            check_hostname = True
            verify_mode = ssl.CERT_NONE

        connector = DefaultConnector(
            ssl_context_factory=InsecureContext)
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with self.assertRaises(TLSError) as ctx:
            connector._wrap_tls(raw, parse_url("https://a.example/"), 0)
        raw.close()
        self.assertIn("does not require certificates", ctx.exception.args[0])


class _BoundListener(socket.socket):
    def __init__(self):
        super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.bind(("127.0.0.1", 0))
        self.listen(1)
        self.port = self.getsockname()[1]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


if __name__ == "__main__":
    unittest.main()
