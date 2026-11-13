import unittest

from safereq import Limits, SafeHttpClient

from tests.helpers import (
    MappedConnector,
    PublicResolver,
    ThreadingLocalServer,
    http_response,
)


class RedirectIntegrationTest(unittest.TestCase):
    def test_relative_redirect_over_real_loopback_sockets(self):
        redirect = http_response(
            status="HTTP/1.1 302 Found",
            headers=(("Location", "/final"),),
        )
        final = http_response(body=b"done")
        with ThreadingLocalServer([redirect, final]) as server:
            connector = MappedConnector(server.server_address[1], "8.8.8.7")
            client = SafeHttpClient(
                resolver=PublicResolver(default="8.8.8.7"),
                connector=connector,
                clock=_Clock(),
                limits=Limits(connect_timeout=2, read_timeout=2,
                              total_timeout=5, max_redirects=3),
            )
            response = client.get("http://api.example/start")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.body, b"done")
        self.assertEqual(len(connector.records), 2)
        self.assertEqual(
            connector.records[0].target.path_query, "/start")
        self.assertEqual(
            connector.records[1].target.path_query, "/final")
        self.assertEqual(
            server.requests[1].split(b"\r\n", 1)[0],
            b"GET /final HTTP/1.1",
        )
        self.assertTrue(all(record.target.host == "api.example"
                            for record in connector.records))


class _Clock:
    def now(self):
        import time

        return time.monotonic()


if __name__ == "__main__":
    unittest.main()
