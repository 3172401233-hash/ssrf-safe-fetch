import os
import socket
import unittest

from safereq import SafeHttpClient, URLError
from safereq.resolver import ResolvedAddress

from tests.helpers import FakeClock, FakeConnector, http_response


class ProxyAndCredentialTest(unittest.TestCase):
    def test_system_proxy_environment_is_ignored(self):
        proxy_vars = {
            "HTTP_PROXY": "http://127.0.0.1:9999",
            "HTTPS_PROXY": "http://127.0.0.1:9999",
            "http_proxy": "http://127.0.0.1:9999",
            "ALL_PROXY": "socks://127.0.0.1:9999",
            "NO_PROXY": "",
        }
        old = {key: os.environ.get(key) for key in proxy_vars}
        os.environ.update(proxy_vars)
        try:
            class StaticResolver:
                def resolve(self, target):
                    return [ResolvedAddress(socket.AF_INET, "8.8.8.5")]

            connector = FakeConnector({"a.example": [http_response()]})
            client = SafeHttpClient(
                resolver=StaticResolver(), connector=connector,
                clock=FakeClock(),
            )
            response = client.get("http://a.example/")
        finally:
            for key, value in old.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        self.assertEqual(response.status_code, 200)
        self.assertEqual(connector.records[0].approved[0].address, "8.8.8.5")

    def test_credentials_never_appear_in_error_messages(self):
        for url in (
            "http://user:secret@example.com/",
            "http://token@example.com/",
        ):
            with self.subTest(url=url):
                try:
                    SafeHttpClient(clock=FakeClock()).get(url)
                except URLError as exc:
                    message = str(exc)
                    self.assertNotIn("secret", message)
                    self.assertNotIn(url, message)
                    self.assertNotIn("user:secret", message)
                else:
                    self.fail("URL with credentials must be rejected")

    def test_error_messages_identify_host_and_hop_without_url_creds(self):
        from safereq import PolicyError

        class PrivateResolver:
            def resolve(self, target):
                return [ResolvedAddress(socket.AF_INET, "10.1.2.3")]

        connector = FakeConnector({})
        client = SafeHttpClient(
            resolver=PrivateResolver(), connector=connector, clock=FakeClock()
        )
        with self.assertRaises(PolicyError) as ctx:
            client.get("http://internal.example/")
        self.assertEqual(ctx.exception.host, "internal.example")
        self.assertEqual(ctx.exception.address, "10.1.2.3")
        self.assertEqual(ctx.exception.hop, 0)
        self.assertIn("10.1.2.3", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
