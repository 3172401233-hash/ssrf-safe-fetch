import unittest

from safereq import Limits, PolicyError, SafeHttpClient, Whitelist

from tests.helpers import FakeClock, FakeConnector, FakeResolver, http_response


class WhitelistIntegrationTest(unittest.TestCase):
    def test_lookalike_domain_cannot_impersonate_whitelisted_host(self):
        whitelist = Whitelist(domains=("allowed.example",), ports=(443,))
        resolver = FakeResolver({
            "allowed.example.evil": ["8.8.8.5"],
            "xnotallowed.example": ["8.8.8.6"],
        })
        connector = FakeConnector({})
        client = SafeHttpClient(
            whitelist=whitelist, resolver=resolver, connector=connector,
            clock=FakeClock(),
        )
        for host in ("allowed.example.evil", "xnotallowed.example"):
            with self.subTest(host=host):
                with self.assertRaises(PolicyError) as ctx:
                    client.get(f"https://{host}/")
                self.assertEqual(ctx.exception.reason, "domain_not_allowed")
        self.assertEqual(connector.records, [])

    def test_whitelisted_domain_and_subdomain_pass(self):
        whitelist = Whitelist(domains=("allowed.example",))
        resolver = FakeResolver({
            "allowed.example": ["8.8.8.5"],
            "api.allowed.example": ["8.8.8.6"],
        })
        connector = FakeConnector({
            "allowed.example": [http_response()],
            "api.allowed.example": [http_response()],
        })
        client = SafeHttpClient(
            whitelist=whitelist, resolver=resolver, connector=connector,
            clock=FakeClock(),
        )
        self.assertEqual(
            client.get("http://allowed.example/").status_code, 200)
        self.assertEqual(
            client.get("http://api.allowed.example/").status_code, 200)

    def test_whitelist_never_elevates_private_address(self):
        whitelist = Whitelist(networks=("10.0.0.0/8",),
                              domains=("internal.example",))
        resolver = FakeResolver({"internal.example": ["10.0.0.7"]})
        connector = FakeConnector({})
        client = SafeHttpClient(
            whitelist=whitelist, resolver=resolver, connector=connector,
            clock=FakeClock(),
        )
        with self.assertRaises(PolicyError) as ctx:
            client.get("http://internal.example/")
        self.assertEqual(ctx.exception.reason, "private")
        self.assertEqual(connector.records, [])

    def test_default_limits_are_documented_values(self):
        limits = Limits()
        self.assertEqual(limits.connect_timeout, 5.0)
        self.assertEqual(limits.read_timeout, 10.0)
        self.assertEqual(limits.total_timeout, 30.0)
        self.assertEqual(limits.max_redirects, 5)
        self.assertEqual(limits.max_header_bytes, 64 * 1024)
        self.assertEqual(limits.max_body_bytes, 5 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
