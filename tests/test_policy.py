import ipaddress
import unittest

from safereq.errors import PolicyError
from safereq.policy import Limits, Policy, Whitelist, classify_address
from safereq.urlmodel import parse_url


class ClassifyAddressTest(unittest.TestCase):
    def assert_rejected(self, raw: str, expected_reason: str):
        _address, reason = classify_address(raw)
        self.assertEqual(reason, expected_reason, raw)

    def test_public_addresses_accepted(self):
        for raw in ("8.8.8.8", "8.8.8.10", "2606:4700:4700::1111"):
            with self.subTest(raw=raw):
                _address, reason = classify_address(raw)
                self.assertEqual(reason, "public")

    def test_non_public_ipv4_ranges(self):
        cases = {
            "127.0.0.1": "loopback",
            "127.1.2.3": "loopback",
            "10.0.0.1": "private",
            "172.16.4.5": "private",
            "192.168.1.1": "private",
            "169.254.1.1": "link_local",
            "0.0.0.0": "unspecified",
            "224.0.0.1": "multicast",
            "255.255.255.255": "reserved",
        }
        for raw, reason in cases.items():
            with self.subTest(raw=raw):
                self.assert_rejected(raw, reason)

    def test_ipv6_non_public_ranges(self):
        cases = {
            "::1": "loopback",
            "::": "unspecified",
            "fe80::1": "link_local",
            "ff02::1": "multicast",
            "fc00::1": "private",
            "fd12::1": "private",
        }
        for raw, reason in cases.items():
            with self.subTest(raw=raw):
                self.assert_rejected(raw, reason)

    def test_ipv4_mapped_ipv6_unwrapped(self):
        address, reason = classify_address("::ffff:127.0.0.1")
        self.assertIsInstance(address, ipaddress.IPv4Address)
        self.assertEqual(reason, "loopback")
        address2, reason2 = classify_address("::ffff:10.0.0.1")
        self.assertIsInstance(address2, ipaddress.IPv4Address)
        self.assertEqual(reason2, "private")
        address3, reason3 = classify_address("::ffff:8.8.8.9")
        self.assertEqual(reason3, "public")
        self.assertEqual(str(address3), "8.8.8.9")


class WhitelistTest(unittest.TestCase):
    def test_domain_boundary_matching(self):
        whitelist = Whitelist(domains=("allowed.example",))
        self.assertTrue(whitelist.domain_allowed("allowed.example"))
        self.assertTrue(whitelist.domain_allowed("a.allowed.example"))
        self.assertTrue(whitelist.domain_allowed("ALLOWED.Example"))
        self.assertFalse(whitelist.domain_allowed("allowed.example.evil"))
        self.assertFalse(whitelist.domain_allowed("notallowed.example"))

    def test_leading_dot_pattern_equivalent(self):
        whitelist = Whitelist(domains=(".example.com",))
        self.assertTrue(whitelist.domain_allowed("example.com"))
        self.assertTrue(whitelist.domain_allowed("api.example.com"))
        self.assertFalse(whitelist.domain_allowed("example.com.evil"))

    def test_port_whitelist(self):
        whitelist = Whitelist(ports=(443, 8443))
        self.assertTrue(whitelist.port_allowed(443))
        self.assertFalse(whitelist.port_allowed(80))
        with self.assertRaises(ValueError):
            Whitelist(ports=(0,))
        with self.assertRaises(ValueError):
            Whitelist(ports=(70000,))

    def test_network_whitelist(self):
        whitelist = Whitelist(networks=("8.8.8.0/24", "2606:4700:4700::/48"))
        self.assertTrue(
            whitelist.address_allowed(ipaddress.ip_address("8.8.8.77"))
        )
        self.assertFalse(
            whitelist.address_allowed(ipaddress.ip_address("1.1.1.5"))
        )
        self.assertTrue(
            whitelist.address_allowed(ipaddress.ip_address("2606:4700:4700::9"))
        )
        with self.assertRaises(ValueError):
            Whitelist(networks=("not-a-network",))


class PolicyTargetTest(unittest.TestCase):
    def setUp(self):
        self.policy = Policy(Whitelist(
            domains=("allowed.example",), ports=(443, 8443),
            networks=("8.8.8.0/24",)))

    def test_target_rejected_by_domain_then_port(self):
        with self.assertRaises(PolicyError) as ctx:
            self.policy.check_target(parse_url("https://evil.example/"), 0)
        self.assertEqual(ctx.exception.reason, "domain_not_allowed")
        self.assertEqual(ctx.exception.hop, 0)
        with self.assertRaises(PolicyError) as ctx:
            self.policy.check_target(
                parse_url("https://allowed.example:9000/"), 2)
        self.assertEqual(ctx.exception.reason, "port_not_allowed")
        self.assertEqual(ctx.exception.hop, 2)

    def test_whitelist_does_not_widen_address_policy(self):
        loopback_policy = Policy(Whitelist(networks=("127.0.0.0/8",)))
        with self.assertRaises(PolicyError) as ctx:
            loopback_policy.check_address(
                parse_url("http://allowed.example/"), "127.0.0.1", 0)
        self.assertEqual(ctx.exception.reason, "loopback")

    def test_network_whitelist_applies_after_public_check(self):
        with self.assertRaises(PolicyError) as ctx:
            self.policy.check_address(
                parse_url("https://allowed.example/"), "1.1.1.5", 1)
        self.assertEqual(ctx.exception.reason, "network_not_allowed")
        self.assertEqual(ctx.exception.address, "1.1.1.5")
        self.assertEqual(ctx.exception.hop, 1)

    def test_approved_address_returned(self):
        address = self.policy.check_address(
            parse_url("https://allowed.example/"), "8.8.8.20", 0)
        self.assertEqual(str(address), "8.8.8.20")


class LimitsTest(unittest.TestCase):
    def test_invalid_limits_rejected_early(self):
        with self.assertRaises(ValueError):
            Limits(connect_timeout=0)
        with self.assertRaises(ValueError):
            Limits(total_timeout=-1)
        with self.assertRaises(ValueError):
            Limits(max_redirects=-1)
        with self.assertRaises(ValueError):
            Limits(max_body_bytes=-10)


if __name__ == "__main__":
    unittest.main()
