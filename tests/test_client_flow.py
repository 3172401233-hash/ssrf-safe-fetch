import socket
import unittest

from safereq import (
    DNSResolutionError,
    HeaderError,
    LimitExceeded,
    PeerMismatchError,
    PolicyError,
    RedirectError,
    RequestConfigError,
    SafeHttpClient,
    Limits,
    Whitelist,
)
from safereq.urlmodel import parse_url

from tests.helpers import FakeClock, FakeConnector, FakeResolver, http_response


def make_client(resolver_map, scripted=None, *, limits=None, whitelist=None,
                clock=None):
    resolver = FakeResolver(resolver_map)
    connector = FakeConnector(scripted or {})
    client = SafeHttpClient(
        resolver=resolver,
        connector=connector,
        clock=clock or FakeClock(),
        limits=limits,
        whitelist=whitelist,
    )
    return client, resolver, connector


OK = http_response(body=b"hello")


class ResolutionAndConnectionTest(unittest.TestCase):
    def test_all_resolved_addresses_checked_and_rejection_lists_offender(self):
        client, resolver, connector = make_client(
            {"mix.example": ["8.8.8.5", "10.0.0.9"]},
            {"mix.example": [OK]},
        )
        with self.assertRaises(PolicyError) as ctx:
            client.get("http://mix.example/")
        self.assertEqual(ctx.exception.reason, "private")
        self.assertEqual(ctx.exception.address, "10.0.0.9")
        self.assertEqual(ctx.exception.host, "mix.example")
        self.assertEqual(resolver.calls, [("mix.example", 80)])
        self.assertEqual(connector.records, [])

    def test_loopback_link_local_multicast_rejected(self):
        for host, ip, reason in (
            ("lo.example", "127.0.0.1", "loopback"),
            ("ll.example", "169.254.169.254", "link_local"),
            ("mc.example", "224.0.0.251", "multicast"),
        ):
            client, _r, _c = make_client({host: [ip]}, {host: [OK]})
            with self.subTest(host=host):
                with self.assertRaises(PolicyError) as ctx:
                    client.get(f"http://{host}/")
                self.assertEqual(ctx.exception.reason, reason)

    def test_dns_failure_is_distinct_exception(self):
        client, _r, _c = make_client({}, {})
        with self.assertRaises(DNSResolutionError) as ctx:
            client.get("http://missing.example/")
        self.assertEqual(ctx.exception.host, "missing.example")

    def test_approved_ip_is_used_for_connection_without_second_lookup(self):
        client, resolver, connector = make_client(
            {"api.example": ["8.8.8.5", "8.8.8.6"]},
            {"api.example": [OK]},
        )
        response = client.get("http://api.example/v1")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.body, b"hello")
        self.assertEqual(resolver.calls, [("api.example", 80)])
        record = connector.records[0]
        approved = [entry.address for entry in record.approved]
        self.assertEqual(approved, ["8.8.8.5", "8.8.8.6"])
        self.assertEqual(record.target.host, "api.example")
        self.assertEqual(response.extra["approved_addresses"], approved)

    def test_dns_rebinding_between_check_and_connect_is_blocked(self):
        resolver = FakeResolver({"api.example": ["8.8.8.5"]})
        connector = FakeConnector({"api.example": [OK]})
        connector.peer_mismatch = "127.0.0.1"
        client = SafeHttpClient(
            resolver=resolver, connector=connector, clock=FakeClock()
        )
        with self.assertRaises(PeerMismatchError) as ctx:
            client.get("http://api.example/")
        self.assertEqual(ctx.exception.address, "127.0.0.1")
        self.assertEqual(ctx.exception.host, "api.example")

    def test_ip_literal_target_skips_dns_but_still_classified(self):
        connector = FakeConnector({"*": [OK]})
        client = SafeHttpClient(connector=connector, clock=FakeClock())
        response = client.get("http://8.8.8.9/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(connector.records[0].approved[0].address,
                         "8.8.8.9")
        with self.assertRaises(PolicyError) as ctx:
            client.get("http://192.168.0.9/")
        self.assertEqual(ctx.exception.reason, "private")

    def test_mapped_ipv6_literal_is_classified_as_ipv4_family(self):
        class MappedResolver:
            def resolve(self, target):
                from safereq.resolver import ResolvedAddress
                return [ResolvedAddress(
                    socket.AF_INET6, "::ffff:8.8.8.5")]

        connector = FakeConnector({"mapped.example": [OK]})
        client = SafeHttpClient(
            resolver=MappedResolver(), connector=connector,
            clock=FakeClock())
        client.get("http://mapped.example/")
        entry = connector.records[0].approved[0]
        self.assertEqual(entry.address, "8.8.8.5")
        self.assertEqual(entry.family, socket.AF_INET)

    def test_connection_closed_on_success_and_on_rejection(self):
        client, _r, connector = make_client(
            {"api.example": ["8.8.8.5"]}, {"api.example": [OK]})
        client.get("http://api.example/")
        self.assertTrue(connector.records[0].closed)

        bad_client, _r2, bad_connector = make_client(
            {"bad.example": ["127.0.0.1"]}, {"bad.example": [OK]})
        with self.assertRaises(PolicyError):
            bad_client.get("http://bad.example/")
        self.assertEqual(bad_connector.records, [])


class HeaderTest(unittest.TestCase):
    def test_forbidden_headers_rejected_with_reason(self):
        client, _r, _c = make_client({"a.example": ["1.2.3.4"]},
                                     {"a.example": [OK]})
        for name in ("Host", "host", "Connection", "Accept-Encoding",
                     "Transfer-Encoding", "Proxy-Connection", "Keep-Alive"):
            with self.subTest(name=name):
                with self.assertRaises(HeaderError) as ctx:
                    client.get("http://a.example/", headers={name: "x"})
                self.assertIn("managed or forbidden", ctx.exception.args[0])

    def test_sensitive_headers_allowed_per_request_but_present(self):
        client, _r, connector = make_client(
            {"a.example": ["1.2.3.4"]}, {"a.example": [OK]})
        client.get("http://a.example/",
                   headers={"Authorization": "Bearer t", "Cookie": "x=1"})
        request = connector.last_request_bytes[0].decode()
        self.assertIn("Authorization: Bearer t", request)
        self.assertIn("Cookie: x=1", request)

    def test_library_generates_host_and_identity_encoding(self):
        client, _r, connector = make_client(
            {"a.example": ["8.8.8.5"]}, {"a.example": [OK]})
        client.get("http://a.example:8080/path", headers={"X-Trace": "abc"})
        request = connector.last_request_bytes[0].decode("ascii")
        self.assertIn("Host: a.example:8080\r\n", request)
        self.assertIn("Accept-Encoding: identity\r\n", request)
        self.assertIn("Connection: close\r\n", request)
        self.assertIn("X-Trace: abc\r\n", request)
        self.assertTrue(request.startswith("GET /path HTTP/1.1\r\n"))

    def test_post_sends_content_length(self):
        client, _r, connector = make_client(
            {"a.example": ["8.8.8.5"]}, {"a.example": [OK]})
        client.post("http://a.example/", body=b"payload")
        request = connector.last_request_bytes[0]
        self.assertTrue(request.startswith(b"POST / HTTP/1.1\r\n"))
        self.assertIn(b"Content-Length: 7\r\n", request)
        self.assertTrue(request.endswith(b"payload"))

    def test_non_ascii_request_target_raises_config_error(self):
        client, _r, connector = make_client(
            {"a.example": ["8.8.8.5"]}, {"a.example": [OK]})
        with self.assertRaises(RequestConfigError):
            client.get("http://a.example/中文")
        self.assertTrue(connector.records[0].closed)


class RedirectTest(unittest.TestCase):
    def _redirect(self, location, status=302):
        return http_response(
            status=f"HTTP/1.1 {status} Found",
            headers=(("Location", location),),
        )

    def test_relative_redirect_rechecked_and_host_header_regenerated(self):
        client, resolver, connector = make_client(
            {"a.example": ["8.8.8.5"], "b.example": ["8.8.8.6"]},
            {
                "a.example": [self._redirect("/next"), OK],
                "b.example": [OK],
            },
        )
        response = client.get("http://a.example/start")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(connector.records), 2)
        self.assertEqual(
            connector.last_request_bytes[1].split(b"\r\n", 1)[0],
            b"GET /next HTTP/1.1",
        )

    def test_redirect_to_new_domain_resolves_and_checks_again(self):
        client, resolver, connector = make_client(
            {"a.example": ["8.8.8.5"],
             "internal.example": ["169.254.1.1"]},
            {"a.example": [self._redirect("http://internal.example/")]},
        )
        with self.assertRaises(PolicyError) as ctx:
            client.get("http://a.example/")
        self.assertEqual(ctx.exception.reason, "link_local")
        self.assertEqual(ctx.exception.host, "internal.example")
        self.assertEqual(ctx.exception.hop, 1)
        self.assertEqual(resolver.calls,
                         [("a.example", 80), ("internal.example", 80)])

    def test_https_downgrade_refused_by_default(self):
        client, _r, connector = make_client(
            {"secure.example": ["8.8.8.5"]},
            {"secure.example": [self._redirect("http://secure.example/")]},
        )
        with self.assertRaises(RedirectError) as ctx:
            client.get("https://secure.example/")
        self.assertIn("downgrade", ctx.exception.args[0])
        self.assertEqual(ctx.exception.hop, 0)

    def test_redirect_loop_and_missing_location(self):
        loop = self._redirect("/loop")
        client, _r, _c = make_client(
            {"a.example": ["8.8.8.5"]}, {"a.example": [loop, loop]})
        with self.assertRaises(RedirectError) as ctx:
            client.get("http://a.example/loop")
        self.assertIn("loop", ctx.exception.args[0])

        no_location = http_response(status="HTTP/1.1 302 Found")
        client2, _r2, _c2 = make_client(
            {"b.example": ["8.8.8.5"]}, {"b.example": [no_location]})
        with self.assertRaises(RedirectError) as ctx:
            client2.get("http://b.example/")
        self.assertIn("no Location", ctx.exception.args[0])

    def test_multiple_location_headers_ambiguous(self):
        response = (
            b"HTTP/1.1 302 Found\r\n"
            b"Location: /a\r\nLocation: /b\r\n\r\n"
        )
        client, _r, _c = make_client(
            {"a.example": ["8.8.8.5"]}, {"a.example": [response]})
        with self.assertRaises(RedirectError) as ctx:
            client.get("http://a.example/")
        self.assertIn("ambiguous", ctx.exception.args[0])

    def test_redirect_count_limit(self):
        chain = [
            self._redirect("/hop1"),
            self._redirect("/hop2"),
            self._redirect("/hop3"),
            self._redirect("/hop4"),
        ]
        client, _r, connector = make_client(
            {"a.example": ["8.8.8.5"]},
            {"a.example": chain},
            limits=Limits(max_redirects=2),
        )
        with self.assertRaises(LimitExceeded) as ctx:
            client.get("http://a.example/hop0")
        self.assertEqual(ctx.exception.reason, "max_redirects")
        self.assertEqual(ctx.exception.limit, 2)
        self.assertEqual(len(connector.records), 3)

    def test_sensitive_headers_dropped_on_cross_host_redirect(self):
        client, _r, connector = make_client(
            {"a.example": ["8.8.8.5"], "b.example": ["8.8.8.6"]},
            {
                "a.example": [self._redirect("http://b.example/")],
                "b.example": [OK],
            },
        )
        client.get(
            "http://a.example/",
            headers={"Authorization": "Bearer token", "X-Keep": "1"},
        )
        first = connector.last_request_bytes[0].decode()
        second = connector.last_request_bytes[1].decode()
        self.assertIn("Authorization: Bearer token", first)
        self.assertNotIn("Authorization", second)
        self.assertIn("X-Keep: 1", second)

    def test_303_changes_post_to_get_and_drops_body(self):
        client, _r, connector = make_client(
            {"a.example": ["8.8.8.5"], "b.example": ["8.8.8.6"]},
            {
                "a.example": [self._redirect("http://b.example/", status=303)],
                "b.example": [OK],
            },
        )
        client.post("http://a.example/", body=b"secret")
        second = connector.last_request_bytes[1]
        self.assertTrue(second.startswith(b"GET / HTTP/1.1"))
        self.assertNotIn(b"Content-Length", second)


class LimitTest(unittest.TestCase):
    def test_total_timeout_enforced_with_fake_clock(self):
        clock = FakeClock()
        client, _r, connector = make_client(
            {"a.example": ["8.8.8.5"]},
            {"a.example": [OK]},
            limits=Limits(total_timeout=3.0, connect_timeout=1.0),
            clock=clock,
        )
        inner_connect = connector.connect

        def slow_connect(target, approved, timeout, hop):
            clock.advance(3.5)
            return inner_connect(target, approved, timeout, hop)

        connector.connect = slow_connect
        with self.assertRaises(LimitExceeded) as ctx:
            client.get("http://a.example/")
        self.assertEqual(ctx.exception.reason, "total_timeout")

    def test_connect_timeout_value_passed_to_connector(self):
        clock = FakeClock()
        client, _r, connector = make_client(
            {"a.example": ["8.8.8.5"]}, {"a.example": [OK]},
            limits=Limits(connect_timeout=1.5, total_timeout=12.0),
            clock=clock,
        )
        clock.advance(9.0)
        client.get("http://a.example/")
        self.assertAlmostEqual(connector.records[0].timeout, 1.5)

    def test_body_size_limit_on_declared_content_length(self):
        big = http_response(
            headers=(("Content-Length", "100"),), body=b"")
        client, _r, _c = make_client(
            {"a.example": ["8.8.8.5"]}, {"a.example": [big]},
            limits=Limits(max_body_bytes=50),
        )
        with self.assertRaises(LimitExceeded) as ctx:
            client.get("http://a.example/")
        self.assertEqual(ctx.exception.reason, "body_size")
        self.assertEqual(ctx.exception.limit, 50)
        self.assertEqual(ctx.exception.observed, 100)


if __name__ == "__main__":
    unittest.main()
