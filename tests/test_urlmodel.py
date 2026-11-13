import unittest

from safereq.errors import URLError
from safereq.urlmodel import parse_url


class ParseUrlTest(unittest.TestCase):
    def test_scheme_restricted_to_http_and_https(self):
        with self.assertRaises(URLError) as ctx:
            parse_url("ftp://example.com/")
        self.assertEqual(ctx.exception.args[0],
                         "unsupported scheme 'ftp': only http and https are allowed")
        with self.assertRaises(URLError):
            parse_url("file:///etc/passwd")
        with self.assertRaises(URLError):
            parse_url("gopher://example.com")

    def test_scheme_is_case_insensitive_but_normalised(self):
        target = parse_url("HTTP://Example.COM/path")
        self.assertEqual(target.scheme, "http")
        self.assertEqual(target.host, "example.com")
        self.assertEqual(target.port, 80)

    def test_credentials_are_rejected_not_silently_ignored(self):
        for url in (
            "http://user:pass@example.com/",
            "http://user@example.com/",
            "http://:@example.com/",
        ):
            with self.subTest(url=url):
                with self.assertRaises(URLError) as ctx:
                    parse_url(url)
                self.assertIn("userinfo", ctx.exception.args[0])

    def test_control_characters_and_backslashes_rejected(self):
        for url in (
            "http://example.com/a\rb",
            "http://example.com/a\nb",
            "http://example.com/a\tb",
            "http://example.com/a\x00b",
            "http://example.com/a\\b",
            "http://exa\\mple.com/",
            "http://example.com/a b",
        ):
            with self.subTest(url=repr(url)):
                with self.assertRaises(URLError):
                    parse_url(url)

    def test_invalid_ports_rejected(self):
        for port in ("0", "65536", "99999", "abc", "8 0", ""):
            with self.subTest(port=port):
                with self.assertRaises(URLError) as ctx:
                    parse_url(f"http://example.com:{port}/")
                if port != "8 0":
                    self.assertIn("port", ctx.exception.args[0])
                else:
                    self.assertIn("whitespace", ctx.exception.args[0])

    def test_path_separator_after_port_is_accepted(self):
        target = parse_url("http://example.com:8080/path")
        self.assertEqual(target.port, 8080)
        self.assertEqual(target.path_query, "/path")

    def test_default_ports_and_explicit_ports(self):
        self.assertEqual(parse_url("http://example.com/").port, 80)
        self.assertEqual(parse_url("https://example.com/").port, 443)
        target = parse_url("https://example.com:8443/x")
        self.assertEqual(target.port, 8443)
        self.assertEqual(target.host_header, "example.com:8443")
        self.assertEqual(parse_url("http://example.com:80/").host_header,
                         "example.com")

    def test_ipv4_literal_canonicalised(self):
        target = parse_url("http://8.8.8.10:8080/x")
        self.assertTrue(target.is_ip_literal)
        self.assertEqual(target.host, "8.8.8.10")

    def test_ambiguous_numeric_hosts_rejected(self):
        for host in ("0x7f000001", "2130706433", "0177.0.0.1", "127.0.0.1."):
            with self.subTest(host=host):
                with self.assertRaises(URLError):
                    parse_url(f"http://{host}/")

    def test_ipv6_literals(self):
        target = parse_url("http://[2001:db8::1]/x")
        self.assertTrue(target.is_ip_literal)
        self.assertEqual(target.host, "2001:db8::1")
        self.assertEqual(target.authority, "[2001:db8::1]:80")
        self.assertEqual(target.host_header, "[2001:db8::1]")
        target6 = parse_url("https://[2001:db8::1]:443/y")
        self.assertEqual(target6.host_header, "[2001:db8::1]")

    def test_bare_ipv6_and_bad_brackets_rejected(self):
        for url in (
            "http://2001:db8::1/",
            "http://[2001:db8::1/x",
            "http://2001:db8::1]/x",
            "http://[fe80::1%25eth0]/x",
            "http://[not-an-ip]/x",
        ):
            with self.subTest(url=url):
                with self.assertRaises(URLError):
                    parse_url(url)

    def test_domain_normalisation_and_trailing_dot(self):
        target = parse_url("http://WWW.Example.COM./x")
        self.assertEqual(target.host, "www.example.com")
        self.assertTrue(target.trailing_dot)
        with self.assertRaises(URLError):
            parse_url("http://example.com../x")
        with self.assertRaises(URLError):
            parse_url("http://exa..mple.com/x")

    def test_internationalised_domain_encoded_idna(self):
        target = parse_url("http://bücher.example/p")
        self.assertEqual(target.host, "xn--bcher-kva.example")
        target2 = parse_url("http://xn--bcher-kva.example/p")
        self.assertEqual(target2.host, "xn--bcher-kva.example")
        with self.assertRaises(URLError):
            parse_url("http://bad_label!.example/")

    def test_localhost_substring_in_domain_is_not_special_cased(self):
        target = parse_url("http://localhost.evil.example/")
        self.assertEqual(target.host, "localhost.evil.example")
        self.assertFalse(target.is_ip_literal)
        target2 = parse_url("http://notlocalhost/")
        self.assertEqual(target2.host, "notlocalhost")

    def test_fragment_and_empty_url_rejected(self):
        with self.assertRaises(URLError):
            parse_url("http://example.com/#frag")
        with self.assertRaises(URLError):
            parse_url("")
        with self.assertRaises(URLError):
            parse_url("http://")

    def test_path_defaults_to_slash_and_query_preserved(self):
        self.assertEqual(parse_url("http://example.com").path_query, "/")
        target = parse_url("http://example.com/a?x=1&y=2")
        self.assertEqual(target.path_query, "/a?x=1&y=2")

    def test_display_url_never_contains_credentials(self):
        target = parse_url("https://example.com:8443/a?b=1")
        self.assertEqual(target.display_url,
                         "https://example.com:8443/a?b=1")


if __name__ == "__main__":
    unittest.main()
