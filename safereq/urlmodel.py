"""Strict URL parsing and host classification.

The parser deliberately does not rely on the lenient behaviour of
:mod:`urllib.parse` alone: it rejects credentials, control characters,
backslashes, ambiguous host spellings and invalid ports up front instead of
silently normalising them.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .errors import URLError

_SCHEME_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class Target:
    """A fully validated request target.

 Attributes:
        scheme: Lower-cased ``http`` or ``https``.
        host: ASCII host name.  Domain names are lower-cased and encoded with
            IDNA; an IP literal is its canonical textual form.
        original_host: The host spelling provided by the caller (trimmed of
            IPv6 brackets), kept for diagnostics and IDNA comparison.
        port: Numeric port in the range 1-65535.
        path_query: Request target sent on the HTTP request line, beginning
            with ``/`` and including the query string when present.
        is_ip_literal: True when the host is an IPv4 or IPv6 literal.
        trailing_dot: True when a domain name ended with a dot.
    """

    scheme: str
    host: str
    original_host: str
    port: int
    path_query: str
    is_ip_literal: bool
    trailing_dot: bool

    @property
    def authority(self) -> str:
        """The host:port part with IPv6 brackets when needed."""
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"

    @property
    def host_header(self) -> str:
        """The Host header value: the default port is omitted."""
        host = f"[{self.host}]" if ":" in self.host else self.host
        if self.port == _SCHEME_DEFAULT_PORTS[self.scheme]:
            return host
        return f"{host}:{self.port}"

    @property
    def display_url(self) -> str:
        """A credential-free URL safe for error messages."""
        return f"{self.scheme}://{self.authority}{self.path_query}"


def _reject_control_and_backslash(value: str, component: str) -> None:
    for char in value:
        if char == "\\":
            raise URLError(f"backslash is not allowed in URL {component}")
        if ord(char) < 0x20 or ord(char) == 0x7F:
            raise URLError(f"control characters are not allowed in URL {component}")
    if any(char.isspace() for char in value):
        raise URLError(f"whitespace is not allowed in URL {component}")


def _parse_ip_literal(host: str) -> str | None:
    """Return the canonical IP form, or None if host is not an IP literal."""
    if host.startswith("["):
        if not host.endswith("]"):
            raise URLError("malformed IPv6 literal: missing closing ']'")
        inner = host[1:-1]
        if not inner or "%" in inner:
            raise URLError("empty or scoped IPv6 literal is not allowed")
        try:
            return str(ipaddress.IPv6Address(inner))
        except ValueError as exc:
            raise URLError(f"invalid IPv6 literal '{inner}'") from exc

    try:
        address = ipaddress.IPv4Address(host)
    except ValueError:
        return None
    return str(address)


def _validate_domain_label(label: str) -> None:
    if not label:
        raise URLError("empty label in domain name")
    if len(label) > 63:
        raise URLError(f"domain label longer than 63 octets: '{label}'")
    if label.startswith("-") or label.endswith("-"):
        raise URLError(f"domain label must not start or end with '-': '{label}'")
    if label.startswith("xn--"):
        try:
            label.encode("ascii")
            label[4:].encode("punycode")
        except UnicodeError as exc:
            raise URLError(f"invalid A-label '{label}'") from exc
        return
    for char in label:
        if not (char.isascii() and (char.isalnum() or char == "-")) and not (
            ord(char) > 127
        ):
            raise URLError(f"illegal character {char!r} in domain label")


def _normalize_domain(host: str) -> tuple[str, bool]:
    trailing_dot = host.endswith(".")
    if trailing_dot:
        host = host[:-1]
    if not host:
        raise URLError("empty host")
    if host.endswith(".") or ".." in host:
        raise URLError("multiple or misplaced dots in domain name")

    labels = host.split(".")
    ascii_labels: list[str] = []
    for label in labels:
        _validate_domain_label(label)
        if label.isascii():
            ascii_labels.append(label.lower())
        else:
            try:
                encoded = label.encode("idna")
            except UnicodeError as exc:
                raise URLError(f"internationalized domain label '{label}' cannot be encoded") from exc
            if not encoded.isascii():
                raise URLError(f"IDNA encoding produced non-ASCII label from '{label}'")
            ascii_labels.append(encoded.decode("ascii").lower())
    normalized = ".".join(ascii_labels)
    if len(normalized) > 253:
        raise URLError("domain name exceeds 253 octets after IDNA encoding")
    return normalized, trailing_dot


def _split_authority(authority: str) -> tuple[str, int]:
    _reject_control_and_backslash(authority, "authority")
    if "@" in authority:
        raise URLError("URL userinfo (username/password) is not allowed")

    if authority.startswith("["):
        closing = authority.find("]")
        if closing < 0:
            raise URLError("malformed IPv6 literal: missing closing ']'")
        host_part = authority[: closing + 1]
        remainder = authority[closing + 1 :]
        if remainder == "":
            port_part: str | None = None
        elif remainder.startswith(":"):
            port_part = remainder[1:]
            if ":" in port_part or "[" in port_part:
                raise URLError("malformed IPv6 authority")
        else:
            raise URLError("malformed authority after IPv6 literal")
    else:
        if authority.count(":") > 1:
            raise URLError("bare IPv6 addresses must be enclosed in brackets")
        if ":" in authority:
            host_part, port_part = authority.split(":", 1)
        else:
            host_part, port_part = authority, None

    if not host_part or host_part.strip("[]") == "":
        raise URLError("missing host")
    if port_part is None:
        port = -1
    else:
        if (
            port_part == ""
            or not port_part.isascii()
            or not port_part.isdigit()
            or any(ch.isspace() for ch in port_part)
        ):
            raise URLError(f"invalid port '{port_part}': port must be digits only")
        port = int(port_part)
        if not 1 <= port <= 65535:
            raise URLError(f"port {port} is outside the range 1-65535")
    return host_part, port


def parse_url(url: str) -> Target:
    """Validate ``url`` and return a :class:`Target`.

    Raises :class:`safereq.errors.URLError` for any malformed or forbidden
    component.  Fragments are rejected; credentials and control characters
    are never silently stripped.
    """
    if not isinstance(url, str) or not url:
        raise URLError("URL must be a non-empty string")
    _reject_control_and_backslash(url, "input")

    scheme_sep = url.find("://")
    if scheme_sep <= 0:
        raise URLError("URL must start with 'http://' or 'https://'")
    scheme = url[:scheme_sep].lower()
    if scheme not in _SCHEME_DEFAULT_PORTS:
        raise URLError(f"unsupported scheme '{scheme}': only http and https are allowed")
    rest = url[scheme_sep + 3 :]
    if not rest:
        raise URLError("missing authority")

    slash_index = rest.find("/")
    question_index = rest.find("?")
    fragment_index = rest.find("#")
    if fragment_index >= 0:
        raise URLError("URL fragments are not allowed")
    authority_end = min(
        index for index in (slash_index, question_index, len(rest)) if index >= 0
    )
    authority = rest[:authority_end]
    tail = rest[authority_end:]
    _reject_control_and_backslash(tail, "path/query")

    host_part, port = _split_authority(authority)
    if port < 0:
        port = _SCHEME_DEFAULT_PORTS[scheme]

    original_host = host_part[1:-1] if host_part.startswith("[") else host_part
    canonical_ip = _parse_ip_literal(host_part)
    if canonical_ip is not None:
        return Target(
            scheme=scheme,
            host=canonical_ip,
            original_host=original_host,
            port=port,
            path_query=tail or "/",
            is_ip_literal=True,
            trailing_dot=False,
        )

    stripped = host_part.replace(".", "")
    if stripped and (
        stripped.isdigit()
        or (
            stripped.startswith(("0x", "0X"))
            and all(ch in "0123456789abcdefABCDEFxX" for ch in stripped)
        )
        or all(ch in "0123456789abcdefABCDEF" for ch in stripped)
            and any(ch in "abcdefABCDEF" for ch in stripped)
    ):
        raise URLError(f"'{host_part}' looks like an IPv4 address but is not a valid one")
    normalized, trailing_dot = _normalize_domain(host_part)
    return Target(
        scheme=scheme,
        host=normalized,
        original_host=original_host,
        port=port,
        path_query=tail or "/",
        is_ip_literal=False,
        trailing_dot=trailing_dot,
    )
