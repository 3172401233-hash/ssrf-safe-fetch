"""Exception hierarchy used by :mod:`safereq`.

Every error raised by the public API is a subclass of
:class:`SafeRequestError`.  The hierarchy is intentionally split by failure
stage so callers can distinguish a bad URL, a policy rejection, a DNS
failure, a transport/TLS failure, a redirect problem and a resource-limit
breach without parsing message strings.

URL userinfo (``user:pass@host``) is rejected before any exception message is
formatted, so credentials can never leak through these messages.
"""

from __future__ import annotations


class SafeRequestError(Exception):
    """Base class for every error raised by the package."""


class RequestConfigError(SafeRequestError):
    """The caller passed an invalid request configuration."""


class URLError(SafeRequestError):
    """The URL itself is malformed or contains a forbidden component."""


class HeaderError(RequestConfigError):
    """A caller-supplied header is forbidden or malformed."""


class PolicyError(SafeRequestError):
    """A host/address/port was rejected by the security policy.

    ``reason`` is a stable machine-readable code, for example
    ``"loopback"`` or ``"port_not_allowed"``; ``host`` and ``address`` are
    populated where applicable.
    """

    def __init__(self, message: str, *, reason: str, host: str | None = None,
                 address: str | None = None, hop: int | None = None) -> None:
        super().__init__(message)
        self.reason = reason
        self.host = host
        self.address = address
        self.hop = hop


class DNSResolutionError(SafeRequestError):
    """DNS resolution failed or returned no usable addresses."""

    def __init__(self, message: str, *, host: str | None = None,
                 hop: int | None = None) -> None:
        super().__init__(message)
        self.host = host
        self.hop = hop


class ConnectionFailedError(SafeRequestError):
    """TCP connection establishment failed."""

    def __init__(self, message: str, *, host: str | None = None,
                 address: str | None = None, hop: int | None = None) -> None:
        super().__init__(message)
        self.host = host
        self.address = address
        self.hop = hop


class TLSError(SafeRequestError):
    """The TLS handshake or certificate verification failed."""

    def __init__(self, message: str, *, host: str | None = None,
                 address: str | None = None, hop: int | None = None) -> None:
        super().__init__(message)
        self.host = host
        self.address = address
        self.hop = hop


class PeerMismatchError(ConnectionFailedError):
    """The connected peer is not one of the approved addresses."""


class RedirectError(SafeRequestError):
    """A redirect response was invalid or the redirect chain is not allowed."""

    def __init__(self, message: str, *, hop: int | None = None,
                 host: str | None = None) -> None:
        super().__init__(message)
        self.hop = hop
        self.host = host


class LimitExceeded(SafeRequestError):
    """A resource limit was exceeded.

    ``limit`` carries the configured numeric bound (or ``None`` when not
    applicable) and ``observed`` the value that breached it.
    """

    def __init__(self, message: str, *, reason: str,
                 limit: int | float | None = None,
                 observed: int | float | None = None,
                 hop: int | None = None) -> None:
        super().__init__(message)
        self.reason = reason
        self.limit = limit
        self.observed = observed
        self.hop = hop


class ReadError(SafeRequestError):
    """Reading the response body failed after the connection was established."""

    def __init__(self, message: str, *, host: str | None = None,
                 address: str | None = None, hop: int | None = None) -> None:
        super().__init__(message)
        self.host = host
        self.address = address
        self.hop = hop


class ResponseError(SafeRequestError):
    """The response itself was malformed (bad headers, unsupported encoding...)."""
