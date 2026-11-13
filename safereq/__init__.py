"""safereq: SSRF-safe HTTP/HTTPS fetching on top of the standard library."""

from .client import SafeHttpClient
from .clock import Clock, MonotonicClock
from .connection import Connector, DefaultConnector, SafeConnection
from .errors import (
    ConnectionFailedError,
    DNSResolutionError,
    HeaderError,
    LimitExceeded,
    PeerMismatchError,
    PolicyError,
    ReadError,
    RedirectError,
    RequestConfigError,
    ResponseError,
    SafeRequestError,
    TLSError,
    URLError,
)
from .http_layer import Response
from .policy import Limits, Policy, Whitelist, classify_address
from .resolver import ResolvedAddress, Resolver, SystemResolver
from .urlmodel import Target, parse_url

__all__ = [
    "SafeHttpClient",
    "Limits",
    "Policy",
    "Whitelist",
    "Target",
    "Response",
    "SafeConnection",
    "ResolvedAddress",
    "Resolver",
    "SystemResolver",
    "Connector",
    "DefaultConnector",
    "Clock",
    "MonotonicClock",
    "parse_url",
    "classify_address",
    "SafeRequestError",
    "RequestConfigError",
    "URLError",
    "HeaderError",
    "PolicyError",
    "DNSResolutionError",
    "ConnectionFailedError",
    "TLSError",
    "PeerMismatchError",
    "RedirectError",
    "LimitExceeded",
    "ReadError",
    "ResponseError",
]

__version__ = "1.0.0"
