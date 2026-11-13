"""High-level SSRF-safe HTTP client."""

from __future__ import annotations

import socket

from .clock import Clock, MonotonicClock
from .connection import Connector, DefaultConnector, SafeConnection
from .errors import (
    ConnectionFailedError,
    LimitExceeded,
    RedirectError,
    SafeRequestError,
)
from .http_layer import (
    Response,
    build_request,
    read_response,
    sanitize_headers,
)
from .http_layer import _HOP_BY_HOP
from .policy import Limits, Policy, Whitelist
from .redirect import (
    REDIRECT_STATUSES,
    detect_loop,
    next_location,
    redirect_method_and_body,
    resolve_redirect,
)
from .resolver import ResolvedAddress, Resolver, SystemResolver
from .urlmodel import Target, parse_url

_SENSITIVE_ON_CROSS_HOST = frozenset({"authorization", "cookie", "proxy-authorization"})


class SafeHttpClient:
    """An HTTP/HTTPS client that binds policy checks to actual connections.

    Every hop performs the full pipeline:
    strict URL parse -> host/port policy -> DNS resolution -> every resolved
    address classified -> connect only to an approved IP -> verify the kernel
    peer -> TLS with the original hostname -> bounded response read.
    """

    def __init__(
        self,
        *,
        whitelist: Whitelist | None = None,
        limits: Limits | None = None,
        resolver: Resolver | None = None,
        connector: Connector | None = None,
        clock: Clock | None = None,
        allow_https_downgrade: bool = False,
    ) -> None:
        self.policy = Policy(whitelist)
        self.limits = limits or Limits()
        self.resolver: Resolver = resolver or SystemResolver()
        self.connector: Connector = connector or DefaultConnector()
        self.clock: Clock = clock or MonotonicClock()
        self.allow_https_downgrade = allow_https_downgrade

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> Response:
        if not isinstance(method, str) or not method.isalpha():
            from .errors import RequestConfigError

            raise RequestConfigError("method must be an alphabetic string")
        method = method.upper()
        if body is not None and not isinstance(body, bytes):
            from .errors import RequestConfigError

            raise RequestConfigError("body must be bytes or None")
        extra_headers = sanitize_headers(headers)

        start = self.clock.now()
        deadline = start + self.limits.total_timeout
        target = parse_url(url)
        chain: list[Target] = []
        current_method = method
        current_body = body
        hop = 0

        while True:
            if self.clock.now() >= deadline:
                raise LimitExceeded(
                    "total request timeout elapsed before hop started",
                    reason="total_timeout",
                    limit=self.limits.total_timeout,
                    hop=hop,
                )
            if hop > self.limits.max_redirects:
                raise LimitExceeded(
                    f"redirect limit of {self.limits.max_redirects} exceeded",
                    reason="max_redirects",
                    limit=self.limits.max_redirects,
                    observed=hop,
                    hop=hop,
                )

            response, conn = self._execute_hop(
                target, extra_headers, current_method, current_body, deadline, hop
            )
            try:
                if response.status_code not in REDIRECT_STATUSES:
                    return response

                location = next_location(response)
                new_target = resolve_redirect(target, location, hop)
                detect_loop(chain, new_target, hop)
                if (
                    new_target.scheme == "http"
                    and target.scheme == "https"
                    and not self.allow_https_downgrade
                ):
                    raise RedirectError(
                        f"hop {hop}: refusing to downgrade from HTTPS to HTTP "
                        f"for host '{new_target.host}'",
                        hop=hop,
                        host=new_target.host,
                    )
                current_method, current_body = redirect_method_and_body(
                    current_method, current_body, response.status_code
                )
                extra_headers = self._filter_headers_for_redirect(
                    extra_headers, target, new_target
                )
                chain.append(target)
                target = new_target
                hop += 1
            finally:
                conn.close()

    def _execute_hop(
        self,
        target: Target,
        extra_headers: list[tuple[str, str]],
        method: str,
        body: bytes | None,
        deadline: float,
        hop: int,
    ) -> tuple[Response, SafeConnection]:
        self.policy.check_target(target, hop)
        import ipaddress

        if target.is_ip_literal:
            address = self.policy.check_address(target, target.host, hop)
            family = (
                socket.AF_INET6
                if isinstance(address, ipaddress.IPv6Address)
                else socket.AF_INET
            )
            approved = [ResolvedAddress(family=family, address=str(address))]
        else:
            resolved = self.resolver.resolve(target)
            approved = []
            for entry in resolved:
                checked = self.policy.check_address(target, entry.address, hop)
                family = (
                    socket.AF_INET6
                    if isinstance(checked, ipaddress.IPv6Address)
                    else socket.AF_INET
                )
                approved.append(
                    ResolvedAddress(family=family, address=str(checked))
                )

        connect_timeout = min(
            self.limits.connect_timeout, max(0.0, deadline - self.clock.now())
        )
        conn = self.connector.connect(target, approved, connect_timeout, hop)
        try:
            request_bytes = build_request(method, target, extra_headers, body)
            conn.sock.settimeout(
                min(self.limits.read_timeout, max(0.0, deadline - self.clock.now()))
            )
            conn.send_all(request_bytes)
            response = read_response(conn, self.limits, self.clock, deadline, hop)
            response.extra["approved_addresses"] = [
                entry.address for entry in approved
            ]
            return response, conn
        except SafeRequestError:
            conn.close()
            raise
        except socket.timeout as exc:
            conn.close()
            raise LimitExceeded(
                "socket timed out while sending the request",
                reason="read_timeout",
                limit=self.limits.read_timeout,
                hop=hop,
            ) from exc
        except OSError as exc:
            conn.close()
            raise ConnectionFailedError(
                f"hop {hop}: transport error talking to '{target.host}': {exc}",
                host=target.host,
                address=getattr(conn, "peer", None),
                hop=hop,
            ) from exc

    @staticmethod
    def _filter_headers_for_redirect(
        headers: list[tuple[str, str]], old: Target, new: Target
    ) -> list[tuple[str, str]]:
        same_host = (
            old.host == new.host and old.port == new.port and old.scheme == new.scheme
        )
        result: list[tuple[str, str]] = []
        for name, value in headers:
            lowered = name.lower()
            if lowered in _HOP_BY_HOP:
                continue
            if not same_host and lowered in _SENSITIVE_ON_CROSS_HOST:
                continue
            result.append((name, value))
        return result

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> Response:
        return self.request("GET", url, headers=headers)

    def post(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> Response:
        return self.request("POST", url, headers=headers, body=body)
