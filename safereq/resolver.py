"""DNS resolution abstraction.

The default resolver uses :func:`socket.getaddrinfo` once per hop and returns
the full candidate set.  The client pins the *checked* results and passes
them to the connector, so the transport never performs a second, unchecked
resolution (DNS rebinding is blocked at the connector boundary).
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Protocol

from .errors import DNSResolutionError
from .urlmodel import Target


@dataclass(frozen=True)
class ResolvedAddress:
    """A single resolution result with the socket family it was returned for."""

    family: int
    address: str

    @property
    def ip(self) -> ipaddress._BaseAddress:
        return ipaddress.ip_address(self.address)


class Resolver(Protocol):
    def resolve(self, target: Target) -> list[ResolvedAddress]:
        """Return every address the target resolves to."""


class SystemResolver:
    """Default resolver backed by the standard library."""

    def __init__(self, getaddrinfo=socket.getaddrinfo) -> None:
        self._getaddrinfo = getaddrinfo

    def resolve(self, target: Target) -> list[ResolvedAddress]:
        try:
            infos = self._getaddrinfo(
                target.host,
                target.port,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
        except socket.gaierror as exc:
            raise DNSResolutionError(
                f"DNS resolution failed for host '{target.host}': {exc.strerror or exc}",
                host=target.host,
            ) from exc
        except OSError as exc:
            raise DNSResolutionError(
                f"DNS resolution failed for host '{target.host}': {exc}",
                host=target.host,
            ) from exc

        results: list[ResolvedAddress] = []
        seen: set[tuple[int, str]] = set()
        for family, _type, _proto, _canonname, sockaddr in infos:
            address = sockaddr[0]
            if "%" in address:
                address = address.split("%", 1)[0]
            key = (family, address)
            if key in seen:
                continue
            seen.add(key)
            results.append(ResolvedAddress(family=family, address=address))

        if not results:
            raise DNSResolutionError(
                f"DNS returned no usable addresses for host '{target.host}'",
                host=target.host,
            )
        return results
