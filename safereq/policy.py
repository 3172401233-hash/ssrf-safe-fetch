"""Network reachability policy and whitelist matching.

The default policy only permits global/public addresses.  Whitelists narrow
the policy; they never widen it, so a whitelisted private or loopback address
is still refused.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from .errors import PolicyError
from .urlmodel import Target


def classify_address(raw: str) -> tuple[ipaddress._BaseAddress, str]:
    """Parse ``raw`` and classify it against the public-address policy.

    IPv4-mapped IPv6 addresses (``::ffff:1.2.3.4``) are unwrapped before
    classification, so a mapped loopback/private address cannot bypass checks.
    Returns ``(address, reason)`` where reason is ``"public"`` or the
    machine-readable rejection reason.
    """
    try:
        address = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise PolicyError(
            f"address '{raw}' is not a valid IP address", reason="invalid_address"
        ) from exc

    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped

    if address.is_loopback:
        reason = "loopback"
    elif address.is_unspecified:
        reason = "unspecified"
    elif address.is_link_local:
        reason = "link_local"
    elif address.is_multicast:
        reason = "multicast"
    elif address.is_reserved:
        reason = "reserved"
    elif address.is_private:
        reason = "private"
    else:
        reason = "public"

    if reason != "public" or not address.is_global:
        return address, "non_global" if reason == "public" else reason
    return address, "public"


def _domain_matches(pattern: str, host: str) -> bool:
    """Boundary-aware suffix matching.

    ``allowed.example`` matches itself and ``a.allowed.example`` but never
    ``allowed.example.evil``.  Leading dots are stripped; ``.example.com`` and
    ``example.com`` are equivalent whitelist entries.
    """
    pattern = pattern.lower().strip(".")
    host = host.lower().strip(".")
    if pattern == host:
        return True
    return host.endswith("." + pattern)


@dataclass
class Whitelist:
    """Optional host/IP/port allow-list.

    Empty entries mean "no restriction on this dimension".  Whitelisting only
    restricts which public targets may be reached; non-public addresses are
    always rejected regardless of whitelist membership.
    """

    domains: tuple[str, ...] = ()
    ports: tuple[int, ...] = ()
    networks: tuple[str, ...] = ()
    _network_objects: tuple = field(default=(), init=False, repr=False)

    def __post_init__(self) -> None:
        nets = []
        for entry in self.networks:
            try:
                nets.append(ipaddress.ip_network(entry, strict=False))
            except ValueError as exc:
                raise ValueError(f"invalid whitelist network '{entry}'") from exc
        for port in self.ports:
            if not 1 <= port <= 65535:
                raise ValueError(f"invalid whitelist port {port}")
        self._network_objects = tuple(nets)

    def domain_allowed(self, host: str) -> bool:
        if not self.domains:
            return True
        return any(_domain_matches(pattern, host) for pattern in self.domains)

    def port_allowed(self, port: int) -> bool:
        if not self.ports:
            return True
        return port in self.ports

    def address_allowed(self, address: ipaddress._BaseAddress) -> bool:
        if not self._network_objects:
            return True
        return any(address in network for network in self._network_objects)


@dataclass(frozen=True)
class Limits:
    """Resource limits applied to every request chain."""

    connect_timeout: float = 5.0
    read_timeout: float = 10.0
    total_timeout: float = 30.0
    max_redirects: int = 5
    max_header_bytes: int = 64 * 1024
    max_body_bytes: int = 5 * 1024 * 1024
    read_chunk_size: int = 64 * 1024

    def __post_init__(self) -> None:
        for name in ("connect_timeout", "read_timeout", "total_timeout"):
            value = getattr(self, name)
            if not isinstance(value, (int, float)) or value <= 0:
                raise ValueError(f"{name} must be a positive number")
        for name in ("max_redirects", "max_header_bytes", "max_body_bytes"):
            value = getattr(self, name)
            if not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        if self.read_chunk_size <= 0:
            raise ValueError("read_chunk_size must be positive")


class Policy:
    """Validates targets and resolved addresses against the policy."""

    def __init__(self, whitelist: Whitelist | None = None) -> None:
        self.whitelist = whitelist or Whitelist()

    def check_target(self, target: Target, hop: int) -> None:
        """Check the pre-DNS dimensions of a target (host name and port)."""
        if not self.whitelist.port_allowed(target.port):
            raise PolicyError(
                f"hop {hop}: port {target.port} is not in the port whitelist",
                reason="port_not_allowed",
                host=target.host,
                hop=hop,
            )
        if not target.is_ip_literal and not self.whitelist.domain_allowed(target.host):
            raise PolicyError(
                f"hop {hop}: host '{target.host}' is not in the domain whitelist",
                reason="domain_not_allowed",
                host=target.host,
                hop=hop,
            )

    def check_address(self, target: Target, raw: str, hop: int) -> object:
        """Classify one resolved address and apply whitelist network rules."""
        address, reason = classify_address(raw)
        if reason != "public":
            raise PolicyError(
                f"hop {hop}: address {raw} resolved for host '{target.host}' "
                f"is not a public address ({reason})",
                reason=reason,
                host=target.host,
                address=str(address),
                hop=hop,
            )
        if not self.whitelist.address_allowed(address):
            raise PolicyError(
                f"hop {hop}: address {raw} for host '{target.host}' is outside "
                "the whitelisted networks",
                reason="network_not_allowed",
                host=target.host,
                address=str(address),
                hop=hop,
            )
        return address
