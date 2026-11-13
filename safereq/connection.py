"""TCP/TLS connector bound to pre-approved addresses.

The connector receives the exact addresses that passed policy checks and
connects to them directly by IP.  After the TCP handshake it re-reads the
peer address from the kernel and verifies membership in the approved set,
closing the socket immediately on mismatch.  For HTTPS the original domain
name is used for SNI and certificate verification even though the TCP
connection goes to a literal IP.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from dataclasses import dataclass
from typing import Protocol

from .errors import (
    ConnectionFailedError,
    PeerMismatchError,
    TLSError,
)
from .resolver import ResolvedAddress
from .urlmodel import Target


@dataclass
class SafeConnection:
    """A live, policy-approved connection.

    ``close()`` is idempotent and swallows transport errors so callers can
    always use it inside ``finally`` blocks.
    """

    sock: socket.socket
    target: Target
    peer: str
    tls: bool

    def send_all(self, data: bytes) -> None:
        self.sock.sendall(data)

    def recv(self, size: int) -> bytes:
        return self.sock.recv(size)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class Connector(Protocol):
    def connect(
        self,
        target: Target,
        approved: list[ResolvedAddress],
        timeout: float,
        hop: int,
    ) -> SafeConnection:
        """Connect to one of ``approved`` without any additional DNS lookup."""


class DefaultConnector:
    """Production connector using raw :mod:`socket` and :mod:`ssl`."""

    def __init__(
        self,
        socket_factory=socket.socket,
        ssl_context_factory=None,
    ) -> None:
        self._socket_factory = socket_factory
        self._ssl_context_factory = ssl_context_factory or self._default_ssl_context

    @staticmethod
    def _default_ssl_context() -> ssl.SSLContext:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context

    def _wrap_tls(
        self, raw_sock: socket.socket, target: Target, hop: int
    ) -> ssl.SSLSocket:
        context = self._ssl_context_factory()
        if not getattr(context, "check_hostname", False):
            raise TLSError(
                "refusing to use an SSL context with hostname checking disabled",
                host=target.host,
                hop=hop,
            )
        if context.verify_mode != ssl.CERT_REQUIRED:
            raise TLSError(
                "refusing to use an SSL context that does not require certificates",
                host=target.host,
                hop=hop,
            )
        try:
            return context.wrap_socket(
                raw_sock, server_hostname=target.host, do_handshake_on_connect=True
            )
        except ssl.SSLError as exc:
            raw_sock.close()
            raise TLSError(
                f"TLS handshake with '{target.host}' failed: {exc}",
                host=target.host,
                hop=hop,
            ) from exc
        except OSError as exc:
            raw_sock.close()
            raise TLSError(
                f"TLS connection to '{target.host}' failed: {exc}",
                host=target.host,
                hop=hop,
            ) from exc

    def connect(
        self,
        target: Target,
        approved: list[ResolvedAddress],
        timeout: float,
        hop: int,
    ) -> SafeConnection:
        if not approved:
            raise ConnectionFailedError(
                f"hop {hop}: no approved addresses available for '{target.host}'",
                host=target.host,
                hop=hop,
            )

        approved_set = {entry.address for entry in approved}
        last_error: Exception | None = None
        for entry in approved:
            raw_sock = self._socket_factory(entry.family, socket.SOCK_STREAM)
            raw_sock.settimeout(timeout)
            try:
                raw_sock.connect((entry.address, target.port))
                peer_raw = raw_sock.getpeername()[0]
                peer = self._canonical_peer(peer_raw)
                if peer not in approved_set:
                    raw_sock.close()
                    raise PeerMismatchError(
                        f"hop {hop}: connected peer {peer} is not in the approved "
                        f"address set {sorted(approved_set)}",
                        host=target.host,
                        address=peer,
                        hop=hop,
                    )
                if target.scheme == "https":
                    sock = self._wrap_tls(raw_sock, target, hop)
                else:
                    sock = raw_sock
                return SafeConnection(
                    sock=sock, target=target, peer=peer, tls=target.scheme == "https"
                )
            except PeerMismatchError:
                raise
            except (OSError, TimeoutError) as exc:
                last_error = exc
                try:
                    raw_sock.close()
                except OSError:
                    pass
                continue

        raise ConnectionFailedError(
            f"hop {hop}: could not connect to any approved address of "
            f"'{target.host}': {last_error}",
            host=target.host,
            hop=hop,
        ) from last_error

    @staticmethod
    def _canonical_peer(peer: str) -> str:
        if "%" in peer:
            peer = peer.split("%", 1)[0]
        try:
            return str(ipaddress.ip_address(peer))
        except ValueError:
            return peer
