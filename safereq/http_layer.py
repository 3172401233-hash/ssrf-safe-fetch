"""Ministic HTTP/1.1 request and response handling on raw sockets."""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

from .clock import Clock
from .connection import SafeConnection
from .errors import LimitExceeded, ReadError, ResponseError
from .policy import Limits
from .urlmodel import Target

_FORBIDDEN_REQUEST_HEADERS = frozenset(
    {
        "host",
        "connection",
        "accept-encoding",
        "content-length",
        "transfer-encoding",
        "proxy-connection",
        "te",
        "trailer",
        "upgrade",
        "keep-alive",
    }
)

SENSITIVE_REQUEST_HEADERS = frozenset(
    {"authorization", "cookie", "proxy-authorization"}
)

_HOP_BY_HOP = frozenset(
    {
        "connection",
        "proxy-connection",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)


@dataclass
class Response:
    status_code: int
    reason: str
    headers: dict[str, str]
    raw_headers: list[tuple[str, str]]
    body: bytes
    target: Target
    peer: str
    hop: int
    extra: dict = field(default_factory=dict)

    def header(self, name: str) -> str | None:
        lowered = name.lower()
        for key, value in self.raw_headers:
            if key.lower() == lowered:
                return value
        return None

    def header_all(self, name: str) -> list[str]:
        lowered = name.lower()
        return [value for key, value in self.raw_headers if key.lower() == lowered]


def _read_until_headers(
    conn: SafeConnection,
    limits: Limits,
    clock: Clock,
    deadline: float,
    hop: int,
) -> tuple[bytes, bytes]:
    buffer = bytearray()
    while b"\r\n\r\n" not in buffer:
        if len(buffer) >= limits.max_header_bytes:
            raise LimitExceeded(
                f"response headers exceeded {limits.max_header_bytes} bytes",
                reason="header_size",
                limit=limits.max_header_bytes,
                observed=len(buffer),
                hop=hop,
            )
        timeout = _remaining(clock, deadline, limits)
        conn.sock.settimeout(timeout)
        recv_size = min(
            limits.read_chunk_size,
            8192,
            limits.max_header_bytes - len(buffer) + 1,
        )
        try:
            chunk = conn.recv(recv_size)
        except socket.timeout as exc:
            raise LimitExceeded(
                "read timeout while waiting for response headers",
                reason="read_timeout",
                limit=limits.read_timeout,
                hop=hop,
            ) from exc
        except OSError as exc:
            raise ReadError(
                f"failed to read response headers: {exc}",
                host=conn.target.host,
                address=conn.peer,
            ) from exc
        if not chunk:
            raise ReadError(
                "connection closed before complete response headers were received",
                host=conn.target.host,
                address=conn.peer,
            )
        buffer.extend(chunk)
        if len(buffer) > limits.max_header_bytes:
            raise LimitExceeded(
                f"response headers exceeded {limits.max_header_bytes} bytes",
                reason="header_size",
                limit=limits.max_header_bytes,
                observed=len(buffer),
                hop=hop,
            )
    header_block, _, leftover = buffer.partition(b"\r\n\r\n")
    return bytes(header_block), bytes(leftover)


def _remaining(clock: Clock, deadline: float, limits: Limits) -> float:
    remaining = deadline - clock.now()
    if remaining <= 0:
        raise LimitExceeded(
            "total request timeout elapsed",
            reason="total_timeout",
            limit=limits.total_timeout,
        )
    return min(remaining, limits.read_timeout)


def _parse_status(line: str) -> tuple[int, str]:
    parts = line.split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        raise ResponseError(f"malformed status line: {line!r}")
    version = parts[0].split("/", 1)[1]
    if version not in ("1.0", "1.1"):
        raise ResponseError(f"unsupported HTTP version: {version}")
    try:
        status_code = int(parts[1])
    except ValueError as exc:
        raise ResponseError(f"non-numeric status code in {line!r}") from exc
    reason = parts[2] if len(parts) == 3 else ""
    return status_code, reason


def _parse_headers(block: bytes) -> list[tuple[str, str]]:
    lines = block.split(b"\r\n")
    status_line = lines[0].decode("iso-8859-1")
    status_code, reason = _parse_status(status_line)
    headers: list[tuple[str, str]] = []
    for raw_line in lines[1:]:
        if not raw_line:
            continue
        if raw_line[:1] in (b" ", b"\t"):
            if not headers:
                raise ResponseError("obsolete line folding without a previous header")
            key, value = headers[-1]
            headers[-1] = (key, value + " " + raw_line.decode("iso-8859-1").strip())
            continue
        try:
            name, value = raw_line.decode("iso-8859-1").split(":", 1)
        except ValueError as exc:
            raise ResponseError(f"malformed header line: {raw_line!r}") from exc
        if not name or any(ch in name for ch in " \t"):
            raise ResponseError(f"malformed header name: {name!r}")
        headers.append((name.strip(), value.strip()))
    return status_code, reason, headers


def _recv_more(
    conn: SafeConnection,
    limits: Limits,
    clock: Clock,
    deadline: float,
    hop: int,
) -> bytes:
    timeout = _remaining(clock, deadline, limits)
    conn.sock.settimeout(timeout)
    try:
        return conn.recv(limits.read_chunk_size)
    except socket.timeout as exc:
        raise LimitExceeded(
            "read timeout while reading the response body",
            reason="read_timeout",
            limit=limits.read_timeout,
            hop=hop,
        ) from exc
    except OSError as exc:
        raise ReadError(
            f"failed to read response body: {exc}",
            host=conn.target.host,
            address=conn.peer,
        ) from exc


def _enforce_body_cap(
    body: bytearray, limits: Limits, conn: SafeConnection, hop: int
) -> None:
    if len(body) > limits.max_body_bytes:
        raise LimitExceeded(
            f"response body exceeded {limits.max_body_bytes} bytes",
            reason="body_size",
            limit=limits.max_body_bytes,
            observed=len(body),
            hop=hop,
        )


def _read_fixed_body(
    conn: SafeConnection,
    limits: Limits,
    clock: Clock,
    deadline: float,
    content_length: int,
    initial: bytes,
    hop: int,
) -> bytes:
    body = bytearray(initial)
    while len(body) < content_length:
        if len(body) >= limits.max_body_bytes:
            break
        chunk = _recv_more(conn, limits, clock, deadline, hop)
        if not chunk:
            raise ReadError(
                "connection closed before the declared body was fully received",
                host=conn.target.host,
                address=conn.peer,
            )
        body.extend(chunk)
        _enforce_body_cap(body, limits, conn, hop)
    if len(body) > content_length:
        raise ResponseError("server returned more bytes than Content-Length declared")
    if len(body) < content_length:
        raise LimitExceeded(
            f"response body exceeded {limits.max_body_bytes} bytes",
            reason="body_size",
            limit=limits.max_body_bytes,
            observed=content_length,
                hop=hop,
        )
    return bytes(body[:content_length])


def _read_chunked(
    conn: SafeConnection,
    limits: Limits,
    clock: Clock,
    deadline: float,
    initial: bytes,
    hop: int,
) -> bytes:
    buffered = bytearray(initial)
    body = bytearray()

    def pull() -> bytes:
        chunk = _recv_more(conn, limits, clock, deadline, hop)
        if not chunk:
            raise ReadError(
                "connection closed in the middle of a chunked body",
                host=conn.target.host,
                address=conn.peer,
            )
        buffered.extend(chunk)

    while True:
        while b"\r\n" not in buffered:
            pull()
        size_line, _, rest = buffered.partition(b"\r\n")
        buffered = bytearray(rest)
        size_text = size_line.split(b";", 1)[0].strip()
        try:
            chunk_size = int(size_text, 16)
        except ValueError as exc:
            raise ResponseError(f"invalid chunk size {size_text!r}") from exc
        if chunk_size == 0:
            while b"\r\n" not in buffered:
                pull()
            return bytes(body)
        if len(body) + chunk_size > limits.max_body_bytes:
            raise LimitExceeded(
                f"response body exceeded {limits.max_body_bytes} bytes",
                reason="body_size",
                limit=limits.max_body_bytes,
                observed=len(body) + chunk_size,
                hop=hop,
            )
        while len(buffered) < chunk_size + 2:
            if len(body) + chunk_size > limits.max_body_bytes:
                raise LimitExceeded(
                    f"response body exceeded {limits.max_body_bytes} bytes",
                    reason="body_size",
                    limit=limits.max_body_bytes,
                    observed=len(body) + chunk_size,
                    hop=hop,
                )
            pull()
        data = bytes(buffered[:chunk_size])
        if buffered[chunk_size : chunk_size + 2] != b"\r\n":
            raise ResponseError("chunk not terminated by CRLF")
        del buffered[: chunk_size + 2]
        body.extend(data)
        _enforce_body_cap(body, limits, conn, hop)


def _read_until_close(
    conn: SafeConnection,
    limits: Limits,
    clock: Clock,
    deadline: float,
    initial: bytes,
    hop: int,
) -> bytes:
    body = bytearray(initial)
    _enforce_body_cap(body, limits, conn, hop)
    while True:
        chunk = _recv_more(conn, limits, clock, deadline, hop)
        if not chunk:
            return bytes(body)
        body.extend(chunk)
        _enforce_body_cap(body, limits, conn, hop)


def read_response(
    conn: SafeConnection, limits: Limits, clock: Clock, deadline: float, hop: int
) -> Response:
    """Read a complete HTTP response, enforcing every size/time limit."""
    block, leftover = _read_until_headers(conn, limits, clock, deadline, hop)
    status_code, reason, raw_headers = _parse_headers(block)

    transfer_encodings = [
        value.lower()
        for key, value in raw_headers
        if key.lower() == "transfer-encoding"
    ]
    content_lengths = [
        value for key, value in raw_headers if key.lower() == "content-length"
    ]
    content_encoding = None
    for key, value in raw_headers:
        if key.lower() == "content-encoding":
            content_encoding = value.strip().lower()

    if transfer_encodings:
        if len(transfer_encodings) > 1:
            raise ResponseError("multiple Transfer-Encoding headers are not allowed")
        if transfer_encodings[0] != "chunked":
            raise ResponseError(
                f"unsupported transfer encoding '{transfer_encodings[0]}'; "
                "only 'chunked' is supported"
            )
        if content_lengths:
            raise ResponseError(
                "message must not contain both Transfer-Encoding and Content-Length"
            )
        body = _read_chunked(conn, limits, clock, deadline, leftover, hop)
    elif content_lengths:
        if len(content_lengths) > 1:
            raise ResponseError("multiple Content-Length headers are not allowed")
        try:
            content_length = int(content_lengths[0].strip())
        except ValueError as exc:
            raise ResponseError("non-numeric Content-Length value") from exc
        if content_length < 0:
            raise ResponseError("negative Content-Length value")
        if content_length > limits.max_body_bytes:
            raise LimitExceeded(
                f"declared Content-Length {content_length} exceeds body limit",
                reason="body_size",
                limit=limits.max_body_bytes,
                observed=content_length,
            )
        body = _read_fixed_body(
            conn, limits, clock, deadline, content_length, leftover, hop
        )
    else:
        body = _read_until_close(conn, limits, clock, deadline, leftover, hop)

    if content_encoding not in (None, "", "identity"):
        raise ResponseError(
            f"unsupported Content-Encoding '{content_encoding}'; "
            "only identity encoding is accepted"
        )

    folded: dict[str, str] = {}
    for key, value in raw_headers:
        folded.setdefault(key.lower(), value)
    return Response(
        status_code=status_code,
        reason=reason,
        headers=folded,
        raw_headers=raw_headers,
        body=body,
        target=conn.target,
        peer=conn.peer,
        hop=hop,
    )


def sanitize_headers(headers: dict[str, str] | None) -> list[tuple[str, str]]:
    """Validate caller headers and strip anything the library controls."""
    if not headers:
        return []
    result: list[tuple[str, str]] = []
    for name, value in headers.items():
        if not isinstance(name, str) or not name.strip():
            from .errors import HeaderError

            raise HeaderError("header names must be non-empty strings")
        if not isinstance(value, str):
            from .errors import HeaderError

            raise HeaderError(f"header '{name}' must have a string value")
        lowered = name.lower()
        if lowered in _FORBIDDEN_REQUEST_HEADERS:
            from .errors import HeaderError

            raise HeaderError(
                f"header '{name}' is managed or forbidden and cannot be overridden"
            )
        if any(ord(ch) < 0x20 for ch in value):
            from .errors import HeaderError

            raise HeaderError(f"header '{name}' contains control characters")
        result.append((name.strip(), value.strip()))
    return result


def build_request(
    method: str,
    target: Target,
    extra_headers: list[tuple[str, str]],
    body: bytes | None,
) -> bytes:
    lines = [f"{method.upper()} {target.path_query} HTTP/1.1"]
    lines.append(f"Host: {target.host_header}")
    lines.append("Accept-Encoding: identity")
    lines.append("Connection: close")
    lines.append("User-Agent: safereq/1.0")
    if body is not None:
        lines.append(f"Content-Length: {len(body)}")
    lines.extend(f"{name}: {value}" for name, value in extra_headers)
    lines.append("")
    lines.append("")
    head = "\r\n".join(lines)
    try:
        return head.encode("ascii") + (body or b"")
    except UnicodeEncodeError as exc:
        from .errors import RequestConfigError

        raise RequestConfigError(
            "request target and headers must be ASCII; percent-encode any "
            "non-ASCII path or query before sending"
        ) from exc
