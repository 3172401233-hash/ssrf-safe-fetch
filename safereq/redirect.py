"""Per-hop redirect validation.

Every redirect target is reparsed and re-policy-checked from scratch: a new
domain means a new DNS resolution, address policy check and connection peer
check.  Relative ``Location`` values are resolved against the current hop.
"""

from __future__ import annotations

from urllib.parse import urljoin

from .errors import RedirectError
from .http_layer import Response
from .urlmodel import Target, parse_url

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_BODY_PRESERVING = frozenset({307, 308})


def next_location(response: Response) -> str:
    locations = response.header_all("Location")
    if not locations:
        raise RedirectError(
            f"hop {response.hop}: {response.status_code} response has no Location header",
            hop=response.hop,
            host=response.target.host,
        )
    if len(locations) > 1:
        raise RedirectError(
            f"hop {response.hop}: ambiguous response with {len(locations)} "
            "Location headers",
            hop=response.hop,
            host=response.target.host,
        )
    return locations[0].strip()


def resolve_redirect(current: Target, location: str, hop: int) -> Target:
    base = current.display_url
    joined = urljoin(base, location)
    try:
        target = parse_url(joined)
    except Exception as exc:
        raise RedirectError(
            f"hop {hop}: redirect target {location!r} is not a valid URL: {exc}",
            hop=hop,
            host=current.host,
        ) from exc
    return target


def redirect_method_and_body(
    method: str, body: bytes | None, status_code: int
) -> tuple[str, bytes | None]:
    if status_code in _BODY_PRESERVING:
        return method, body
    return "GET", None


def detect_loop(chain: list[Target], candidate: Target, hop: int) -> None:
    fingerprint = (candidate.scheme, candidate.host, candidate.port, candidate.path_query)
    for previous in chain:
        seen = (
            previous.scheme,
            previous.host,
            previous.port,
            previous.path_query,
        )
        if seen == fingerprint:
            raise RedirectError(
                f"hop {hop}: redirect loop detected at host '{candidate.host}' "
                f"{candidate.path_query}",
                hop=hop,
                host=candidate.host,
            )
