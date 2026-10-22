"""Parser for nginx access logs in the default ``combined`` format.

    $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
    "$http_referer" "$http_user_agent"

Extra fields appended after the user agent (``$request_time`` and friends) are
tolerated. nginx escapes ``"`` and non-printable bytes inside quoted fields as
``\\xHH``, so a quoted field never contains a raw quote and the pattern needs no
backtracking. The request line is attacker-controlled and often garbage (TLS
handshakes on port 80, scanners): when it does not look like
``METHOD target PROTOCOL``, only the raw text is kept in ``event.original``.
URL paths and queries are stored exactly as logged, without decoding.
"""

import ipaddress
import re
from datetime import UTC, datetime, tzinfo
from typing import Any

Fields = dict[str, Any]

_COMBINED = re.compile(
    r"^(?P<addr>[0-9A-Fa-f:.]{2,45}) \S{1,64} (?P<user>\S{1,256}) "
    r"\[(?P<time>[^\]]{1,40})\] "
    r'"(?P<request>[^"]{0,16384})" (?P<status>\d{3}) (?P<bytes>\d{1,19}|-) '
    r'"(?P<referer>[^"]{0,8192})" "(?P<agent>[^"]{0,8192})"(?: .{0,4096})?$'
)
_REQUEST = re.compile(
    r"^(?P<method>[A-Z]{1,16}) (?P<target>\S{1,16384}) (?P<proto>HTTP/[0-9.]{1,3})$"
)


def _ip(value: str) -> str | None:
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        return None


def parse(line: str, *, received: datetime, tz: tzinfo = UTC) -> list[Fields]:
    """Parse one access log line. Unrecognised lines are kept, tagged ``nyctala.unparsed``."""
    m = _COMBINED.match(line)
    try:
        ts = datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z") if m else None
    except ValueError:
        ts = None
    if m is None or ts is None:
        return [{"event.original": line, "@timestamp": received, "tags": ["nyctala.unparsed"]}]

    status = int(m["status"])
    event: Fields = {
        "@timestamp": ts,
        "event.original": line,
        "event.category": "web",
        "event.action": "http_request",
        "event.outcome": "failure" if status >= 400 else "success",
        "source.ip": _ip(m["addr"]),
        "user.name": None if m["user"] == "-" else m["user"],
        "http.response.status_code": status,
        "http.response.bytes": None if m["bytes"] == "-" else int(m["bytes"]),
        "user_agent.original": None if m["agent"] == "-" else m["agent"],
        "tags": [],
    }
    if request := _REQUEST.match(m["request"]):
        path, _, query = request["target"].partition("?")
        event["http.request.method"] = request["method"]
        event["url.path"] = path
        event["url.query"] = query or None
    elif m["request"] not in ("", "-"):
        event["tags"] = ["http.malformed_request"]
    return [event]
