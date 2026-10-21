"""Parser for Apache/Nginx `combined` access log lines."""

import gzip
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

LINE_RE = re.compile(
    r'^(?P<host>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<request>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<size>\d+|-) '
    r'"(?P<referer>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)"\s*$'
)
TIME_RE = re.compile(r"(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})")
# Month names are fixed in the log format: never rely on the OS locale.
MONTH_NAMES = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
               "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
MONTHS = {name: i for i, name in enumerate(MONTH_NAMES, start=1)}


@dataclass
class Request:
    host: str
    timestamp: datetime
    method: str | None
    path: str
    has_query: bool
    protocol: str | None
    status: int
    size: int
    referer: str | None
    user_agent: str | None


@dataclass
class ParseStats:
    lines: int = 0
    parsed: int = 0

    @property
    def malformed(self) -> int:
        return self.lines - self.parsed


def parse_time(raw: str) -> datetime:
    m = TIME_RE.fullmatch(raw)
    if not m or m.group(2) not in MONTHS:
        raise ValueError(f"bad timestamp: {raw!r}")
    day, month, year, hh, mm, ss, sign, off_h, off_m = m.groups()
    offset = timedelta(hours=int(off_h), minutes=int(off_m))
    if sign == "-":
        offset = -offset
    local = datetime(int(year), MONTHS[month], int(day), int(hh), int(mm), int(ss),
                     tzinfo=timezone(offset))
    return local.astimezone(UTC)


def format_time(ts: datetime) -> str:
    ts = ts.astimezone(UTC)
    return f"{ts.day:02d}/{MONTH_NAMES[ts.month - 1]}/{ts.year}:{ts:%H:%M:%S} +0000"


def _unescape(value: str) -> str:
    return value.replace('\\"', '"')


def _none_if_dash(value: str) -> str | None:
    return None if value in ("", "-") else value


def parse_line(line: str) -> Request | None:
    m = LINE_RE.match(line.rstrip("\r\n"))
    if not m:
        return None
    try:
        timestamp = parse_time(m["time"])
    except ValueError:
        return None
    request = _unescape(m["request"])
    parts = request.split(" ")
    if len(parts) == 3 and parts[2].startswith("HTTP/"):
        method, target, protocol = parts
    else:
        # Binary junk or truncated request line (TLS on port 80, scanners): keep it as path.
        method, target, protocol = None, request, None
    path, _, query = target.partition("?")
    return Request(
        host=m["host"],
        timestamp=timestamp,
        method=method,
        path=path or "/",
        has_query=bool(query),
        protocol=protocol,
        status=int(m["status"]),
        size=0 if m["size"] == "-" else int(m["size"]),
        referer=_none_if_dash(_unescape(m["referer"])),
        user_agent=_none_if_dash(_unescape(m["ua"])),
    )


def open_text(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open(encoding="utf-8", errors="replace")


def parse_file(path: Path, stats: ParseStats) -> Iterator[Request]:
    with open_text(path) as fh:
        for line in fh:
            if not line.strip():
                continue
            stats.lines += 1
            request = parse_line(line)
            if request is not None:
                stats.parsed += 1
                yield request
