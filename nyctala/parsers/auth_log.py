"""Parser for syslog-format auth logs (``/var/log/auth.log``, ``/var/log/syslog``).

Understands both the classic BSD header (``Oct 22 10:00:00 host prog[pid]: msg``,
no year and no zone) and the RFC 3339 header written by modern rsyslog
(``2026-10-22T10:00:00.123456+02:00 host prog[pid]: msg``).

Usernames are attacker-controlled and may contain spaces, so sshd patterns take
the *last* ``from <ip> port <n>`` in the line: that suffix is written by sshd
after the username and cannot be forged by it. All patterns are anchored and
use at most one unbounded group, so matching stays linear (no ReDoS).
"""

import ipaddress
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, tzinfo
from typing import Any

Fields = dict[str, Any]

MAX_REPEAT = 100

_BSD = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2}) {1,2}(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S{1,255}) (?P<prog>[^\s\[:]{1,64})(?:\[(?P<pid>\d{1,10})\])?: (?P<msg>.*)$"
)
_RFC3339 = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})) "
    r"(?P<host>\S{1,255}) (?P<prog>[^\s\[:]{1,64})(?:\[(?P<pid>\d{1,10})\])?: (?P<msg>.*)$"
)
_MONTH_NAMES = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_MONTHS = {name: number for number, name in enumerate(_MONTH_NAMES, 1)}

_REPEATED = re.compile(r"^message repeated (?P<n>\d{1,9}) times: \[ ?(?P<msg>.*?) ?\]$")

_SSH_AUTH = re.compile(
    r"^(?P<result>Accepted|Failed) (?P<method>\S{1,64}) for (?P<invalid>invalid user )?"
    r"(?P<user>.+) from (?P<ip>[0-9A-Fa-f:.]{2,45}) port (?P<port>\d{1,5})"
    r"(?: ssh2)?(?:: \S{1,32} \S{1,128})?$"
)
_SSH_INVALID = re.compile(
    r"^Invalid user (?P<user>.+) from (?P<ip>[0-9A-Fa-f:.]{2,45})(?: port (?P<port>\d{1,5}))?$"
)
_SSH_MAX_TRIES = re.compile(
    r"^error: maximum authentication attempts exceeded for (?P<invalid>invalid user )?"
    r"(?P<user>.+) from (?P<ip>[0-9A-Fa-f:.]{2,45}) port \d{1,5}(?: ssh2)?(?: \[preauth\])?$"
)
_SUDO = re.compile(
    r"^ *(?P<user>\S{1,256}) : (?:(?P<problem>[^;]{1,128}) ; )?TTY=(?P<tty>\S{1,64}) ; "
    r"PWD=(?P<pwd>[^;]{0,4096}) ; USER=(?P<target>\S{1,256}) ; (?:ENV=[^;]{0,4096} ; )?"
    r"COMMAND=(?P<cmd>.*)$"
)
_SU = re.compile(
    r"^(?P<failed>FAILED SU )?\(to (?P<target>[^\s)]{1,256})\) (?P<user>\S{1,256}) on \S{1,64}$"
)
_PAM_SESSION = re.compile(
    r"^pam_unix\((?P<service>[^:)]{1,64}):session\): session (?P<state>opened|closed) "
    r"for user (?P<target>[^\s(]{1,256})(?:\(uid=\d+\))?(?: by (?P<user>[^\s(]{0,256})"
    r"(?:\(uid=\d+\))?)?$"
)
_PAM_AUTH_FAIL = re.compile(
    r"^pam_unix\((?P<service>[^:)]{1,64}):auth\): authentication failure;(?P<kv>.*)$"
)
_KV = re.compile(r"(\w{1,32})=(\S{0,256})")
_CRONTAB = re.compile(
    r"^\((?P<user>[^)\s]{1,256})\) (?P<op>BEGIN EDIT|END EDIT|REPLACE|DELETE|LIST) "
    r"\((?P<target>[^)\s]{1,256})\)$"
)
_CRON_CMD = re.compile(r"^\((?P<user>[^)\s]{1,256})\) CMD \((?P<cmd>.*)\)$")


def _bsd_time(m: re.Match[str], received: datetime, tz: tzinfo) -> datetime | None:
    month = _MONTHS.get(m["mon"])
    if month is None:
        return None
    hh, mm, ss = (int(x) for x in m["time"].split(":"))
    reference = received.astimezone(tz)
    try:
        ts = datetime(reference.year, month, int(m["day"]), hh, mm, ss, tzinfo=tz)
    except ValueError:
        return None
    # No year in the header: a date "in the future" belongs to last year (Dec -> Jan).
    if ts - reference > timedelta(days=1):
        ts = ts.replace(year=ts.year - 1)
    return ts


def _ip_or_none(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        return None  # rhost may be a hostname or a tty


def _ssh(msg: str) -> Fields | None:
    if m := _SSH_AUTH.match(msg):
        ok = m["result"] == "Accepted"
        return {
            "event.category": "authentication",
            "event.action": "ssh_login",
            "event.outcome": "success" if ok else "failure",
            "user.name": m["user"],
            "source.ip": m["ip"],
            "tags": [f"ssh.method:{m['method']}"] + (["ssh.invalid_user"] if m["invalid"] else []),
        }
    if m := _SSH_INVALID.match(msg):
        return {
            "event.category": "authentication",
            "event.action": "ssh_invalid_user",
            "event.outcome": "failure",
            "user.name": m["user"],
            "source.ip": m["ip"],
            "tags": ["ssh.invalid_user"],
        }
    if m := _SSH_MAX_TRIES.match(msg):
        return {
            "event.category": "authentication",
            "event.action": "ssh_max_auth_tries",
            "event.outcome": "failure",
            "user.name": m["user"],
            "source.ip": m["ip"],
        }
    return None


def _sudo(msg: str) -> Fields | None:
    if m := _SUDO.match(msg):
        return {
            "event.category": "process",
            "event.action": "sudo_command",
            "event.outcome": "failure" if m["problem"] else "success",
            "user.name": m["user"],
            "user.target.name": m["target"],
            "process.command_line": m["cmd"],
            "file.path": m["pwd"],
            "tags": [f"sudo.problem:{m['problem']}"] if m["problem"] else [],
        }
    return None


def _su(msg: str) -> Fields | None:
    if m := _SU.match(msg):
        return {
            "event.category": "authentication",
            "event.action": "su",
            "event.outcome": "failure" if m["failed"] else "success",
            "user.name": m["user"],
            "user.target.name": m["target"],
        }
    return None


def _pam(msg: str) -> Fields | None:
    if m := _PAM_SESSION.match(msg):
        return {
            "event.category": "session",
            "event.action": f"session_{m['state']}",
            "event.outcome": "success",
            "user.name": m["user"] or None,
            "user.target.name": m["target"],
            "tags": [f"pam.service:{m['service']}"],
        }
    if m := _PAM_AUTH_FAIL.match(msg):
        kv = dict(_KV.findall(m["kv"]))
        return {
            "event.category": "authentication",
            "event.action": "pam_auth_failure",
            "event.outcome": "failure",
            "user.name": kv.get("ruser") or kv.get("logname") or None,
            "user.target.name": kv.get("user") or None,
            "source.ip": _ip_or_none(kv.get("rhost")),
            "tags": [f"pam.service:{m['service']}"],
        }
    return None


def _crontab(msg: str) -> Fields | None:
    if m := _CRONTAB.match(msg):
        op = m["op"].lower().replace(" ", "_")
        return {
            "event.category": "configuration",
            "event.action": f"crontab_{op}",
            "event.outcome": "success",
            "user.name": m["user"],
            "user.target.name": m["target"],
        }
    return None


def _cron(msg: str) -> Fields | None:
    if m := _CRON_CMD.match(msg):
        return {
            "event.category": "process",
            "event.action": "cron_command",
            "event.outcome": "success",
            "user.name": m["user"],
            "process.command_line": m["cmd"],
        }
    return None


_PROGRAMS: dict[str, Callable[[str], Fields | None]] = {
    "sshd": _ssh,
    "sshd-session": _ssh,
    "sudo": _sudo,
    "su": _su,
    "crontab": _crontab,
    "CRON": _cron,
    "cron": _cron,
}


def _message(prog: str, msg: str) -> Fields | None:
    if msg.startswith("pam_unix("):
        return _pam(msg)
    handler = _PROGRAMS.get(prog)
    return handler(msg) if handler else None


def parse(line: str, *, received: datetime, tz: tzinfo = UTC) -> list[Fields]:
    """Parse one auth.log line into one or more ECS-lite field dicts.

    Lines whose header cannot be parsed are kept (tagged ``nyctala.unparsed``)
    rather than dropped: unknown is still evidence.
    """
    base: Fields = {"event.original": line}
    header = _RFC3339.match(line)
    if header:
        base["@timestamp"] = datetime.fromisoformat(header["ts"].replace("Z", "+00:00"))
    elif header := _BSD.match(line):
        ts = _bsd_time(header, received, tz)
        if ts is None:
            header = None
        else:
            base["@timestamp"] = ts
    if header is None:
        return [{**base, "@timestamp": received, "tags": ["nyctala.unparsed"]}]

    base["host.name"] = header["host"]
    base["process.name"] = header["prog"]
    msg = header["msg"]
    count = 1
    if repeated := _REPEATED.match(msg):
        # rsyslog folds identical lines; unfold them so counting rules see every attempt.
        count = min(int(repeated["n"]), MAX_REPEAT)
        msg = repeated["msg"]
        base["tags"] = ["syslog.repeated"]

    fields = _message(header["prog"], msg)
    if fields is None:
        return [dict(base) for _ in range(count)]
    event = {**base, **fields, "tags": base.get("tags", []) + fields.get("tags", [])}
    return [dict(event) for _ in range(count)]
