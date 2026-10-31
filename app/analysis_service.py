"""Parsers and transparent rule-based analysis for supported log formats.

This is an educational triage aid. Rules identify patterns worth reviewing; they
cannot establish intent, compromise, or attribution by themselves.
"""
from __future__ import annotations
import csv
import io
import json
import ipaddress
import re
from datetime import datetime, timezone, timedelta
from typing import Any

ISO_TS = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?")
IP_PATTERN = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
USER_PATTERN = re.compile(r"(?:user(?:name)?[=: ]+|for\s+(?:(?:invalid\s+)?user\s+)?)([A-Za-z0-9_.@-]{2,64})", re.I)
APACHE_PATTERN = re.compile(r'^(\S+) \S+ \S+ \[([^]]+)\] "([A-Z]+) ([^ ]+) [^"]+" (\d{3}) (\S+)', re.I)
CUSTOM_WEB_PATTERN = re.compile(r"^(?:\S+\s+)?((?:\d{1,3}\.){3}\d{1,3})\s+([A-Z]+)\s+(\S+)\s+(\d{3})(?:\s|$)", re.I)


def normalize_timestamp(raw: str | None) -> str | None:
    """Normalize ISO-like timestamps to UTC; naive timestamps assume UTC and are documented."""
    if not raw:
        return None
    value = raw.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    # fromisoformat accepts date/time strings without a timezone; the project explicitly assumes UTC.
    parsed = None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        # Common Event Viewer CSV date strings. Locale-specific ambiguous formats are deliberately not guessed.
        for date_format in ("%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S", "%Y-%m-%d %I:%M:%S %p", "%d/%b/%Y %H:%M:%S"):
            try:
                parsed = datetime.strptime(value, date_format)
                break
            except ValueError:
                continue
    if parsed is None:
        return None
    try:
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    except (ValueError, OverflowError):
        return None


def _classify(message: str) -> tuple[str, str, str]:
    lower = message.lower()
    if any(x in lower for x in ("failed password", "login failed", "authentication failure", "invalid password", "failed login", "logon failure")):
        return "authentication_failure", "medium", "Authentication failure-like event; a single failure is not a high-priority finding by itself"
    if any(x in lower for x in ("accepted password", "login successful", "authentication success", "logged in", "successful logon")):
        return "authentication_success", "info", "Authentication success-like event"
    if any(x in lower for x in ("critical", " error", "error:", "denied", "blocked")):
        return "system_warning", "medium", "System warning/error"
    return "log_event", "info", "Log event"


def _event_from_line(line: str, line_number: int) -> dict[str, Any] | None:
    text = line.strip()
    if not text:
        return None
    timestamp = None
    match = ISO_TS.search(text)
    if match:
        timestamp = normalize_timestamp(match.group(0))
    ip_match = IP_PATTERN.search(text)
    if ip_match:
        try: ipaddress.ip_address(ip_match.group(0))
        except ValueError: ip_match = None
    user_match = USER_PATTERN.search(text)
    event_type, severity, _ = _classify(text)
    http_match = APACHE_PATTERN.match(text)
    if http_match:
        ip, raw_date, method, path, status_code, _size = http_match.groups()
        try:
            stamp = datetime.strptime(raw_date, "%d/%b/%Y:%H:%M:%S %z")
            timestamp = stamp.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        except ValueError:
            pass
        ip_match_value = ip
        event_type = "http_access"
        status_int = int(status_code)
        severity = "medium" if status_int in (401, 403) or status_int >= 500 else "info"
        return {"timestamp": timestamp, "event_type": event_type, "source_ip": ip_match_value,
                "username": None, "severity": severity, "message": text[:5000],
                "line_number": line_number}
    custom_web = CUSTOM_WEB_PATTERN.search(text)
    if custom_web:
        ip, method, request_path, status_code = custom_web.groups()
        code = int(status_code)
        return {"timestamp": timestamp, "event_type": "http_access", "source_ip": ip,
                "username": user_match.group(1) if user_match else None,
                "severity": "medium" if code in (401, 403) or code >= 500 else "info",
                "message": text[:5000], "line_number": line_number}
    return {"timestamp": timestamp, "event_type": event_type,
            "source_ip": ip_match.group(0) if ip_match else None,
            "username": user_match.group(1) if user_match else None,
            "severity": severity, "message": text[:5000], "line_number": line_number}


def _event_from_json(obj: Any, line_number: int) -> dict[str, Any] | None:
    if not isinstance(obj, dict):
        return None
    aliases = {str(k).lower().replace(" ", "").replace("_", ""): v for k, v in obj.items()}
    def pick(*keys):
        return next((aliases[k] for k in keys if k in aliases and aliases[k] not in (None, "")), None)
    raw_message = pick("message", "event", "description", "log", "msg")
    message = str(raw_message if raw_message is not None else json.dumps(obj, ensure_ascii=False))[:5000]
    event = _event_from_line(message, line_number)
    if event is None:
        return None
    event["timestamp"] = normalize_timestamp(str(pick("timestamp", "time", "datetime", "timecreated", "date"))) or event["timestamp"]
    ip = pick("sourceip", "srcip", "clientip", "ipaddress", "ip")
    user = pick("username", "user", "account", "subjectusername")
    if ip is not None and IP_PATTERN.fullmatch(str(ip).strip()):
        try: ipaddress.ip_address(str(ip).strip()); event["source_ip"] = str(ip).strip()
        except ValueError: pass
    if user is not None:
        event["username"] = str(user)[:100]
    # Structured JSON attributes take precedence over guesses from free-text messages.
    structured_type = pick("eventtype", "category", "eventaction", "action")
    if structured_type:
        normalized_type = str(structured_type).strip().lower().replace(" ", "_")[:100]
        aliases_by_type = {
            "authentication_failure": "authentication_failure", "login_failed": "authentication_failure",
            "failed_login": "authentication_failure", "authentication_success": "authentication_success",
            "login_success": "authentication_success", "http_access": "http_access",
        }
        event["event_type"] = aliases_by_type.get(normalized_type, normalized_type)
    level = pick("leveldisplayname", "level", "severity", "loglevel")
    if level:
        normalized_level = str(level).strip().lower()
        if normalized_level in {"critical", "fatal", "emergency", "alert"}:
            event["severity"] = "high"
        elif normalized_level in {"error", "warning", "warn"}:
            event["severity"] = "medium"
        elif normalized_level in {"debug", "trace", "information", "informational", "info", "notice"}:
            event["severity"] = "info"
    provider = pick("providername", "provider", "source")
    event_id = pick("eventid", "eventcode", "recordid", "id")
    if provider or event_id:
        event["message"] = f"{message} [provider={str(provider)[:100] if provider else 'n/a'}, event_id={str(event_id)[:50] if event_id else 'n/a'}]"
    return event


def parse_log(content: bytes, filename: str) -> tuple[list[dict[str, Any]], int]:
    """Parse text, JSONL/JSON arrays, and common Event Viewer CSV exports.

    Returns (events, parsing_gaps). Gaps count non-empty source records that could
    not be structured plus records whose timestamp could not be recognized.
    """
    # UTF-8 BOM is common in Windows exports. If decoding fails, recover with replacement
    # characters but count the decode issue as a gap rather than silently claiming clean input.
    decode_gaps = 0
    try:
        text = content.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError:
        decode_gaps = 1
        text = content.decode("utf-8-sig", errors="replace")
    if "\x00" in text[:4096]:
        raise ValueError("Binary or unsupported text encoding detected; export the source as UTF-8 text/CSV first")
    suffix = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    events: list[dict[str, Any]] = []
    gaps = decode_gaps
    if suffix == "json":
        try:
            parsed = json.loads(text)
            records = parsed if isinstance(parsed, list) else [parsed]
            for index, obj in enumerate(records, 1):
                event = _event_from_json(obj, index)
                if event is None:
                    gaps += 1
                    continue
                if event["timestamp"] is None:
                    gaps += 1
                events.append(event)
            return events, gaps
        except json.JSONDecodeError:
            # A .json file may be JSON Lines; try each non-empty line below.
            pass
    if suffix == "csv":
        try:
            reader = csv.DictReader(io.StringIO(text))
            if reader.fieldnames:
                normalized = {str(k).strip().lower().replace(" ", "").replace("_", ""): k for k in reader.fieldnames if k}
                message_key = next((normalized[k] for k in ("message", "event", "log", "description") if k in normalized), None)
                timestamp_key = next((normalized[k] for k in ("timestamp", "time", "datetime", "date", "dateandtime", "timecreated", "systemtime") if k in normalized), None)
                # Windows Event Viewer CSV often uses Message and TimeCreated; support it explicitly.
                if message_key or any(k in normalized for k in ("eventid", "providername", "leveldisplayname")):
                    for line_no, row in enumerate(reader, 2):
                        if not any(v not in (None, "") for v in row.values()):
                            continue
                        message = str(row.get(message_key) or "") if message_key else ""
                        if not message.strip():
                            # Preserve useful Windows event metadata even if Message is blank.
                            message = "; ".join(f"{k}: {v}" for k, v in row.items() if v not in (None, ""))
                        event = _event_from_line(message, line_no)
                        if event is None:
                            gaps += 1
                            continue
                        if timestamp_key and row.get(timestamp_key):
                            event["timestamp"] = normalize_timestamp(str(row[timestamp_key])) or event["timestamp"]
                        def field(*keys):
                            key = next((normalized[k] for k in keys if k in normalized), None)
                            return row.get(key) if key else None
                        ip = field("ip", "sourceip", "srcip", "clientip")
                        username = field("username", "user", "account", "subjectusername")
                        if ip and IP_PATTERN.fullmatch(str(ip).strip()):
                            try: ipaddress.ip_address(str(ip).strip()); event["source_ip"] = str(ip).strip()
                            except ValueError: pass
                        if username: event["username"] = str(username)[:100]
                        level = field("level", "leveldisplayname", "severity")
                        if level and str(level).lower() in {"critical", "error", "warning"}:
                            event["severity"] = "high" if str(level).lower() == "critical" else "medium"
                        event_id = field("eventid", "eventcode", "recordid", "id")
                        provider = field("providername", "provider")
                        if event_id or provider:
                            event["message"] = f"{event['message']} [provider={provider or 'n/a'}, event_id={event_id or 'n/a'}]"
                        if event["timestamp"] is None: gaps += 1
                        events.append(event)
                    return events, gaps
        except csv.Error:
            return [], 1
    # JSON Lines is a practical fallback for JSON files with one object per line.
    if suffix == "json":
        for line_no, line in enumerate(text.splitlines(), 1):
            if not line.strip(): continue
            try: event = _event_from_json(json.loads(line), line_no)
            except json.JSONDecodeError: event = None
            if event is None: gaps += 1; continue
            if event["timestamp"] is None: gaps += 1
            events.append(event)
        return events, gaps
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip(): continue
        event = _event_from_line(line, line_no)
        if event is None:
            gaps += 1
            continue
        if event["timestamp"] is None: gaps += 1
        events.append(event)
    return events, gaps


def analyse_events(events: list[dict[str, Any]], threshold: int = 3) -> list[dict[str, Any]]:
    """Create event-linked, explainable findings; no synthetic 'no alert' finding."""
    # Finding event_ids are source-list indices here; the API replaces them with persisted DB IDs after insert.
    findings: list[dict[str, Any]] = []
    failures_by_ip: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for index, event in enumerate(events):
        # Do not aggregate unrelated failures under a synthetic "unknown source" and call it high severity.
        if event.get("event_type") == "authentication_failure" and event.get("source_ip"):
            failures_by_ip.setdefault(event["source_ip"], []).append((index, event))
    # Correlate only a bounded 15-minute window when timestamps exist. For undated
    # logs, retain a source-scoped count but disclose the missing temporal confidence.
    def parse_time(value):
        if not value: return None
        try: return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (ValueError, TypeError): return None
    for source_ip, pairs in failures_by_ip.items():
        dated = sorted([(parse_time(e.get("timestamp")), i, e) for i, e in pairs if parse_time(e.get("timestamp"))], key=lambda x: x[0])
        if dated:
            best = []
            left = 0
            for right in range(len(dated)):
                while dated[right][0] - dated[left][0] > timedelta(minutes=15): left += 1
                if right - left + 1 > len(best): best = dated[left:right + 1]
            if len(best) < threshold: continue
            selected = [(i, e) for _, i, e in best]
            times = [t for t, _, _ in best]
            time_note = "within a 15-minute window"
        else:
            if len(pairs) < threshold: continue
            selected = pairs
            times = []
            time_note = "across this file; timestamps were unavailable, so temporal clustering could not be confirmed"
        indices = [i for i, _ in selected]
        findings.append({"severity": "high", "title": "Repeated authentication failures",
            "rule_id": "AUTH-001", "description": f"{len(selected)} events matched authentication-failure patterns for source {source_ip} {time_note}. This may reflect mistyped credentials, a misconfigured service, or suspicious activity; it is not proof of compromise.",
            "rationale": f"Rule AUTH-001 triggered because {len(selected)} linked events from {source_ip} met the configured threshold of {threshold} {time_note}.",
            "recommended_action": "Review the linked events and original log context; validate the source host and account with the system owner before taking action.",
            "event_count": len(selected), "event_ids": indices, "start_timestamp": times[0].astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if times else None, "end_timestamp": times[-1].astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if times else None})
    # Correlate a repeated-failure cluster with a subsequent successful login from the same source.
    successes_by_ip: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for index, event in enumerate(events):
        if event.get("event_type") == "authentication_success" and event.get("source_ip"):
            successes_by_ip.setdefault(event["source_ip"], []).append((index, event))
    for source_ip, pairs in failures_by_ip.items():
        if len(pairs) < threshold or source_ip not in successes_by_ip: continue
        failed_times = [(i, e, parse_time(e.get("timestamp"))) for i, e in pairs]
        failed_times = [(i, e, t) for i, e, t in failed_times if t is not None]
        if not failed_times: continue
        latest_failure_time = max(t for _, _, t in failed_times)
        correlated = []
        for success_index, success in successes_by_ip[source_ip]:
            success_time = parse_time(success.get("timestamp"))
            if success_time is not None and timedelta(0) <= success_time - latest_failure_time <= timedelta(minutes=15):
                correlated.append((success_index, success, success_time))
        if correlated:
            related_failures = [(i, e, t) for i, e, t in failed_times if latest_failure_time - t <= timedelta(minutes=15)]
            # The success-after-failures rule requires a threshold-sized recent cluster,
            # not merely a historical count plus one later successful login.
            if len(related_failures) < threshold:
                continue
            linked = [i for i, _, _ in related_failures] + [i for i, _, _ in correlated]
            all_times = [t for _, _, t in related_failures] + [t for _, _, t in correlated]
            findings.append({"severity": "medium", "title": "Successful login after repeated failures", "rule_id": "AUTH-002",
                "description": f"At least one successful-login-like event from {source_ip} followed a cluster of authentication failures within 15 minutes. This warrants context review but does not establish account compromise.",
                "rationale": f"Rule AUTH-002 correlated {len(related_failures)} failure event(s) and {len(correlated)} success event(s) from the same source IP within the configured time window.",
                "recommended_action": "Confirm with the account owner whether the login was expected; review MFA, source host, session activity and adjacent events.",
                "event_count": len(linked), "event_ids": linked, "start_timestamp": min(all_times).astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                "end_timestamp": max(all_times).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")})

    http_by_ip: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for index, event in enumerate(events):
        if event.get("event_type") == "http_access" and event.get("source_ip") and re.search(r'(?:"\s+|[/\s])(?:401|403|404)(?:\s|$)', event.get("message", "")):
            http_by_ip.setdefault(event["source_ip"], []).append((index, event))
    for source_ip, pairs in http_by_ip.items():
        if len(pairs) >= threshold:
            times = sorted(e["timestamp"] for _, e in pairs if e.get("timestamp"))
            findings.append({"severity": "medium", "title": "Repeated HTTP client errors", "rule_id": "WEB-001",
                "description": f"{len(pairs)} HTTP requests from {source_ip} returned 401, 403, or 404 status codes. This can be routine client behavior or scanning and requires context.",
                "rationale": f"Rule WEB-001 triggered because {len(pairs)} matching requests met the configured threshold of {threshold}.",
                "recommended_action": "Review request paths, user-agent context if available, source ownership, and adjacent server logs.",
                "event_count": len(pairs), "event_ids": [i for i, _ in pairs], "start_timestamp": times[0] if times else None, "end_timestamp": times[-1] if times else None})
    warnings = [(i, e) for i, e in enumerate(events) if e.get("event_type") == "system_warning"]
    if len(warnings) >= threshold:
        times = sorted(e["timestamp"] for _, e in warnings if e.get("timestamp"))
        findings.append({"severity": "medium", "title": "Multiple system warning/error messages", "rule_id": "SYS-001",
            "description": f"{len(warnings)} log lines matched common warning/error phrases. Keyword matching can produce false positives.",
            "rationale": f"Rule SYS-001 triggered because {len(warnings)} matching events met the configured threshold of {threshold}.",
            "recommended_action": "Inspect the linked messages and correlate with application or operating-system health data.",
            "event_count": len(warnings), "event_ids": [i for i, _ in warnings], "start_timestamp": times[0] if times else None, "end_timestamp": times[-1] if times else None})
    return findings
