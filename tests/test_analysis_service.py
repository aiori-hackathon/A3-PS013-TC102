"""Parser and explainable rule regression tests."""
import json
from app.analysis_service import analyse_events, normalize_timestamp, parse_log


def test_normalize_timestamp_to_utc():
    assert normalize_timestamp("2026-10-18T09:30:00+05:30") == "2026-10-18T04:00:00Z"


def test_parser_extracts_ip_and_failed_login():
    events, gaps = parse_log(b"2026-10-18T09:00:00Z Failed password for admin from 203.0.113.9 port 22", "test.log")
    assert len(events) == 1
    assert events[0]["event_type"] == "authentication_failure"
    assert events[0]["source_ip"] == "203.0.113.9"
    assert gaps == 0


def test_findings_are_scoped_by_source_ip_and_link_source_indices():
    events = [{"event_type": "authentication_failure", "source_ip": "203.0.113.9", "severity": "high", "timestamp": None} for _ in range(3)]
    events += [{"event_type": "authentication_failure", "source_ip": "198.51.100.8", "severity": "high", "timestamp": None}]
    findings = analyse_events(events, threshold=3)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AUTH-001"
    assert findings[0]["event_count"] == 3
    assert findings[0]["event_ids"] == [0, 1, 2]
    assert "203.0.113.9" in findings[0]["description"]


def test_no_trigger_does_not_create_fake_finding():
    assert analyse_events([], threshold=3) == []


def test_json_event_and_windows_csv_are_parsed():
    events, gaps = parse_log(json.dumps({"TimeCreated":"2026-10-18T10:00:00Z", "EventID":4625, "ProviderName":"Microsoft-Windows-Security-Auditing", "Message":"Logon failure for admin from 203.0.113.9"}).encode(), "event.json")
    assert events[0]["timestamp"] == "2026-10-18T10:00:00Z"
    assert events[0]["event_type"] == "authentication_failure"
    csv_content = b'"TimeCreated","Id","LevelDisplayName","ProviderName","Message"\n"2026-10-18T10:00:00Z","4625","Information","Security","Logon failure for admin"\n'
    events, gaps = parse_log(csv_content, "windows.csv")
    assert len(events) == 1 and events[0]["timestamp"] == "2026-10-18T10:00:00Z"


def test_http_access_is_structured_and_rule_is_triggered():
    lines = "\n".join(f'203.0.113.9 - - [18/Oct/2026:10:00:0{i} +0000] "GET /missing{i} HTTP/1.1" 404 12' for i in range(3))
    events, gaps = parse_log(lines.encode(), "access.log")
    assert all(e["event_type"] == "http_access" for e in events)
    findings = analyse_events(events, threshold=3)
    assert any(f["rule_id"] == "WEB-001" for f in findings)


def test_included_web_sample_triggers_http_rule():
    from pathlib import Path
    sample = Path(__file__).parents[1] / "sample_logs" / "web_access_sample.log"
    events, gaps = parse_log(sample.read_bytes(), sample.name)
    assert len(events) == 7
    findings = analyse_events(events, threshold=3)
    assert any(f["rule_id"] == "WEB-001" and f["event_count"] == 3 for f in findings)


def test_failure_then_success_same_source_is_correlated():
    events = [
        {"event_type":"authentication_failure", "source_ip":"203.0.113.9", "severity":"high", "timestamp":"2026-10-18T09:00:00Z"},
        {"event_type":"authentication_failure", "source_ip":"203.0.113.9", "severity":"high", "timestamp":"2026-10-18T09:01:00Z"},
        {"event_type":"authentication_failure", "source_ip":"203.0.113.9", "severity":"high", "timestamp":"2026-10-18T09:02:00Z"},
        {"event_type":"authentication_success", "source_ip":"203.0.113.9", "severity":"info", "timestamp":"2026-10-18T09:05:00Z"},
    ]
    findings = analyse_events(events, threshold=3)
    correlated = next(f for f in findings if f["rule_id"] == "AUTH-002")
    assert correlated["event_count"] == 4
    assert correlated["event_ids"] == [0, 1, 2, 3]


def test_common_windows_event_viewer_timestamp_is_supported():
    assert normalize_timestamp("10/18/2026 10:15:30 AM") == "2026-10-18T10:15:30Z"


def test_malformed_json_lines_are_counted_as_gaps():
    events, gaps = parse_log(b'{"timestamp":"2026-10-18T10:00:00Z","message":"service started"}\nnot-json\n', "broken.json")
    assert len(events) == 1
    assert gaps == 1


def test_unknown_source_failures_are_not_mislabelled_as_high_ip_finding():
    events = [{"event_type":"authentication_failure", "source_ip":None, "severity":"high", "timestamp":None} for _ in range(5)]
    assert analyse_events(events, threshold=3) == []


def test_windows_csv_date_and_time_column_is_recognized():
    content = b'Date and Time,Source,Event ID,Level,Message\n"10/18/2026 10:15:30 AM",Security,4625,Information,"Logon failure for admin from 203.0.113.9"\n'
    events, gaps = parse_log(content, "windows-export.csv")
    assert len(events) == 1
    assert events[0]["timestamp"] == "2026-10-18T10:15:30Z"
    assert events[0]["event_type"] == "authentication_failure"


def test_structured_json_severity_and_event_type_are_used():
    content = json.dumps({"timestamp":"2026-10-18T10:00:00Z", "event_type":"service_restart", "level":"error", "message":"Routine restart completed"}).encode()
    events, gaps = parse_log(content, "structured.json")
    assert events[0]["event_type"] == "service_restart"
    assert events[0]["severity"] == "medium"


def test_authentication_failures_outside_window_do_not_form_high_finding():
    events = [
        {"event_type":"authentication_failure", "source_ip":"203.0.113.9", "severity":"medium", "timestamp":"2026-10-18T09:00:00Z"},
        {"event_type":"authentication_failure", "source_ip":"203.0.113.9", "severity":"medium", "timestamp":"2026-10-18T10:00:00Z"},
        {"event_type":"authentication_failure", "source_ip":"203.0.113.9", "severity":"medium", "timestamp":"2026-10-18T11:00:00Z"},
    ]
    assert not any(f["rule_id"] == "AUTH-001" for f in analyse_events(events, threshold=3))


def test_binary_like_input_is_rejected():
    import pytest
    with pytest.raises(ValueError, match="Binary or unsupported text encoding"):
        parse_log(b"\x00\x01\x02\x03", "sample.log")


def test_success_after_old_failures_does_not_trigger_without_recent_cluster():
    events = [
        {"event_type":"authentication_failure", "source_ip":"203.0.113.9", "severity":"medium", "timestamp":"2026-10-18T08:00:00Z"},
        {"event_type":"authentication_failure", "source_ip":"203.0.113.9", "severity":"medium", "timestamp":"2026-10-18T08:01:00Z"},
        {"event_type":"authentication_failure", "source_ip":"203.0.113.9", "severity":"medium", "timestamp":"2026-10-18T08:02:00Z"},
        {"event_type":"authentication_success", "source_ip":"203.0.113.9", "severity":"info", "timestamp":"2026-10-18T09:00:00Z"},
    ]
    assert not any(f["rule_id"] == "AUTH-002" for f in analyse_events(events, threshold=3))
