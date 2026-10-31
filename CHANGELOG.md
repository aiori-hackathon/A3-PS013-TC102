# Changelog

## 1.3.0 — Investigation workflow and parser reliability

- Authentication-failure findings now use a 15-minute window when timestamps are available. Undated records are called out as lacking temporal confirmation.
- Success-after-failure correlation now requires a threshold-sized recent failure cluster, avoiding correlations to stale historical failures.
- Single authentication failures and isolated HTTP 401/403 responses are not labeled high severity by default; rule findings carry the prioritization.
- Structured JSON `event_type` and severity/level fields are recognized. Windows CSV `Date and Time` is supported alongside common Event Viewer timestamp columns.
- Binary-like input disguised as text logs is rejected with a clear `422` message while preserving the original upload and recording a failed evidence item.
- Original evidence can be downloaded only after an ownership check; downloads are recorded in the audit history.
- Finding cards use a readable full-width layout, timeline overflow is contained, and in-app search has working previous/next pagination.
- CSV exports neutralize formula-like values across event type/severity and other untrusted text fields.
- PDF reports limit excessively long linked-event ID paragraphs while preserving the complete mapping in structured exports.
- Added parser edge-case, correlation-window, original-download authorization, binary-upload and CSV-safety tests.

## 1.2.0 — Submission baseline

- Added evidence hashing, case management, event search, consolidated report packages and baseline regression tests.
