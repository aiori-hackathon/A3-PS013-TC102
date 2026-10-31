# Project Report Draft — TraceForge

> Replace the institution/team/guide placeholders and add only screenshots and observations you actually collect during your own run. Do not present synthetic sample results as a real incident.

## Title

**TraceForge: Digital Evidence and Incident Investigation Workspace**  
Project: AIORI-3 · PS-013

## Abstract

TraceForge is a local-first web application for organizing authorized log evidence and supporting an explainable first-pass investigation workflow. It provides account-scoped evidence intake, investigation cases, SHA-256 intake references and verification, parsing for selected text/CSV/JSON log formats, chronological event views, deterministic detection rules, and report generation in PDF, JSON and CSV formats. Each finding includes a rule identifier, rationale, linked persisted event IDs, severity and recommended review actions. The system is intended as an educational triage aid; it does not assert that a rule match proves compromise and does not replace a complete forensic acquisition and chain-of-custody process.

## 1. Introduction

Incident investigation commonly requires analysts to organize multiple log files, compare timestamps, identify recurring patterns and communicate observations in a reviewable format. Manual handling can make it difficult to track which events support a finding and whether the file being reviewed still matches the bytes first received. TraceForge brings these tasks into a single case-oriented workspace while keeping its detection logic transparent.

## 2. Problem statement

A student or analyst needs a practical way to upload authorized log evidence, retain file-integrity references, structure supported log records, identify selected suspicious patterns, trace findings back to source events and produce consistent reports without relying on opaque predictions or manually assembled summaries.

## 3. Objectives

- Organize multiple evidence files under investigation cases.
- Restrict evidence and report access to the owning account.
- Calculate and verify SHA-256 hashes for stored evidence.
- Parse supported log formats and normalize recognized timestamps to UTC.
- Identify selected patterns using deterministic, explainable rules.
- Link each finding to the persisted events that triggered it.
- Generate narrative PDF, structured JSON and separate event/finding/evidence CSV exports.
- Preserve report history and meaningful investigation history.
- Test key parser, ownership, duplicate-upload, integrity and reporting behaviors.

## 4. Scope and limitations

**Included:** local account-based workflow, cases, text/CSV/JSON parsing, UTC timeline, selected authentication/web/system rules, integrity comparison, report generation, local SQLite/file storage and automated regression tests.

**Not included:** native `.evtx` parsing, live endpoint monitoring, remote collection agents, malware scanning, AI-based attack predictions, cloud integrations, enterprise multi-tenancy or a certified chain-of-custody system.

## 5. Technology stack

- Python, FastAPI and Uvicorn for the application/API.
- SQLAlchemy and SQLite for relational records.
- HTML, CSS and vanilla JavaScript for the UI.
- PBKDF2-HMAC-SHA256 password hashing and signed JWT bearer tokens.
- ReportLab for multi-page PDF generation; Python CSV/JSON libraries for structured exports.
- Pytest and FastAPI TestClient for automated regression tests.

## 6. Architecture and workflow

Refer to `ARCHITECTURE.md` for the component diagram, data-flow diagram and ER model. The main processing stages are authentication, case ownership check, upload validation, SHA-256 intake hashing, parsing, event persistence, rule evaluation, event-linked findings, and optional report generation.

## 7. Detection logic

| Rule ID | Pattern | Interpretation |
|---|---|---|
| AUTH-001 | Repeated authentication-failure-like events from the same source | Review for mistyped credentials, misconfiguration or suspicious activity. |
| AUTH-002 | A success-like event from the same source within 15 minutes after a repeated-failure cluster | Correlate the events and validate the login with the system/account owner. |
| WEB-001 | Repeated HTTP 401/403/404 responses from one source | Review paths and surrounding server context; may be routine or scanning. |
| SYS-001 | Multiple lines matching common warning/error phrases | Inspect original messages; keyword rules can produce false positives. |

The configured threshold applies to future uploads. Rules operate only on the parser's recognized fields and phrases.

## 8. Data integrity and access control

The uploaded bytes are stored separately from derived event/finding rows. The application records SHA-256 at intake and compares it during verification. Owner checks scope evidence, investigation and report reads/downloads. The hash comparison does not prove that a source file was authentic when acquired or that acquisition followed a full forensic chain of custody.

## 9. Testing and evaluation

The automated regression suite covers password hashing and token helpers, timestamp normalization, text/CSV/JSON parsing, rule thresholds/source grouping, linked event IDs, HTTP and authentication patterns, user ownership, duplicate uploads, hash verification, saved report downloads, and a simulated processing-failure path. Record the exact output of `python -m pytest -q` when running the submitted version on the demo machine. Do not claim tests not actually run.

## 10. Results and screenshots

Insert screenshots captured from your own local run:

1. Registration/login screen.
2. Empty and populated dashboard.
3. Case creation and evidence upload.
4. Evidence hash and linked finding detail.
5. Event timeline.
6. PDF cover and findings/timeline pages.
7. JSON and CSV exports/report history.
8. Settings and activity history.

For each screenshot, state the synthetic sample file used and what behavior it demonstrates.

## 11. Conclusion

TraceForge provides a practical, explainable workflow for selected log-evidence investigations and repeatable reporting. Its strongest design choices are source-event linkage, explicit parsing gaps, deterministic rules and clear limitations. Broader forensic coverage and production deployment require additional validation, acquisition controls, operational security and independent review.

## 12. Future work

- Native Windows EVTX parsing with tested event mappings.
- Versioned migration framework and automated backup/restore validation.
- More log-format fixtures and parser fuzz tests.
- Evidence collection metadata and a more complete chain-of-custody workflow.
- Deployment hardening and independent security testing.


## Search and export usability improvements

The workspace includes authenticated structured-event search and a consolidated ZIP export. The ZIP contains a readable PDF plus JSON/CSV datasets and a manifest of package-file hashes. The manifest is not signed and does not replace chain-of-custody documentation. Current package generation is evidence-record scoped; aggregating multiple evidence files into a case-wide report remains future work.
