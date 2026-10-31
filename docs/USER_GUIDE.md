# TraceForge User Guide

## 1. Create an account

Open `http://127.0.0.1:8000`, select **Create an account**, and register with an email and password of at least eight characters. Use separate accounts to demonstrate record ownership boundaries.

## 2. Create or select a case

Open **Add evidence**. The initial investigation is created for convenience. To create another, enter a case title and select **Create case**. Choose the case in the dropdown before uploading a file. Multiple files can belong to the same case.

## 3. Upload evidence

Use a `.log`, `.txt`, `.csv` or `.json` file you are authorized to examine. Synthetic examples are in `sample_logs/`. The configured maximum upload size is shown on screen. If the exact same bytes already exist in your account, TraceForge rejects the duplicate and names the existing evidence ID.

After intake, the record contains the original filename, file size, SHA-256 upload reference, case ID, processing status, parsed event count, finding count and parsing-gap count. A failed parser run is recorded as failed; if intake completed, the original bytes and hash are retained and partial parsed rows are not treated as complete results.

## 4. Review findings and timeline

Open **Reports** and choose **Review**. Each finding displays its rule ID, severity, explanation, rationale, linked persisted event IDs, event count, time range and recommended review action. The timeline is sorted chronologically, with unknown timestamps kept explicit. The current view displays up to 100 events; the CSV export contains the complete dataset.

Rules currently cover repeated authentication failures by source IP, a successful-login-like event within 15 minutes after repeated failures from the same source, repeated HTTP 401/403/404 responses, and clusters of common warning/error phrases. Rule triggers are review prompts, not proof of malicious activity.

## 5. Verify integrity

Select **Verify hash** in an evidence detail panel. A match means the current stored bytes match the SHA-256 reference recorded at intake. A mismatch or missing file needs investigation. The check is recorded in investigation history and the security audit data.

## 6. Generate reports

- **PDF report** — narrative report with cover, executive summary, scope/method, evidence inventory, hash, processing statistics, linked findings, event timeline, limitations, recommendations and page numbers.
- **JSON** — structured report object containing investigation/evidence metadata, events, findings and limitations.
- **Events CSV** — one row per parsed event.
- **Findings CSV** — severity, rule ID, rationale, recommendation, time range and linked event IDs.
- **Evidence CSV** — file/case metadata, SHA-256 reference, processing counts and upload timestamp.

The **Generated report history** section keeps report entries and download links after you navigate away or restart the app, as long as local runtime files are retained.

## 7. Activity history and settings

**Activity history** focuses on investigation records: cases, evidence processing, integrity checks and generated reports. Routine account/security records are kept separately at the owner-scoped `/api/audit` endpoint. **Settings** lets you change the display name, upload-size limit, failed-login threshold and display timezone. Threshold changes affect future uploads; existing findings are not silently recalculated.

## 8. Demo recommendations

1. Upload `sample_logs/linux_auth_sample.log` and inspect `AUTH-001`.
2. Upload `sample_logs/web_access_sample.log` and inspect `WEB-001`.
3. Upload `sample_logs/windows_event_export_sample.csv` and `sample_logs/json_events_sample.json` to demonstrate supported formats.
4. Verify SHA-256, then generate all five report outputs and show report history.
5. Explain limitations: `.evtx` is not parsed natively, rule matches need human review, and SHA-256 does not establish source authenticity or full chain of custody.


## Search and consolidated export

Open **Reports** and use **Search all processed events** to query structured event messages, IP addresses, usernames, event types, or numeric event IDs. Severity can be filtered. The API supports pagination; the current UI displays the first page of up to 50 matches. Search is limited to the signed-in user's completed evidence.

Open an evidence record to generate a PDF report or a consolidated ZIP package. The package contains `investigation-report.pdf`, `investigation.json`, `events.csv`, `findings.csv`, `evidence-inventory.csv`, and `manifest.json`. The manifest contains SHA-256 digests for package files but is not digitally signed. This package currently covers one evidence record at a time.
