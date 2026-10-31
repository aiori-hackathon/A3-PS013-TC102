# Security and Regression Test Matrix

The automated tests in `tests/` cover the following behaviors. The suite is regression evidence for the educational application, not a security certification.

| Area | Test coverage | Expected behavior |
|---|---|---|
| Passwords | Salted hash, correct/wrong password, malformed hash | Plaintext is not stored; malformed hashes fail closed. |
| Tokens | Valid round-trip and invalid token | Valid user ID decodes; invalid token is rejected. |
| Parser | UTC conversion, text authentication log, Windows CSV including `Date and Time`, structured JSON, JSON Lines, web access sample, binary-like input | Recognized records are structured; decode/parse gaps are counted; unsupported binary-like inputs are rejected; timestamps are not invented. |
| Detection rules | Threshold and source-IP grouping; 15-minute authentication cluster; HTTP pattern; failure followed by success | Time-window rules require a recent cluster when timestamps exist; undated records are described as lacking temporal confirmation. Findings retain linked source event IDs. |
| Event linkage | API detail response | Finding links contain actual persisted event IDs. |
| Authorization | Cross-account evidence/report/original-file lookup and download | Other users receive `404` for records they do not own; original-evidence downloads are audited. |
| Duplicate uploads | Same bytes under a different filename | Duplicate is rejected with `409`; counts are not inflated. |
| Integrity | Verify newly uploaded evidence | Current SHA-256 matches the intake reference. |
| Report outputs | PDF, JSON, event CSV, findings CSV, evidence CSV, consolidated ZIP | Files are generated, persisted, downloadable and represented in report history; CSV formula prefixes are neutralized. |
| Failure handling | Simulated parser exception | Partial parsed rows are rolled back; intake record is marked failed and original bytes/hash are retained if intake completed. |
| Frontend syntax | `node --check static/app.js` | JavaScript syntax check passes. |

## Manual checks before a live presentation

- Register two separate accounts; upload evidence as account A and verify account B cannot open it.
- Change the upload limit and threshold, then confirm the new values affect future uploads.
- Tamper with a stored test evidence file in a disposable local copy and confirm hash verification reports a mismatch. Restore or delete that disposable test environment afterward.
- Restart the app and confirm cases, evidence, report history and generated report files remain available.
- Inspect the PDF at multiple page sizes and confirm tables do not overlap or clip on the target machine.

| Search | Query is scoped to authenticated user's completed evidence; validates severity/page bounds; event IDs can be searched | `test_event_search_and_consolidated_package` |
| Consolidated package | ZIP contains PDF, JSON, event/finding/evidence CSVs and manifest; download is owner-protected | `test_event_search_and_consolidated_package` |


## Current automated verification

The maintained suite currently contains 28 tests. Run `python -m pytest -q` to reproduce the result on your machine. JavaScript syntax is checked separately with `node --check static/app.js` when Node.js is available. These checks do not replace browser-based visual review or independent security testing.
