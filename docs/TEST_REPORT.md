# VulnX verification report

Date: 23 October 2026 (Asia/Kolkata). Environment: Apple Silicon macOS, Python 3.14, Node 24, ZAP 2.17.0, SSLyze 6.3.1, installed Nmap. Tested scope: single-user local application and controlled loopback lab.

## Automated checks

32 unit tests passed. Production frontend build passed. Coverage includes input validation, loopback scope, DNS error handling, CSRF/origin guards, persistence, restart recovery, real PDF document generation, CVE candidate semantics, deduplication, retest state transitions and data reset protections.

## Actual integration run

No mocked runtime data was used. All five scanner profiles completed through the app API on the final run.

| Check | Observed outcome |
|---|---|
| Email DNS | 3 findings: permissive SPF, monitoring DMARC, revoked DKIM selector |
| HTTP headers | 2 missing-header findings |
| Nmap | Service inventory returned; 0 fabricated vulnerabilities |
| TLS | 5 subchecks completed; 1 untrusted-certificate finding |
| ZAP active lab | 18 alert occurrences, including reflected XSS and SQL injection |
| Corrected email retest | 2 configuration fixes verified; revoked DKIM remains |
| Corrected HTTP retest | 2 configuration fixes verified; 0 remaining header findings |
| NVD | Actual CVE-2021-44228 reference returned (24-hour cache allowed) |
| PDF / JSON export | Both downloaded; PDF signature and JSON assessment identity verified |

ZAP counts vary with crawl coverage and timing. Findings and CVE candidates are not independently confirmed exploitability. The final integration script is scripts/verify_local.py.

## Issue discovered and resolved

An initial TLS run returned a genuine partial result with a TLS 1.0 subcheck error from SSLyze. The app preserved that error rather than inventing success. Reduced-concurrency mode was enabled using SSLyze's documented option. A focused TLS run and the subsequent full integration both completed all TLS checks. This is observed improvement, not a guarantee against future network/tool failures.

## Data clearing and UI

Reset requires the exact phrase DELETE ALL DATA and the existing session/CSRF checks. Unit tests verify wrong confirmation, active worker and queued-row rejection, data/evidence deletion, tool preservation, restart persistence and repeated empty resets. A live API request was rejected while an assessment was active. Browser checks confirmed the reset button disabled without confirmation and enabled with the exact phrase. Settings now includes usage instructions.

Cleanup verification: PASS. The authorized reset removed all stored workspace records. API and direct database checks confirmed zero assets, scans, findings, occurrences and audit rows. Generated validation evidence and NVD cache were removed. The installed ZAP tool remains available.

## Completion boundaries

This report verifies the documented local application, not every originally proposed expansion. Arbitrary external active scans, authenticated scanning, privileged OS fingerprinting, UDP, full recursive email standards validation, multi-user accounts/roles and optional AI remain unimplemented. Active ZAP is lab-only. Public websites support header/TLS checks. Network inventory is bounded. No public deployment was performed.

The verification report contains aggregate test outcomes only. Raw historical targets and evidence are not included. App data deletion cannot erase separately downloaded reports, backups or filesystem snapshots.
