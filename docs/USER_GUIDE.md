# VulnX user guide

## Open the installed application

In Terminal, go to your project directory:

```sh
cd /Users/channaaa/Documents/Codex/2026-10-22/new-chat/vulnx
.venv/bin/python scripts/start_local.py --lab
```

Open http://127.0.0.1:8787/ and keep Terminal open. Ctrl+C stops the processes started by this command. If ports are already occupied, use the existing app or stop its original terminal first. Omit `--lab` when you do not need the demonstration lab. After updating source, run `npm run build` and restart.

## First demonstration

1. In Settings, click **Check installed tools**. An installed tool is not proof that a target is reachable.
2. In **Add target**, choose the correct type and confirm authorization. For the local lab, add the entries below.
3. In Settings choose **Vulnerable mode** to prepare the demonstration.
4. Choose **New assessment**, select the profile and compatible target, then start. The queue runs one job at a time. Active ZAP can take up to six minutes. Use the assessment dialog to cancel.
5. In **Findings**, inspect severity, confidence and actual evidence. Read the coverage limitations. No findings does not prove security; partial, failed and cancelled scans cannot give a clean result.
6. In **Remediation**, track work using review states and notes. Accepted risk and false positive decisions require a reason.
7. In Settings choose **Apply lab corrections**. Rerun the email and website-header profiles. Comparable successful configuration checks can verify the SPF, DMARC, CSP and nosniff repairs. The lab's revoked DKIM selector and self-signed certificate remain intentional observations.
8. In **Reports**, download PDF or JSON before deleting data. For NVD intelligence, enter a CVE such as CVE-2021-44228 in Settings. A CVE reference or product candidate does not prove the asset is exploitable.

| Target | Asset type | Profile / extra input |
|---|---|---|
| mail.vulnx.test | Email domain | Email configuration; selector `test` |
| http://127.0.0.1:18080/ | Website | Website headers or ZAP active lab |
| https://127.0.0.1:18443/ | Website | TLS configuration |
| 127.0.0.1 | Network | Network inventory; ports `18080,18443` |

## Clear data whenever needed

Finish or cancel all assessments. Open **Settings → Clear workspace data**. Export anything you need, type **DELETE ALL DATA**, then click **Permanently clear all data**.

This deletes assets, scan history, findings, review notes, occurrences, audit history, cached NVD responses and application-generated validation evidence. The operation is irreversible in the app. Installed tools, code, lab configuration and certificates remain. PDFs/JSON downloaded elsewhere, copies and system backups are outside the app's deletion scope. This is application data removal, not a guarantee of forensic erasure from SSDs or backups.

The server rejects reset requests while a worker is active, even if the browser is stale. On success, overview counts return to zero.

## Supported scope

Use only owned or explicitly authorized targets. Public websites can use single-endpoint header and TLS checks. Active ZAP is currently restricted to the built-in lab. Network inventory supports up to 16 IPv4 addresses and 32 chosen TCP ports, with service/version fingerprints. OS fingerprinting, UDP, authenticated website scans, multi-user accounts and optional AI are not implemented. Email analysis checks DNS configuration, not cryptographic message signatures or full recursive SPF compliance.

This is a local single-user capstone application, not a public multi-user security service. Keep its loopback binding. NVD requires internet access and can be rate limited; scanner results remain separate from unavailable intelligence.

## Troubleshooting

- **Dependency missing:** follow README installation instructions; Nmap and Java are separate prerequisites.
- **Lab connection refused:** start with `--lab`; confirm the documented ports are free.
- **TLS partial:** inspect the failed subcheck; retry once after checking the endpoint. Do not interpret it as safe.
- **NVD unavailable:** retry later. Cached entries last 24 hours and are removed by Clear data.
- **App unavailable after closing Terminal:** restart using the command above.

## Analyze an individual email offline

Choose **Email Analyzer** from the sidebar. Upload/drop `.eml` or `.txt`, or paste the full raw message with headers and body; select **Analyze Email**. Review message identity, reported SPF/DKIM/DMARC claims, delivery headers, URLs, attachment hashes and inert source. Select **Clear** to remove the message and results. Navigation away also clears this page's memory. No email is sent to the backend or saved to scan history.

This does not verify DKIM signatures, validate authentication header provenance, run antivirus or check link reputation. A reported pass is a header claim, not a fresh security verification. For actual domain DNS records, continue using **Scans → Email configuration**.

## White-and-purple interface and email result tabs

The Email Analyzer shows one section at a time: Overview, Headers, Links, Attachments, Reputation and Raw Email. Use the tabs or Left/Right arrow keys; Home/End select the first/last tab. **Edit email** returns to the original input; **Clear** discards input and results. Attachment hashes are available in Attachments. Reputation explicitly states that it has not been checked; no invented score is displayed.

If 8787 is occupied, run `.venv/bin/python scripts/start_local.py --port 8788` and open http://127.0.0.1:8788/. Add `--lab` if you need the training lab. The launcher checks port availability before starting processes and prints the selected URL.
