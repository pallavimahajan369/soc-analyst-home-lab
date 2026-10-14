# Incident Report 001 — Suspicious Web Activity

## 1. Summary
A local SOC training exercise detected repeated failed login responses and a traversal-like URL in synthetic web access logs.

## 2. Environment
- Data source: Synthetic Apache-style access logs
- Detection engine: Python
- Scope: Local training environment
- Date: 14 October 2026

## 3. Findings

### Finding A — Repeated Failed Logins
- Source IP: `192.168.1.20`
- Observed events: 3 HTTP 401 responses on `/login`
- Severity: Medium
- Detection rule: `REPEATED_FAILED_LOGINS`

**Analysis:** Repeated authentication failures may indicate password guessing or an incorrect-password scenario. Authentication logs are needed to determine the cause.

### Finding B — Traversal-Like Request
- Source IP: `192.168.1.40`
- Requested path: `/../../etc/passwd`
- HTTP response: 400
- Severity: High indicator; not a confirmed vulnerability
- Detection rule: `PATH_TRAVERSAL_INDICATOR`

**Analysis:** The request contains path traversal patterns. A 400 response alone does not establish whether the server was vulnerable or whether data was accessed.

## 4. Recommended Investigation
1. Correlate requests with application and authentication logs.
2. Check timestamps and surrounding events.
3. Verify whether the requests reached the application.
4. Review server-side path validation and access controls.
5. Preserve relevant logs and document the investigation.

## 5. Conclusion
The analyzer detected two suspicious patterns in synthetic training data. No real compromise was established.

## 6. Limitations
The detector uses simple string matching and a fixed threshold. It does not establish malicious intent, correlate multiple log sources, or detect every attack pattern.
