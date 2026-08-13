# AntiFine Compliance Report

**Generated:** 2026-08-13 21:10:26 UTC  
**Source database:** `antifine.db`  
**Total findings:** 3  
**Targets covered:** 1

---

## Summary

| Severity | Findings |
| :--- | ---: |
| 🟠 HIGH | 1 |
| 🟡 MEDIUM | 1 |
| 🔵 LOW | 1 |
| **Total** | **3** |

---

## Findings by Severity

### 🟠 HIGH (1)

| Target | Finding | Status | Detected | Recommended Remediation |
| :--- | :--- | :--- | :--- | :--- |
| 1 | SSRF | OPEN | 2026-08-13 21:10:20 | Review whether this service must listen on an external interface. Bind it to localhost, restrict it at the firewall, or migrate to an encrypted equivalent. |

### 🟡 MEDIUM (1)

| Target | Finding | Status | Detected | Recommended Remediation |
| :--- | :--- | :--- | :--- | :--- |
| 1 | Misconfiguration | OPEN | 2026-08-13 21:10:20 | Review whether this service must listen on an external interface. Bind it to localhost, restrict it at the firewall, or migrate to an encrypted equivalent. |

### 🔵 LOW (1)

| Target | Finding | Status | Detected | Recommended Remediation |
| :--- | :--- | :--- | :--- | :--- |
| 1 | Info Disclosure | OPEN | 2026-08-13 21:10:20 | Review whether this service must listen on an external interface. Bind it to localhost, restrict it at the firewall, or migrate to an encrypted equivalent. |

---

## Notes

- Severities reflect the exposure observed at scan time. Services bound only to loopback are reported one level lower than the same service bound to an external interface.
- This report covers findings recorded in the audit database. It is not a substitute for an authenticated configuration review.
