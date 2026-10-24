# AntiFine Compliance Report

**Generated:** 2026-09-12 23:38:38 UTC  
**Source database:** `antifine.db`  
**Total findings:** 1  
**Targets covered:** 1

---

## Summary

| Severity | Findings |
| :--- | ---: |
| ⚫ UNCLASSIFIED | 1 |
| **Total** | **1** |

---

## Findings by Severity

### ⚫ UNCLASSIFIED (1)

| Target | Finding | Status | Detected |
| :--- | :--- | :--- | :--- |
| 1 | Informational: USER root in intermediate build stage (stage:builder) in Dockerfile.multistage_compliant -- acceptable for toolchain/package-installation stages | OPEN | 2026-09-12 23:37:41 |

#### Target 1: Informational: USER root in intermediate build stage (stage:builder) in Dockerfile.multistage_compliant -- acceptable for toolchain/package-installation stages

**Remediation & Hardening**

**Summary:** An unclassified security finding was detected.

**Mitigation:**
1. Review whether this service must listen on an external interface.
2. Bind it to localhost or restrict it at the firewall.
3. Migrate to an encrypted equivalent if applicable.

**Example:**
```text
(No specific code example available)
```

---

---

## Notes

- Severities reflect the exposure observed at scan time. Services bound only to loopback are reported one level lower than the same service bound to an external interface.
- This report covers findings recorded in the audit database. It is not a substitute for an authenticated configuration review.
