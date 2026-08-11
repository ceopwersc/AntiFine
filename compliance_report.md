# AntiFine Compliance Report

**Generated:** 2026-08-11 09:15:32 UTC  
**Source database:** `antifine.db`  
**Total findings:** 19  
**Targets covered:** 1

---

## Summary

| Severity | Findings |
| :--- | ---: |
| 🟠 HIGH | 17 |
| 🟡 MEDIUM | 2 |
| **Total** | **19** |

---

## Findings by Severity

### 🟠 HIGH (17)

| Target | Finding | Status | Detected | Recommended Remediation |
| :--- | :--- | :--- | :--- | :--- |
| 1 | Insecure Service: NetBIOS Name Service (137/udp) | OPEN | 2026-08-11 09:15:23 | Disable NetBIOS over TCP/IP on all external interfaces. |
| 1 | Insecure Service: NetBIOS Name Service (137/udp) | OPEN | 2026-08-11 09:15:23 | Disable NetBIOS over TCP/IP on all external interfaces. |
| 1 | Insecure Service: NetBIOS Name Service (137/udp) | OPEN | 2026-08-11 09:15:23 | Disable NetBIOS over TCP/IP on all external interfaces. |
| 1 | Insecure Service: NetBIOS Name Service (137/udp) | OPEN | 2026-08-11 09:15:23 | Disable NetBIOS over TCP/IP on all external interfaces. |
| 1 | Insecure Service: NetBIOS Name Service (137/udp) | OPEN | 2026-08-11 09:15:23 | Disable NetBIOS over TCP/IP on all external interfaces. |
| 1 | Insecure Service: NetBIOS Datagram (138/udp) | OPEN | 2026-08-11 09:15:23 | Disable NetBIOS over TCP/IP on all external interfaces. |
| 1 | Insecure Service: NetBIOS Datagram (138/udp) | OPEN | 2026-08-11 09:15:23 | Disable NetBIOS over TCP/IP on all external interfaces. |
| 1 | Insecure Service: NetBIOS Datagram (138/udp) | OPEN | 2026-08-11 09:15:23 | Disable NetBIOS over TCP/IP on all external interfaces. |
| 1 | Insecure Service: NetBIOS Datagram (138/udp) | OPEN | 2026-08-11 09:15:23 | Disable NetBIOS over TCP/IP on all external interfaces. |
| 1 | Insecure Service: NetBIOS Datagram (138/udp) | OPEN | 2026-08-11 09:15:23 | Disable NetBIOS over TCP/IP on all external interfaces. |
| 1 | Insecure Service: NetBIOS Session (139/tcp) | OPEN | 2026-08-11 09:15:23 | Disable NetBIOS session service; use SMB over 445 with signing, or restrict it to trusted networks. |
| 1 | Insecure Service: NetBIOS Session (139/tcp) | OPEN | 2026-08-11 09:15:23 | Disable NetBIOS session service; use SMB over 445 with signing, or restrict it to trusted networks. |
| 1 | Insecure Service: NetBIOS Session (139/tcp) | OPEN | 2026-08-11 09:15:23 | Disable NetBIOS session service; use SMB over 445 with signing, or restrict it to trusted networks. |
| 1 | Insecure Service: NetBIOS Session (139/tcp) | OPEN | 2026-08-11 09:15:23 | Disable NetBIOS session service; use SMB over 445 with signing, or restrict it to trusted networks. |
| 1 | Insecure Service: NetBIOS Session (139/tcp) | OPEN | 2026-08-11 09:15:23 | Disable NetBIOS session service; use SMB over 445 with signing, or restrict it to trusted networks. |
| 1 | Insecure Service: SMB (445/tcp) | OPEN | 2026-08-11 09:15:23 | Restrict SMB to trusted networks, enforce signing, and disable SMBv1 if still enabled. |
| 1 | Insecure Service: SMB (445/tcp) | OPEN | 2026-08-11 09:15:23 | Restrict SMB to trusted networks, enforce signing, and disable SMBv1 if still enabled. |

### 🟡 MEDIUM (2)

| Target | Finding | Status | Detected | Recommended Remediation |
| :--- | :--- | :--- | :--- | :--- |
| 1 | Insecure Service: MSRPC (135/tcp) | OPEN | 2026-08-11 09:15:23 | Block the RPC endpoint mapper at the host firewall; expose it only to trusted management networks. |
| 1 | Insecure Service: MSRPC (135/tcp) | OPEN | 2026-08-11 09:15:23 | Block the RPC endpoint mapper at the host firewall; expose it only to trusted management networks. |

---

## Notes

- Severities reflect the exposure observed at scan time. Services bound only to loopback are reported one level lower than the same service bound to an external interface.
- This report covers findings recorded in the audit database. It is not a substitute for an authenticated configuration review.
