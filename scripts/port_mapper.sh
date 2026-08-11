#!/usr/bin/env bash
#
# port_mapper.sh -- enumerate listening TCP/UDP sockets on the local host.
#
# Defensive auditing only: this reads local socket state via native system
# tools. It performs no network activity against any host.
#
# Output contract (stable, consumed by src/scanners/baseline_audit.py):
#
#   Lines beginning with '#' are comments and must be ignored by parsers.
#   Every other line is a record of exactly three tab-separated fields:
#
#       <proto>\t<port>\t<address>
#
#     proto   -- "tcp" or "udp" (lowercase; v6 variants normalized to base)
#     port    -- decimal port number, 1-65535
#     address -- local bind address as reported by the system tool, or "*"
#
#   Records are sorted by protocol then numeric port, and de-duplicated.
#   An empty result set is valid and exits 0.
#
# Exit codes:
#   0  success (zero or more records emitted)
#   3  no supported enumeration tool found on this system
#   4  the enumeration tool was found but failed to run

set -uo pipefail

readonly E_NO_TOOL=3
readonly E_TOOL_FAILED=4

# Shared awk helpers. Splits an "address:port" endpoint on its final colon so
# that IPv6 forms ([::]:445, :::445) parse the same as IPv4 (0.0.0.0:445).
readonly AWK_LIB='
function emit(proto, endpoint,   n, parts, port, addr) {
    n = split(endpoint, parts, ":")
    if (n < 2) { return }
    port = parts[n]
    if (port !~ /^[0-9]+$/) { return }
    if (port + 0 < 1 || port + 0 > 65535) { return }
    addr = substr(endpoint, 1, length(endpoint) - length(port) - 1)
    if (addr == "" || addr == "*") { addr = "*" }
    proto = tolower(proto)
    sub(/6$/, "", proto)
    printf "%s\t%s\t%s\n", proto, port + 0, addr
}
'

usage() {
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
}

# ss(8) -- preferred on modern Linux. Header row starts with "Netid".
scan_with_ss() {
    ss -tuln 2>/dev/null | awk "${AWK_LIB}"'
        $1 == "tcp" || $1 == "udp" { emit($1, $5) }
    '
}

# netstat(8), GNU/BSD flavour. UDP rows carry no state column.
scan_with_netstat_posix() {
    netstat -tuln 2>/dev/null | awk "${AWK_LIB}"'
        $1 ~ /^(tcp|udp)6?$/ { emit($1, $4) }
    '
}

# netstat.exe -- Windows flavour (MSYS/MinGW/Cygwin shells). Columns are
# Proto / Local Address / Foreign Address / State / PID. TCP rows must be
# filtered to LISTENING; UDP rows have no state and are listening by nature.
scan_with_netstat_windows() {
    netstat -ano 2>/dev/null | tr -d '\r' | awk "${AWK_LIB}"'
        $1 == "TCP" && $4 == "LISTENING" { emit($1, $2) }
        $1 == "UDP"                      { emit($1, $2) }
    '
}

# Returns the name of the scan function appropriate for this host.
select_scanner() {
    if command -v ss >/dev/null 2>&1; then
        printf 'scan_with_ss\n'
        return 0
    fi

    if command -v netstat >/dev/null 2>&1; then
        case "$(uname -s 2>/dev/null || printf 'unknown')" in
            MINGW*|MSYS*|CYGWIN*|Windows*)
                printf 'scan_with_netstat_windows\n' ;;
            *)
                printf 'scan_with_netstat_posix\n' ;;
        esac
        return 0
    fi

    return 1
}

main() {
    if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
        usage
        return 0
    fi

    local scanner
    if ! scanner="$(select_scanner)"; then
        printf '%s: no supported tool (ss, netstat) found\n' "${0##*/}" >&2
        return "${E_NO_TOOL}"
    fi

    local records
    if ! records="$("${scanner}")"; then
        printf '%s: %s failed to enumerate sockets\n' "${0##*/}" "${scanner}" >&2
        return "${E_TOOL_FAILED}"
    fi

    printf '#proto\tport\taddress\n'
    if [ -n "${records}" ]; then
        # The sort key must cover all three fields. `sort -u` de-duplicates on
        # the key alone, so a key of only (proto, port) would collapse a
        # service bound on several interfaces down to a single record and
        # discard the addresses -- which can mask an externally exposed bind
        # behind a loopback one.
        printf '%s\n' "${records}" \
            | sort -u -t"$(printf '\t')" -k1,1 -k2,2n -k3,3
    fi

    return 0
}

main "$@"
