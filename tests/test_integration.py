"""Integration tests for scripts/port_mapper.sh.

Unlike tests/test_baseline.py, nothing here is mocked: the real script runs
against the real host and its output is checked against the formatting
contract documented in the script header. These tests are the regression
guard for the bash/Python boundary -- a change to the script's output shape
that the unit tests cannot see will fail here.

Host state is live: sockets open and close between runs, so assertions cover
structure and invariants, never exact record counts or exact output equality.
"""

from __future__ import annotations

import ipaddress
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from src.scanners.baseline_audit import (
    PROJECT_ROOT,
    SCRIPT_PATH,
    ScannerError,
    identify_insecure_ports,
    parse_port_records,
    resolve_bash,
    run_port_mapper,
)

pytestmark = pytest.mark.integration

#: The contract: three tab-separated fields, no leading/trailing whitespace.
RECORD_PATTERN = re.compile(r"^([a-z]+)\t(\d+)\t(\S+)$")

VALID_PROTOCOLS = frozenset({"tcp", "udp"})


def _bash_available() -> bool:
    try:
        resolve_bash()
    except ScannerError:
        return False
    return True


requires_bash = pytest.mark.skipif(
    not _bash_available(),
    reason="no usable bash interpreter on this host",
)


@pytest.fixture(scope="module")
def script_output() -> str:
    """Run the real port_mapper.sh once and share its output."""
    try:
        return run_port_mapper(SCRIPT_PATH)
    except ScannerError as exc:
        pytest.skip(f"port_mapper.sh could not run on this host: {exc}")


@pytest.fixture(scope="module")
def record_lines(script_output: str) -> list[str]:
    """Non-comment, non-blank lines from the script output."""
    return [
        line
        for line in script_output.splitlines()
        if line.strip() and not line.startswith("#")
    ]


def _split_endpoint(endpoint: str) -> tuple[str, int] | None:
    """Split a system tool's 'address:port' into (address, port)."""
    if ":" not in endpoint:
        return None
    address, _, port_text = endpoint.rpartition(":")
    if not port_text.isdigit():
        return None
    port = int(port_text)
    if not 1 <= port <= 65535:
        return None
    return (address or "*", port)


def _reference_endpoints() -> set[tuple[str, int, str]] | None:
    """Enumerate listening sockets independently of port_mapper.sh.

    Used to prove the script does not silently drop records. Returns None
    when no reference tool is available, in which case the caller skips.
    """
    records: set[tuple[str, int, str]] = set()

    if os.name == "nt" or platform.system() == "Windows":
        netstat = shutil.which("netstat") or r"C:\Windows\System32\netstat.exe"
        if not Path(netstat).is_file():
            return None
        try:
            result = subprocess.run(
                [netstat, "-ano"], capture_output=True, text=True, timeout=60
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if result.returncode != 0:
            return None

        for line in result.stdout.replace("\r", "").splitlines():
            fields = line.split()
            if len(fields) < 2:
                continue
            proto = fields[0].upper()
            if proto == "TCP":
                if len(fields) < 4 or fields[3] != "LISTENING":
                    continue
            elif proto != "UDP":
                continue
            split = _split_endpoint(fields[1])
            if split is None:
                continue
            address, port = split
            records.add((proto.lower(), port, address))
        return records

    tool = shutil.which("ss")
    args = [tool, "-tuln"] if tool else None
    field_index = 4
    if args is None:
        tool = shutil.which("netstat")
        if tool is None:
            return None
        args = [tool, "-tuln"]
        field_index = 3

    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None

    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) <= field_index:
            continue
        proto = fields[0].lower().rstrip("6")
        if proto not in VALID_PROTOCOLS:
            continue
        split = _split_endpoint(fields[field_index])
        if split is None:
            continue
        address, port = split
        records.add((proto, port, address))
    return records


# --------------------------------------------------------------------------
# Script presence and execution
# --------------------------------------------------------------------------

def test_script_exists_at_expected_path() -> None:
    assert SCRIPT_PATH.is_file(), f"missing script: {SCRIPT_PATH}"
    assert SCRIPT_PATH == PROJECT_ROOT / "scripts" / "port_mapper.sh"


def test_script_has_shebang() -> None:
    first_line = SCRIPT_PATH.read_text(encoding="utf-8").splitlines()[0]
    assert first_line.startswith("#!"), "script must carry a shebang"
    assert "bash" in first_line


@requires_bash
def test_script_exits_zero(script_output: str) -> None:
    # run_port_mapper raises ScannerError on any non-zero exit, so reaching
    # this point with output in hand proves a clean exit.
    assert isinstance(script_output, str)


@requires_bash
def test_script_emits_at_least_one_record(record_lines: list[str]) -> None:
    assert record_lines, (
        "no listening sockets reported; a live host is expected to have at "
        "least one, so this suggests the enumeration path is broken"
    )


# --------------------------------------------------------------------------
# The formatting contract
# --------------------------------------------------------------------------

@requires_bash
def test_output_begins_with_header_comment(script_output: str) -> None:
    first_line = script_output.splitlines()[0]
    assert first_line == "#proto\tport\taddress"


@requires_bash
def test_every_record_matches_the_three_field_contract(
    record_lines: list[str],
) -> None:
    for line in record_lines:
        assert RECORD_PATTERN.match(line), f"record violates contract: {line!r}"
        assert line.count("\t") == 2, f"expected exactly 2 tabs: {line!r}"
        assert line == line.strip(), f"record has stray whitespace: {line!r}"


@requires_bash
def test_protocol_field_is_tcp_or_udp(record_lines: list[str]) -> None:
    for line in record_lines:
        proto = line.split("\t")[0]
        assert proto in VALID_PROTOCOLS, f"unexpected protocol {proto!r}"
        assert proto == proto.lower(), "protocol must be lowercase"


@requires_bash
def test_port_field_is_an_integer_in_range(record_lines: list[str]) -> None:
    for line in record_lines:
        port_text = line.split("\t")[1]
        assert port_text.isdigit(), f"port not numeric: {port_text!r}"
        assert not (len(port_text) > 1 and port_text.startswith("0")), (
            f"port must not be zero-padded: {port_text!r}"
        )
        assert 1 <= int(port_text) <= 65535, f"port out of range: {port_text}"


@requires_bash
def test_address_field_is_a_valid_ip_or_wildcard(record_lines: list[str]) -> None:
    for line in record_lines:
        address = line.split("\t")[2]
        assert address, "address field must not be empty"
        if address == "*":
            continue
        candidate = address[1:-1] if address.startswith("[") else address
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            pytest.fail(f"address is neither an IP nor '*': {address!r}")


@requires_bash
def test_records_are_deduplicated(record_lines: list[str]) -> None:
    assert len(record_lines) == len(set(record_lines)), (
        "duplicate records present; the contract promises de-duplication"
    )


@requires_bash
def test_records_are_sorted_by_protocol_then_numeric_port(
    record_lines: list[str],
) -> None:
    keys = [
        (fields[0], int(fields[1]), fields[2])
        for fields in (line.split("\t") for line in record_lines)
    ]
    assert keys == sorted(keys), "records are not in the documented sort order"


@requires_bash
def test_no_ansi_or_carriage_returns_leak_into_output(script_output: str) -> None:
    assert "\r" not in script_output, (
        "carriage returns present; Windows netstat output must be stripped"
    )
    assert "\x1b" not in script_output, "ANSI escapes must not appear in output"


# --------------------------------------------------------------------------
# The bash/Python boundary -- the regression the unit tests cannot see
# --------------------------------------------------------------------------

@requires_bash
def test_parser_accepts_every_line_the_script_emits(
    script_output: str, record_lines: list[str]
) -> None:
    """The core guard: the parser must not silently discard real output.

    parse_port_records skips malformed rows by design, so a format drift in
    the script would show up as a shortfall here rather than as an error.
    """
    parsed = parse_port_records(script_output)

    assert len(parsed) == len(record_lines), (
        f"parser accepted {len(parsed)} of {len(record_lines)} emitted "
        "records; the script output format and the parser have drifted apart"
    )


@requires_bash
def test_parsed_values_round_trip_to_the_original_lines(
    script_output: str, record_lines: list[str]
) -> None:
    parsed = parse_port_records(script_output)
    rebuilt = {f"{p.proto}\t{p.port}\t{p.address}" for p in parsed}

    assert rebuilt == set(record_lines), (
        "parsed records do not reproduce the emitted lines exactly"
    )


@requires_bash
def test_no_records_lost_against_an_independent_enumeration() -> None:
    """Regression guard: the script must not drop sockets it enumerated.

    A `sort -u` keyed on only (proto, port) previously collapsed services
    bound on several interfaces into a single record, discarding addresses
    and potentially hiding an external bind behind a loopback one.
    """
    reference = _reference_endpoints()
    if reference is None:
        pytest.skip("no independent enumeration tool available on this host")
    if not reference:
        pytest.skip("reference enumeration returned no sockets")

    emitted = {
        (p.proto, p.port, p.address) for p in parse_port_records(run_port_mapper())
    }

    # Sockets churn between the two enumerations, so only require that the
    # script did not drop a whole (proto, port) group that the reference saw.
    reference_groups: dict[tuple[str, int], set[str]] = {}
    for proto, port, address in reference:
        reference_groups.setdefault((proto, port), set()).add(address)

    emitted_groups: dict[tuple[str, int], set[str]] = {}
    for proto, port, address in emitted:
        emitted_groups.setdefault((proto, port), set()).add(address)

    multi_bind = {
        group: addresses
        for group, addresses in reference_groups.items()
        if len(addresses) > 1 and group in emitted_groups
    }
    if not multi_bind:
        pytest.skip("host has no multi-interface binds to verify against")

    for group, addresses in multi_bind.items():
        emitted_count = len(emitted_groups[group])
        assert emitted_count > 1, (
            f"{group[1]}/{group[0]} is bound on {len(addresses)} addresses "
            f"({sorted(addresses)}) but the script emitted only "
            f"{emitted_count}; records are being collapsed"
        )


@requires_bash
def test_multi_interface_binds_keep_distinct_addresses(
    record_lines: list[str],
) -> None:
    """Any (proto, port) seen more than once must carry distinct addresses."""
    groups: dict[tuple[str, str], list[str]] = {}
    for line in record_lines:
        proto, port, address = line.split("\t")
        groups.setdefault((proto, port), []).append(address)

    for (proto, port), addresses in groups.items():
        assert len(addresses) == len(set(addresses)), (
            f"{port}/{proto} repeats an identical address: {addresses}"
        )


# --------------------------------------------------------------------------
# Downstream consumption
# --------------------------------------------------------------------------

@requires_bash
def test_classification_runs_cleanly_on_real_output(script_output: str) -> None:
    findings = identify_insecure_ports(parse_port_records(script_output))

    for finding in findings:
        assert finding.proto in VALID_PROTOCOLS
        assert 1 <= finding.port <= 65535
        assert finding.severity
        assert finding.service
        assert finding.vulnerability_type.startswith("Insecure Service:")


@requires_bash
def test_output_shape_is_stable_across_consecutive_runs() -> None:
    """Two runs must produce the same *shape*.

    Exact equality is not asserted: sockets legitimately open and close
    between invocations on a live host.
    """
    first = run_port_mapper()
    second = run_port_mapper()

    assert first.splitlines()[0] == second.splitlines()[0], "header changed"

    for output in (first, second):
        lines = [
            line
            for line in output.splitlines()
            if line.strip() and not line.startswith("#")
        ]
        assert lines, "a run produced no records"
        for line in lines:
            assert RECORD_PATTERN.match(line), f"unstable format: {line!r}"
