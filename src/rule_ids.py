import logging
import time
from collections import defaultdict, deque

from scapy.all import IP, TCP, Packet, sniff
from scapy.packet import Raw

from src.alert_store import alert_store

logger = logging.getLogger(__name__)

DOSING_PORT = 502
DOSING_FILTER = f"tcp port {DOSING_PORT}"

DOSING_IP = "10.10.0.12"

AUTHORIZED_WRITE_SOURCES = {"10.10.0.20"}
# Hosts allowed to talk to the dosing PLC at all (reads included).
KNOWN_SOURCES = {"10.10.0.20"}

# Recon detection: too many reads from one unknown source in a short window,
# or a sweep across many distinct register addresses.
RECON_WINDOW_SECONDS = 10.0
RECON_READ_THRESHOLD = 20
RECON_DISTINCT_ADDR_THRESHOLD = 8

READ_FUNCTION_CODES = {0x03}
WRITE_FUNCTION_CODES = {0x06, 0x10}
KNOWN_FUNCTION_CODES = READ_FUNCTION_CODES | WRITE_FUNCTION_CODES

MBAP_HEADER_LEN = 7

# Dosing PLC writable registers and their allowed raw values (see
# plant-spec/register-map.md). Registers 0-1 are read-only sensors.
# The pH setpoint bounds (6.00-9.00) are a safe operating assumption.
WRITABLE_REGISTER_RANGES: dict[int, tuple[int, int]] = {
    2: (0, 100),  # pump_speed (%)
    3: (600, 900),  # ph_setpoint (x100)
    4: (0, 1),  # pump_state
}


def parse_modbus_function_code(payload: bytes) -> int | None:
    """Extract the Modbus function code from a raw Modbus/TCP ADU, or None if
    the payload is too short to contain one.
    """
    if len(payload) < MBAP_HEADER_LEN + 1:
        return None
    return payload[MBAP_HEADER_LEN]


_seen_unknown_sources: set[str] = set()
_read_history: dict[str, deque] = defaultdict(deque)
_recon_alerted: set[str] = set()


def reset_state() -> None:
    _seen_unknown_sources.clear()
    _read_history.clear()
    _recon_alerted.clear()


def parse_modbus_start_address(payload: bytes) -> int | None:
    """Starting address of a read/write request, or None if too short."""
    if len(payload) < MBAP_HEADER_LEN + 3:
        return None
    return int.from_bytes(payload[MBAP_HEADER_LEN + 1 : MBAP_HEADER_LEN + 3], "big")


def _check_unknown_source(src_ip: str, function_code: int) -> None:
    if src_ip in KNOWN_SOURCES or src_ip in _seen_unknown_sources:
        return
    _seen_unknown_sources.add(src_ip)
    alert_store.add(
        source="rule_ids",
        severity="warning",
        message=f"traffic from unknown source {src_ip} to dosing PLC (function code 0x{function_code:02x})",
        src_ip=src_ip,
        function_code=function_code,
    )


def _check_recon(src_ip: str, function_code: int, address: int | None, now: float) -> None:
    if src_ip in KNOWN_SOURCES or function_code not in READ_FUNCTION_CODES:
        return
    history = _read_history[src_ip]
    history.append((now, address))
    while history and now - history[0][0] > RECON_WINDOW_SECONDS:
        history.popleft()
    distinct = {addr for _, addr in history if addr is not None}
    if src_ip in _recon_alerted:
        return
    if len(history) >= RECON_READ_THRESHOLD or len(distinct) >= RECON_DISTINCT_ADDR_THRESHOLD:
        _recon_alerted.add(src_ip)
        alert_store.add(
            source="rule_ids",
            severity="critical",
            message=f"possible reconnaissance from {src_ip}: {len(history)} reads, "
            f"{len(distinct)} distinct addresses in {RECON_WINDOW_SECONDS:.0f}s",
            src_ip=src_ip,
            reads=len(history),
            distinct_addresses=len(distinct),
        )


def parse_write_values(function_code: int, payload: bytes) -> list[tuple[int, int]]:
    """Return (address, raw_value) pairs for a write request; [] if malformed."""
    body = payload[MBAP_HEADER_LEN + 1 :]
    if function_code == 0x06:
        if len(body) < 4:
            return []
        return [(int.from_bytes(body[0:2], "big"), int.from_bytes(body[2:4], "big"))]
    if function_code == 0x10:
        if len(body) < 5:
            return []
        start = int.from_bytes(body[0:2], "big")
        qty = int.from_bytes(body[2:4], "big")
        data = body[5:]
        if len(data) < qty * 2:
            return []
        return [(start + i, int.from_bytes(data[2 * i : 2 * i + 2], "big")) for i in range(qty)]
    return []


def _check_write_values(src_ip: str, function_code: int, payload: bytes) -> None:
    for address, value in parse_write_values(function_code, payload):
        bounds = WRITABLE_REGISTER_RANGES.get(address)
        if bounds is None:
            reason = f"write to non-writable register {address}"
        elif not bounds[0] <= value <= bounds[1]:
            reason = f"out-of-range value {value} for register {address} (allowed {bounds[0]}-{bounds[1]})"
        else:
            continue
        alert_store.add(
            source="rule_ids",
            severity="critical",
            message=f"{reason} from {src_ip}",
            src_ip=src_ip,
            function_code=function_code,
            address=address,
            value=value,
        )


def inspect_packet(packet: Packet, now: float | None = None) -> None:
    if not packet.haslayer(IP) or not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return

    # Only inspect requests to the dosing PLC; PLC responses (sport 502) would
    # otherwise look like writes from an unauthorized source.
    if packet[TCP].dport != DOSING_PORT:
        return

    src_ip = packet[IP].src
    payload = bytes(packet[Raw].load)
    function_code = parse_modbus_function_code(payload)

    if function_code is None:
        return

    _check_unknown_source(src_ip, function_code)
    _check_recon(
        src_ip, function_code, parse_modbus_start_address(payload), now if now is not None else time.time()
    )

    if function_code not in KNOWN_FUNCTION_CODES:
        alert_store.add(
            source="rule_ids",
            severity="warning",
            message=f"unexpected Modbus function code 0x{function_code:02x} from {src_ip}",
            src_ip=src_ip,
            function_code=function_code,
        )
        return

    if function_code in WRITE_FUNCTION_CODES:
        _check_write_values(src_ip, function_code, payload)

    if function_code in WRITE_FUNCTION_CODES and src_ip not in AUTHORIZED_WRITE_SOURCES:
        alert_store.add(
            source="rule_ids",
            severity="critical",
            message=f"unauthorized write (function code 0x{function_code:02x}) from {src_ip}",
            src_ip=src_ip,
            function_code=function_code,
        )


def start_sniffing() -> None:
    logger.info("starting Modbus traffic sniffing on filter '%s'", DOSING_FILTER)
    sniff(filter=DOSING_FILTER, prn=inspect_packet, store=False)
