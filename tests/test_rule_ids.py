import pytest
from scapy.all import IP, TCP, Raw

from src.alert_store import alert_store
from src.rule_ids import inspect_packet, parse_modbus_function_code


@pytest.fixture(autouse=True)
def clear_alerts():
    from src import rule_ids

    rule_ids.reset_state()
    alert_store.clear()
    yield
    alert_store.clear()


def make_modbus_packet(src_ip: str, function_code: int, extra: bytes = b"\x00\x00"):
    mbap = b"\x00\x01\x00\x00\x00\x06\x01"  # transaction, protocol, length, unit id
    payload = mbap + bytes([function_code]) + extra
    return IP(src=src_ip, dst="10.10.0.12") / TCP(sport=51000, dport=502) / Raw(load=payload)


def test_parse_modbus_function_code_extracts_correct_byte():
    mbap = b"\x00\x01\x00\x00\x00\x06\x01"
    payload = mbap + bytes([0x06]) + b"\x00\x00"
    assert parse_modbus_function_code(payload) == 0x06


def test_parse_modbus_function_code_returns_none_on_short_payload():
    assert parse_modbus_function_code(b"\x00\x01") is None


def test_authorized_write_does_not_raise_alert():
    packet = make_modbus_packet("10.10.0.20", 0x06)

    inspect_packet(packet)

    assert alert_store.list() == []


def test_unauthorized_write_raises_critical_alert():
    packet = make_modbus_packet("10.10.0.99", 0x06)

    inspect_packet(packet)

    alerts = [a for a in alert_store.list() if a["severity"] == "critical"]
    assert len(alerts) == 1
    assert alerts[0]["details"]["src_ip"] == "10.10.0.99"


def test_unexpected_function_code_raises_warning_alert():
    packet = make_modbus_packet("10.10.0.20", 0x2B)

    inspect_packet(packet)

    alerts = alert_store.list()
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "warning"


def test_known_source_read_does_not_raise_alert():
    packet = make_modbus_packet("10.10.0.20", 0x03)

    inspect_packet(packet)

    assert alert_store.list() == []


def make_read(src_ip: str, address: int):
    mbap = b"\x00\x01\x00\x00\x00\x06\x01"
    payload = mbap + b"\x03" + address.to_bytes(2, "big") + b"\x00\x01"
    return IP(src=src_ip, dst="10.10.0.12") / TCP(sport=51000, dport=502) / Raw(load=payload)


def test_unknown_source_read_alerts_once():
    from src import rule_ids

    rule_ids.reset_state()
    inspect_packet(make_read("10.10.0.99", 0))
    inspect_packet(make_read("10.10.0.99", 0))

    msgs = [a["message"] for a in alert_store.list()]
    assert sum("unknown source" in m for m in msgs) == 1


def test_known_source_reads_do_not_alert():
    from src import rule_ids

    rule_ids.reset_state()
    for addr in range(30):
        inspect_packet(make_read("10.10.0.20", addr))

    assert alert_store.list() == []


def test_register_sweep_triggers_recon_alert():
    from src import rule_ids

    rule_ids.reset_state()
    for addr in range(rule_ids.RECON_DISTINCT_ADDR_THRESHOLD):
        inspect_packet(make_read("10.10.0.99", addr), now=100.0)

    recon = [a for a in alert_store.list() if "reconnaissance" in a["message"]]
    assert len(recon) == 1
    assert recon[0]["severity"] == "critical"


def test_plc_responses_are_ignored():
    mbap = b"\x00\x01\x00\x00\x00\x06\x01"
    pkt = IP(src="10.10.0.12", dst="10.10.0.20") / TCP(sport=502, dport=51000) / Raw(load=mbap + b"\x06\x00\x00\x00\x01")
    inspect_packet(pkt)
    assert alert_store.list() == []
