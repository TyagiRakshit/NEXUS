import asyncio
import os

import anyio
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from app.pcap_analysis import (
    FixtureNotFound,
    FixtureUnreadable,
    NoSupportedPackets,
    PacketMetadata,
    ParserUnavailable,
    analyze_pcap,
    summarize_packets,
)
from fixtures.phase2_expectations import (
    EXPECTED_FLOW_COUNT,
    EXPECTED_FLOWS,
    EXPECTED_PACKET_COUNT,
)


def packet(
    timestamp: float,
    *,
    protocol: str = "TCP",
    source_ip: str = "192.0.2.10",
    source_port: int | None = 51515,
    destination_ip: str = "198.51.100.20",
    destination_port: int | None = 443,
    length: int = 54,
) -> PacketMetadata:
    return PacketMetadata(
        timestamp=timestamp,
        length=length,
        protocol=protocol,
        source_ip=source_ip,
        source_port=source_port,
        destination_ip=destination_ip,
        destination_port=destination_port,
    )


def flow_dict(flow: Any) -> dict[str, object]:
    return {
        "protocol": flow.protocol,
        "source_ip": flow.source_ip,
        "source_port": flow.source_port,
        "destination_ip": flow.destination_ip,
        "destination_port": flow.destination_port,
        "packet_count": flow.packet_count,
        "byte_count": flow.byte_count,
        "duration_seconds": flow.duration_seconds,
        "packets_per_second": flow.packets_per_second,
        "bytes_per_second": flow.bytes_per_second,
    }


def test_reverse_packets_share_one_flow_and_preserve_first_direction() -> None:
    flows = summarize_packets(
        [
            packet(1.0),
            packet(
                2.0,
                source_ip="198.51.100.20",
                source_port=443,
                destination_ip="192.0.2.10",
                destination_port=51515,
            ),
            packet(3.0),
        ]
    )

    assert [flow_dict(flow) for flow in flows] == [EXPECTED_FLOWS[0]]


def test_idle_timeout_keeps_59999_gap_and_splits_exactly_at_60_seconds() -> None:
    flows = summarize_packets([packet(0.0), packet(59.999), packet(119.999)])

    assert len(flows) == 2
    assert flows[0].packet_count == 2
    assert flows[0].duration_seconds == 59.999
    assert flows[1].packet_count == 1
    assert flows[1].duration_seconds == 0.0


def test_ipv6_and_portless_protocols_group_bidirectionally_and_sort_stably() -> None:
    flows = summarize_packets(
        [
            packet(
                4.0,
                protocol="UDP",
                source_ip="2001:db8::10",
                source_port=53000,
                destination_ip="2001:db8::20",
                destination_port=53001,
                length=62,
            ),
            packet(
                5.0,
                protocol="UDP",
                source_ip="2001:db8::20",
                source_port=53001,
                destination_ip="2001:db8::10",
                destination_port=53000,
                length=62,
            ),
            packet(
                6.0,
                protocol="ICMP",
                source_port=None,
                destination_port=None,
                length=42,
            ),
            packet(
                7.0,
                protocol="ICMP",
                source_ip="198.51.100.20",
                source_port=None,
                destination_ip="192.0.2.10",
                destination_port=None,
                length=42,
            ),
        ]
    )

    assert [flow_dict(flow) for flow in flows] == EXPECTED_FLOWS[1:]


def test_zero_duration_reports_zero_rates() -> None:
    flow = summarize_packets([packet(1.0)])[0]

    assert flow.duration_seconds == 0.0
    assert flow.packets_per_second == 0.0
    assert flow.bytes_per_second == 0.0


def test_packet_limit_is_enforced() -> None:
    with pytest.raises(FixtureUnreadable, match="cannot be analyzed"):
        summarize_packets([packet(float(index)) for index in range(3)], max_packets=2)


class FakeCapture:
    def __init__(self, packets: list[object]) -> None:
        self.packets = packets
        self.closed = False

    def __iter__(self):
        return iter(self.packets)

    def close(self) -> None:
        self.closed = True


def test_analyzer_opens_pyshark_without_raw_packet_data(tmp_path: Path) -> None:
    fixture = tmp_path / "fixture.pcap"
    fixture.write_bytes(b"small fixture")
    observed: dict[str, object] = {}
    capture = FakeCapture([])

    def capture_factory(**kwargs: object) -> FakeCapture:
        observed.update(kwargs)
        return capture

    with pytest.raises(NoSupportedPackets):
        analyze_pcap(fixture, capture_factory=capture_factory)

    assert observed["input_file"] == str(fixture)
    assert observed["keep_packets"] is False
    assert observed["include_raw"] is False
    eventloop = observed["eventloop"]
    assert getattr(eventloop, "is_closed")() is True
    assert capture.closed is True


def test_missing_fixture_is_distinct_from_unreadable(tmp_path: Path) -> None:
    with pytest.raises(FixtureNotFound, match="unavailable"):
        analyze_pcap(tmp_path / "missing.pcap")


def test_directory_and_oversized_fixture_are_unreadable(tmp_path: Path) -> None:
    with pytest.raises(FixtureUnreadable, match="cannot be analyzed"):
        analyze_pcap(tmp_path)

    fixture = tmp_path / "large.pcap"
    fixture.write_bytes(b"x" * 9)
    with pytest.raises(FixtureUnreadable, match="cannot be analyzed"):
        analyze_pcap(fixture, max_bytes=8)


def test_permission_error_is_reported_as_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = tmp_path / "unreadable.pcap"
    fixture.write_bytes(b"fixture")

    def denied_open(*_args: object, **_kwargs: object) -> None:
        raise PermissionError("private local path")

    monkeypatch.setattr(Path, "open", denied_open)

    with pytest.raises(FixtureUnreadable) as raised:
        analyze_pcap(fixture)

    assert str(raised.value) == "Offline demo fixture cannot be analyzed."


def test_capture_with_no_supported_packets_is_reported(tmp_path: Path) -> None:
    fixture = tmp_path / "unsupported.pcap"
    fixture.write_bytes(b"fixture")

    with pytest.raises(NoSupportedPackets, match="no supported packets"):
        analyze_pcap(
            fixture,
            capture_factory=lambda **_kwargs: FakeCapture([object()]),
        )


class BrokenCapture(FakeCapture):
    def __iter__(self):
        raise RuntimeError("private parser command and path")


def test_parser_failure_is_sanitized_and_capture_is_closed(tmp_path: Path) -> None:
    fixture = tmp_path / "broken.pcap"
    fixture.write_bytes(b"fixture")
    capture = BrokenCapture([])

    with pytest.raises(ParserUnavailable) as raised:
        analyze_pcap(fixture, capture_factory=lambda **_kwargs: capture)

    assert str(raised.value) == "Offline packet analysis is unavailable."
    assert capture.closed is True


class BlockingCapture(FakeCapture):
    def __init__(self) -> None:
        super().__init__([])
        self.release = threading.Event()

    def __iter__(self):
        self.release.wait(timeout=1.0)
        return iter([])

    def close(self) -> None:
        self.closed = True
        self.release.set()


def test_parser_timeout_is_sanitized_and_capture_is_closed(tmp_path: Path) -> None:
    fixture = tmp_path / "slow.pcap"
    fixture.write_bytes(b"fixture")
    capture = BlockingCapture()

    with pytest.raises(ParserUnavailable) as raised:
        analyze_pcap(
            fixture,
            timeout_seconds=0.01,
            capture_factory=lambda **_kwargs: capture,
        )

    assert str(raised.value) == "Offline packet analysis is unavailable."
    assert capture.closed is True


@pytest.mark.skipif(
    "NEXUS_TEST_PCAP_PATH" not in os.environ,
    reason="real TShark integration fixture is not mounted",
)
def test_real_fixture_produces_expected_metadata_only_flows() -> None:
    result = analyze_pcap(Path(os.environ["NEXUS_TEST_PCAP_PATH"]))

    assert result.packet_count == EXPECTED_PACKET_COUNT
    assert len(result.flows) == EXPECTED_FLOW_COUNT
    assert [flow_dict(flow) for flow in result.flows] == EXPECTED_FLOWS


class MetadataPacket:
    def __init__(self, timestamp: float, source_port: int) -> None:
        self.sniff_timestamp = str(timestamp)
        self.length = "54"
        self.ip = SimpleNamespace(src="192.0.2.10", dst="198.51.100.20")
        self.transport_layer = "TCP"
        self.tcp = SimpleNamespace(srcport=str(source_port), dstport="443")

    def __getitem__(self, layer: str) -> object:
        assert layer == "TCP"
        return self.tcp


def test_analyzer_retains_capture_and_ordered_flow_time_bounds(tmp_path: Path) -> None:
    fixture = tmp_path / "metadata.pcap"
    fixture.write_bytes(b"fixture")
    capture = FakeCapture(
        [
            MetadataPacket(106.0, 50002),
            MetadataPacket(60.0, 50001),
            MetadataPacket(64.0, 50001),
            MetadataPacket(80.0, 50002),
        ]
    )

    result = analyze_pcap(fixture, capture_factory=lambda **_kwargs: capture)

    assert result.packet_count == 4
    assert result.capture_first_timestamp == 60.0
    assert result.capture_last_timestamp == 106.0
    assert result.flow_time_bounds == ((60.0, 64.0), (80.0, 106.0))
    assert [flow.packet_count for flow in result.flows] == [2, 2]


class LoopSensitiveCapture(FakeCapture):
    def close(self) -> None:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            self.closed = True
        else:
            raise RuntimeError("capture closed on an active API event loop")


def test_capture_closes_outside_async_api_event_loop(tmp_path: Path) -> None:
    fixture = tmp_path / "api.pcap"
    fixture.write_bytes(b"fixture")
    capture = LoopSensitiveCapture(
        [MetadataPacket(60.0, 40001), MetadataPacket(62.0, 40001)]
    )

    async def analyze_inside_route() -> None:
        result = analyze_pcap(fixture, capture_factory=lambda **_kwargs: capture)
        assert result.packet_count == 2

    anyio.run(analyze_inside_route)
    assert capture.closed is True
