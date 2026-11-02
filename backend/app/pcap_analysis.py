from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

import pyshark


class PcapAnalysisError(Exception):
    pass


class FixtureNotFound(PcapAnalysisError):
    def __init__(self) -> None:
        super().__init__("Offline demo fixture is unavailable.")


class FixtureUnreadable(PcapAnalysisError):
    def __init__(self) -> None:
        super().__init__("Offline demo fixture cannot be analyzed.")


class NoSupportedPackets(PcapAnalysisError):
    def __init__(self) -> None:
        super().__init__("Offline demo fixture contains no supported packets.")


class ParserUnavailable(PcapAnalysisError):
    def __init__(self) -> None:
        super().__init__("Offline packet analysis is unavailable.")


@dataclass(frozen=True)
class PacketMetadata:
    timestamp: float
    length: int
    protocol: str
    source_ip: str
    source_port: int | None
    destination_ip: str
    destination_port: int | None


@dataclass(frozen=True)
class FlowSummary:
    protocol: str
    source_ip: str
    source_port: int | None
    destination_ip: str
    destination_port: int | None
    packet_count: int
    byte_count: int
    duration_seconds: float
    packets_per_second: float
    bytes_per_second: float


@dataclass(frozen=True)
class AnalysisResult:
    packet_count: int
    flows: tuple[FlowSummary, ...]
    capture_first_timestamp: float | None = None
    capture_last_timestamp: float | None = None
    flow_time_bounds: tuple[tuple[float, float], ...] = ()


@dataclass
class _FlowAccumulator:
    first_packet: PacketMetadata
    last_timestamp: float
    packet_count: int
    byte_count: int
    sort_key: tuple[object, ...]


EndpointKey = tuple[int, bytes, int]
FlowKey = tuple[str, EndpointKey, EndpointKey]
CaptureFactory = Callable[..., Any]


def _endpoint_key(ip: str, port: int | None) -> EndpointKey:
    address = ipaddress.ip_address(ip)
    return (address.version, address.packed, -1 if port is None else port)


def _flow_key(packet: PacketMetadata) -> FlowKey:
    source = _endpoint_key(packet.source_ip, packet.source_port)
    destination = _endpoint_key(packet.destination_ip, packet.destination_port)
    endpoint_a, endpoint_b = sorted((source, destination))
    return (packet.protocol.upper(), endpoint_a, endpoint_b)


def _finish_flow(accumulator: _FlowAccumulator) -> FlowSummary:
    duration = round(
        accumulator.last_timestamp - accumulator.first_packet.timestamp, 6
    )
    if duration == 0:
        packets_per_second = 0.0
        bytes_per_second = 0.0
    else:
        packets_per_second = round(accumulator.packet_count / duration, 3)
        bytes_per_second = round(accumulator.byte_count / duration, 3)

    first = accumulator.first_packet
    return FlowSummary(
        protocol=first.protocol.upper(),
        source_ip=str(ipaddress.ip_address(first.source_ip)),
        source_port=first.source_port,
        destination_ip=str(ipaddress.ip_address(first.destination_ip)),
        destination_port=first.destination_port,
        packet_count=accumulator.packet_count,
        byte_count=accumulator.byte_count,
        duration_seconds=duration,
        packets_per_second=packets_per_second,
        bytes_per_second=bytes_per_second,
    )


def _summarize_accumulators(
    packets: Iterable[PacketMetadata], *, max_packets: int = 2_000
) -> tuple[_FlowAccumulator, ...]:
    active: dict[FlowKey, _FlowAccumulator] = {}
    finished: list[_FlowAccumulator] = []

    for packet_count, packet in enumerate(
        sorted(packets, key=lambda item: item.timestamp), start=1
    ):
        if packet_count > max_packets:
            raise FixtureUnreadable()

        key = _flow_key(packet)
        current = active.get(key)
        idle_seconds = Decimal(str(packet.timestamp)) - Decimal(
            str(current.last_timestamp)
        ) if current is not None else None
        if current is None or idle_seconds >= Decimal("60"):
            if current is not None:
                finished.append(current)
            active[key] = _FlowAccumulator(
                first_packet=packet,
                last_timestamp=packet.timestamp,
                packet_count=1,
                byte_count=packet.length,
                sort_key=(packet.timestamp, *key),
            )
        else:
            current.last_timestamp = packet.timestamp
            current.packet_count += 1
            current.byte_count += packet.length

    finished.extend(active.values())
    finished.sort(key=lambda item: item.sort_key)
    return tuple(finished)


def summarize_packets(
    packets: Iterable[PacketMetadata], *, max_packets: int = 2_000
) -> tuple[FlowSummary, ...]:
    return tuple(
        _finish_flow(item)
        for item in _summarize_accumulators(packets, max_packets=max_packets)
    )


def _optional_int(value: object | None) -> int | None:
    return None if value is None else int(str(value))


def _packet_to_metadata(packet: Any) -> PacketMetadata | None:
    ip_layer = getattr(packet, "ip", None)
    ipv6_layer = getattr(packet, "ipv6", None)
    network_layer = ip_layer if ip_layer is not None else ipv6_layer
    if network_layer is None:
        return None

    transport_layer = getattr(packet, "transport_layer", None)
    protocol: str
    source_port: int | None = None
    destination_port: int | None = None
    if transport_layer in {"TCP", "UDP"}:
        protocol = transport_layer
        layer = packet[transport_layer]
        source_port = _optional_int(getattr(layer, "srcport", None))
        destination_port = _optional_int(getattr(layer, "dstport", None))
    elif getattr(packet, "icmp", None) is not None:
        protocol = "ICMP"
    elif getattr(packet, "icmpv6", None) is not None:
        protocol = "ICMPV6"
    else:
        return None

    return PacketMetadata(
        timestamp=float(packet.sniff_timestamp),
        length=int(packet.length),
        protocol=protocol,
        source_ip=str(network_layer.src),
        source_port=source_port,
        destination_ip=str(network_layer.dst),
        destination_port=destination_port,
    )


def _read_capture(capture: Any, max_packets: int) -> list[PacketMetadata]:
    packets: list[PacketMetadata] = []
    for raw_packet in capture:
        metadata = _packet_to_metadata(raw_packet)
        if metadata is None:
            continue
        packets.append(metadata)
        if len(packets) > max_packets:
            raise FixtureUnreadable()
    return packets


def _close_capture(capture: Any) -> None:
    try:
        capture.close()
    except Exception:
        pass


def _read_capture_and_close(capture: Any, max_packets: int) -> list[PacketMetadata]:
    try:
        return _read_capture(capture, max_packets)
    finally:
        _close_capture(capture)


def analyze_pcap(
    path: Path,
    *,
    max_bytes: int = 1_048_576,
    max_packets: int = 2_000,
    timeout_seconds: float = 10.0,
    capture_factory: CaptureFactory | None = None,
) -> AnalysisResult:
    if not path.exists():
        raise FixtureNotFound()
    if not path.is_file():
        raise FixtureUnreadable()
    try:
        if path.stat().st_size > max_bytes:
            raise FixtureUnreadable()
        with path.open("rb") as fixture:
            fixture.read(1)
    except FixtureUnreadable:
        raise
    except OSError as error:
        raise FixtureUnreadable() from error

    factory = pyshark.FileCapture if capture_factory is None else capture_factory
    eventloop = asyncio.new_event_loop()
    try:
        capture = factory(
            input_file=str(path),
            keep_packets=False,
            include_raw=False,
            eventloop=eventloop,
        )
    except Exception as error:
        eventloop.close()
        raise ParserUnavailable() from error

    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(_read_capture_and_close, capture, max_packets)
    wait_for_worker = True
    try:
        packets = future.result(timeout=timeout_seconds)
    except FutureTimeout as error:
        wait_for_worker = False
        _close_capture(capture)
        future.cancel()
        raise ParserUnavailable() from error
    except FixtureUnreadable:
        raise
    except Exception as error:
        raise ParserUnavailable() from error
    finally:
        executor.shutdown(wait=wait_for_worker, cancel_futures=True)
        if not eventloop.is_running() and not eventloop.is_closed():
            eventloop.close()

    if not packets:
        raise NoSupportedPackets()

    accumulators = _summarize_accumulators(packets, max_packets=max_packets)
    flows = tuple(_finish_flow(item) for item in accumulators)
    return AnalysisResult(
        packet_count=len(packets),
        flows=flows,
        capture_first_timestamp=min(packet.timestamp for packet in packets),
        capture_last_timestamp=max(packet.timestamp for packet in packets),
        flow_time_bounds=tuple(
            (item.first_packet.timestamp, item.last_timestamp)
            for item in accumulators
        ),
    )
