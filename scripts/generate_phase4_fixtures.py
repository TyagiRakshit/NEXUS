"""Generate the fixed payload-free Phase 4 demonstration fixtures."""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIRECTORY = REPOSITORY_ROOT / "data" / "pcap"
NORMAL_OUTPUT_PATH = OUTPUT_DIRECTORY / "phase4-normal-training.pcap"
UNUSUAL_OUTPUT_PATH = OUTPUT_DIRECTORY / "phase4-unusual.pcap"
MIXED_OUTPUT_PATH = OUTPUT_DIRECTORY / "phase4-mixed-demo.pcap"

HOSTS = ("192.0.2.10", "198.51.100.20", "203.0.113.30")
MACS = {
    HOSTS[0]: bytes.fromhex("020000000010"),
    HOSTS[1]: bytes.fromhex("020000000020"),
    HOSTS[2]: bytes.fromhex("020000000030"),
}


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xFFFF) + (total >> 16)
    total += total >> 16
    return (~total) & 0xFFFF


def ethernet(source: str, destination: str, payload: bytes) -> bytes:
    return MACS[destination] + MACS[source] + struct.pack("!H", 0x0800) + payload


def ipv4_packet(source: str, destination: str, protocol: int, payload: bytes) -> bytes:
    base = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        0,
        0,
        64,
        protocol,
        0,
        ipaddress.IPv4Address(source).packed,
        ipaddress.IPv4Address(destination).packed,
    )
    header = base[:10] + struct.pack("!H", checksum(base)) + base[12:]
    return header + payload


def tcp_frame(
    source: str,
    source_port: int,
    destination: str,
    destination_port: int,
    *,
    reverse: bool,
) -> bytes:
    flags = 0x12 if reverse else 0x02
    header = struct.pack(
        "!HHIIBBHHH",
        source_port,
        destination_port,
        0,
        0,
        0x50,
        flags,
        8192,
        0,
        0,
    )
    return ethernet(source, destination, ipv4_packet(source, destination, 6, header))


def udp_frame(
    source: str,
    source_port: int,
    destination: str,
    destination_port: int,
) -> bytes:
    header = struct.pack("!HHHH", source_port, destination_port, 8, 0)
    return ethernet(source, destination, ipv4_packet(source, destination, 17, header))


def icmp_frame(source: str, destination: str, *, reverse: bool) -> bytes:
    icmp_type = 0 if reverse else 8
    base = struct.pack("!BBHHH", icmp_type, 0, 0, 1, 1)
    header = base[:2] + struct.pack("!H", checksum(base)) + base[4:]
    return ethernet(source, destination, ipv4_packet(source, destination, 1, header))


def _alternating_flow(
    *,
    start: int,
    duration: float,
    packet_count: int,
    source: str,
    destination: str,
    protocol: str,
    source_port: int | None,
    destination_port: int | None,
) -> list[tuple[float, bytes]]:
    records: list[tuple[float, bytes]] = []
    for packet_index in range(packet_count):
        reverse = packet_index % 2 == 1
        packet_source = destination if reverse else source
        packet_destination = source if reverse else destination
        packet_source_port = destination_port if reverse else source_port
        packet_destination_port = source_port if reverse else destination_port
        timestamp = start + (duration * packet_index / (packet_count - 1))
        if protocol == "TCP":
            frame = tcp_frame(
                packet_source,
                int(packet_source_port),
                packet_destination,
                int(packet_destination_port),
                reverse=reverse,
            )
        elif protocol == "UDP":
            frame = udp_frame(
                packet_source,
                int(packet_source_port),
                packet_destination,
                int(packet_destination_port),
            )
        else:
            frame = icmp_frame(packet_source, packet_destination, reverse=reverse)
        records.append((timestamp, frame))
    return records


def normal_records() -> list[tuple[float, bytes]]:
    records: list[tuple[float, bytes]] = []
    for index in range(48):
        records.extend(normal_flow_records(index))
    assert len(records) == 144
    return records


def normal_flow_records(index: int) -> list[tuple[float, bytes]]:
    tcp_destinations = (80, 443, 22, 8443)
    udp_destinations = (53, 123)
    source_index = (index // 4) % 3
    destination_index = (source_index + 1 + (index % 2)) % 3
    is_udp = index % 4 == 0
    return _alternating_flow(
        start=index * 70,
        duration=1 + (index % 4),
        packet_count=2 + (index % 3),
        source=HOSTS[source_index],
        destination=HOSTS[destination_index],
        protocol="UDP" if is_udp else "TCP",
        source_port=40000 + index,
        destination_port=(
            udp_destinations[(index // 4) % 2]
            if is_udp
            else tcp_destinations[(index // 4) % 4]
        ),
    )


def mixed_records() -> list[tuple[float, bytes]]:
    records: list[tuple[float, bytes]] = []
    for index in range(9):
        records.extend(normal_flow_records(index))
    for index, (source, destination) in enumerate(
        (
            (HOSTS[0], HOSTS[1]),
            (HOSTS[1], HOSTS[2]),
            (HOSTS[2], HOSTS[0]),
        )
    ):
        records.extend(
            _alternating_flow(
                start=(9 + index) * 70,
                duration=0.1,
                packet_count=2,
                source=source,
                destination=destination,
                protocol="ICMP",
                source_port=None,
                destination_port=None,
            )
        )
    assert len(records) == 33
    return records


def unusual_records() -> list[tuple[float, bytes]]:
    records = _alternating_flow(
        start=1,
        duration=1,
        packet_count=12,
        source=HOSTS[0],
        destination=HOSTS[1],
        protocol="TCP",
        source_port=56001,
        destination_port=443,
    )
    records.extend(
        _alternating_flow(
            start=70,
            duration=45,
            packet_count=2,
            source=HOSTS[1],
            destination=HOSTS[2],
            protocol="UDP",
            source_port=56002,
            destination_port=123,
        )
    )
    records.extend(
        _alternating_flow(
            start=140,
            duration=0.1,
            packet_count=2,
            source=HOSTS[2],
            destination=HOSTS[0],
            protocol="ICMP",
            source_port=None,
            destination_port=None,
        )
    )
    assert len(records) == 16
    return records


def write_pcap(path: Path, records: list[tuple[float, bytes]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    packet_records = []
    for timestamp, frame in records:
        seconds = int(timestamp)
        microseconds = round((timestamp - seconds) * 1_000_000)
        packet_records.append(
            struct.pack("<IIII", seconds, microseconds, len(frame), len(frame)) + frame
        )
    path.write_bytes(global_header + b"".join(packet_records))
    return path


def generate_fixtures(
    normal_path: Path = NORMAL_OUTPUT_PATH,
    unusual_path: Path = UNUSUAL_OUTPUT_PATH,
    mixed_path: Path = MIXED_OUTPUT_PATH,
) -> tuple[Path, Path, Path]:
    normal = write_pcap(normal_path, normal_records())
    unusual = write_pcap(unusual_path, unusual_records())
    mixed = write_pcap(mixed_path, mixed_records())
    assert normal.stat().st_size == 9_672
    assert unusual.stat().st_size == 1_096
    assert mixed.stat().st_size == 2_154
    return normal, unusual, mixed


if __name__ == "__main__":
    generated_normal, generated_unusual, generated_mixed = generate_fixtures()
    print(f"Generated synthetic payload-free fixture: {generated_normal}")
    print(f"Generated synthetic payload-free fixture: {generated_unusual}")
    print(f"Generated synthetic payload-free fixture: {generated_mixed}")
