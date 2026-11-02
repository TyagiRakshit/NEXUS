"""Generate the fixed payload-free Phase 3 normal replay fixture."""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = REPOSITORY_ROOT / "data" / "pcap" / "phase3-normal.pcap"

HOST_A = "192.0.2.10"
HOST_B = "198.51.100.20"
HOST_C = "203.0.113.30"

MACS = {
    HOST_A: bytes.fromhex("020000000010"),
    HOST_B: bytes.fromhex("020000000020"),
    HOST_C: bytes.fromhex("020000000030"),
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


def tcp_header(source_port: int, destination_port: int, flags: int) -> bytes:
    return struct.pack(
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


def udp_header(source_port: int, destination_port: int) -> bytes:
    return struct.pack("!HHHH", source_port, destination_port, 8, 0)


def icmp_echo(icmp_type: int) -> bytes:
    base = struct.pack("!BBHHH", icmp_type, 0, 0, 1, 1)
    return base[:2] + struct.pack("!H", checksum(base)) + base[4:]


def tcp_pair(
    source: str,
    source_port: int,
    destination: str,
    destination_port: int,
) -> tuple[bytes, bytes]:
    return (
        ethernet(
            source,
            destination,
            ipv4_packet(
                source,
                destination,
                6,
                tcp_header(source_port, destination_port, 0x02),
            ),
        ),
        ethernet(
            destination,
            source,
            ipv4_packet(
                destination,
                source,
                6,
                tcp_header(destination_port, source_port, 0x12),
            ),
        ),
    )


def udp_pair(
    source: str,
    source_port: int,
    destination: str,
    destination_port: int,
) -> tuple[bytes, bytes]:
    return (
        ethernet(
            source,
            destination,
            ipv4_packet(
                source,
                destination,
                17,
                udp_header(source_port, destination_port),
            ),
        ),
        ethernet(
            destination,
            source,
            ipv4_packet(
                destination,
                source,
                17,
                udp_header(destination_port, source_port),
            ),
        ),
    )


def icmp_pair(source: str, destination: str) -> tuple[bytes, bytes]:
    return (
        ethernet(
            source,
            destination,
            ipv4_packet(source, destination, 1, icmp_echo(8)),
        ),
        ethernet(
            destination,
            source,
            ipv4_packet(destination, source, 1, icmp_echo(0)),
        ),
    )


def fixture_records() -> list[tuple[int, bytes]]:
    flows = [
        (1, 1, tcp_pair(HOST_A, 51001, HOST_B, 443)),
        (10, 2, tcp_pair(HOST_A, 51002, HOST_B, 80)),
        (20, 1, udp_pair(HOST_A, 53000, HOST_C, 53)),
        (30, 2, icmp_pair(HOST_A, HOST_C)),
        (40, 1, tcp_pair(HOST_B, 51003, HOST_C, 22)),
        (50, 2, udp_pair(HOST_B, 54000, HOST_C, 123)),
        (60, 4, tcp_pair(HOST_A, 51004, HOST_C, 8443)),
        (70, 4, udp_pair(HOST_A, 55000, HOST_B, 443)),
    ]
    records = [
        record
        for start, duration, pair in flows
        for record in ((start, pair[0]), (start + duration, pair[1]))
    ]
    assert len(records) == 16
    assert sum(len(frame) for _, frame in records) == 768
    return records


def generate_fixture(path: Path = OUTPUT_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    packet_records = [
        struct.pack("<IIII", timestamp, 0, len(frame), len(frame)) + frame
        for timestamp, frame in fixture_records()
    ]
    contents = global_header + b"".join(packet_records)
    assert len(contents) == 1_048
    path.write_bytes(contents)
    return path


if __name__ == "__main__":
    generated = generate_fixture()
    print(f"Generated synthetic payload-free fixture: {generated}")
