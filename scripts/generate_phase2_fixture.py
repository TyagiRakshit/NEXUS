"""Generate the one authorized, payload-free Phase 2 demo PCAP."""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = REPOSITORY_ROOT / "data" / "pcap" / "phase2-demo.pcap"

SOURCE_MAC = bytes.fromhex("020000000010")
DESTINATION_MAC = bytes.fromhex("020000000020")


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xFFFF) + (total >> 16)
    total += total >> 16
    return (~total) & 0xFFFF


def ethernet(payload: bytes, ether_type: int, *, reverse: bool = False) -> bytes:
    source, destination = (
        (DESTINATION_MAC, SOURCE_MAC) if reverse else (SOURCE_MAC, DESTINATION_MAC)
    )
    return destination + source + struct.pack("!H", ether_type) + payload


def ipv4_packet(source: str, destination: str, protocol: int, payload: bytes) -> bytes:
    source_bytes = ipaddress.IPv4Address(source).packed
    destination_bytes = ipaddress.IPv4Address(destination).packed
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
        source_bytes,
        destination_bytes,
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


def ipv6_udp_packet(
    source: str, destination: str, source_port: int, destination_port: int
) -> bytes:
    udp = struct.pack("!HHHH", source_port, destination_port, 8, 0)
    header = struct.pack(
        "!IHBB16s16s",
        0x60000000,
        len(udp),
        17,
        64,
        ipaddress.IPv6Address(source).packed,
        ipaddress.IPv6Address(destination).packed,
    )
    return header + udp


def icmp_echo(icmp_type: int) -> bytes:
    base = struct.pack("!BBHHH", icmp_type, 0, 0, 1, 1)
    return base[:2] + struct.pack("!H", checksum(base)) + base[4:]


def fixture_frames() -> list[bytes]:
    frames = [
        ethernet(
            ipv4_packet(
                "192.0.2.10", "198.51.100.20", 6, tcp_header(51515, 443, 0x02)
            ),
            0x0800,
        ),
        ethernet(
            ipv4_packet(
                "198.51.100.20", "192.0.2.10", 6, tcp_header(443, 51515, 0x12)
            ),
            0x0800,
            reverse=True,
        ),
        ethernet(
            ipv4_packet(
                "192.0.2.10", "198.51.100.20", 6, tcp_header(51515, 443, 0x10)
            ),
            0x0800,
        ),
        ethernet(
            ipv6_udp_packet("2001:db8::10", "2001:db8::20", 53000, 53001),
            0x86DD,
        ),
        ethernet(
            ipv6_udp_packet("2001:db8::20", "2001:db8::10", 53001, 53000),
            0x86DD,
            reverse=True,
        ),
        ethernet(
            ipv4_packet("192.0.2.10", "198.51.100.20", 1, icmp_echo(8)),
            0x0800,
        ),
        ethernet(
            ipv4_packet("198.51.100.20", "192.0.2.10", 1, icmp_echo(0)),
            0x0800,
            reverse=True,
        ),
    ]
    assert [len(frame) for frame in frames] == [54, 54, 54, 62, 62, 42, 42]
    return frames


def generate_fixture(path: Path = OUTPUT_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    packet_records = []
    for timestamp, frame in enumerate(fixture_frames(), start=1):
        packet_records.append(
            struct.pack("<IIII", timestamp, 0, len(frame), len(frame)) + frame
        )
    path.write_bytes(global_header + b"".join(packet_records))
    return path


if __name__ == "__main__":
    generated = generate_fixture()
    print(f"Generated synthetic payload-free fixture: {generated}")
