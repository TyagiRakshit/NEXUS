EXPECTED_FIXTURE_ID = "phase2-synthetic-v1"
EXPECTED_PACKET_COUNT = 7
EXPECTED_FLOW_COUNT = 3

EXPECTED_FLOWS = [
    {
        "protocol": "TCP",
        "source_ip": "192.0.2.10",
        "source_port": 51515,
        "destination_ip": "198.51.100.20",
        "destination_port": 443,
        "packet_count": 3,
        "byte_count": 162,
        "duration_seconds": 2.0,
        "packets_per_second": 1.5,
        "bytes_per_second": 81.0,
    },
    {
        "protocol": "UDP",
        "source_ip": "2001:db8::10",
        "source_port": 53000,
        "destination_ip": "2001:db8::20",
        "destination_port": 53001,
        "packet_count": 2,
        "byte_count": 124,
        "duration_seconds": 1.0,
        "packets_per_second": 2.0,
        "bytes_per_second": 124.0,
    },
    {
        "protocol": "ICMP",
        "source_ip": "192.0.2.10",
        "source_port": None,
        "destination_ip": "198.51.100.20",
        "destination_port": None,
        "packet_count": 2,
        "byte_count": 84,
        "duration_seconds": 1.0,
        "packets_per_second": 2.0,
        "bytes_per_second": 84.0,
    },
]
