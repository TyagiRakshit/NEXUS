EXPECTED_PACKET_COUNT = 16
EXPECTED_FLOW_COUNT = 8
EXPECTED_FIXTURE_BYTES = 1_048

EXPECTED_HOST_PROFILES = [
    {
        "host_ip": "192.0.2.10",
        "observed_flow_count": 6,
        "protocol_mix": [
            {"protocol": "ICMP", "flow_count": 1},
            {"protocol": "TCP", "flow_count": 3},
            {"protocol": "UDP", "flow_count": 2},
        ],
        "average_bytes_per_flow": 96.0,
        "average_duration_seconds": 2.333,
        "average_packets_per_second": 1.167,
    },
    {
        "host_ip": "198.51.100.20",
        "observed_flow_count": 5,
        "protocol_mix": [
            {"protocol": "TCP", "flow_count": 3},
            {"protocol": "UDP", "flow_count": 2},
        ],
        "average_bytes_per_flow": 98.4,
        "average_duration_seconds": 2.0,
        "average_packets_per_second": 1.3,
    },
    {
        "host_ip": "203.0.113.30",
        "observed_flow_count": 5,
        "protocol_mix": [
            {"protocol": "ICMP", "flow_count": 1},
            {"protocol": "TCP", "flow_count": 2},
            {"protocol": "UDP", "flow_count": 2},
        ],
        "average_bytes_per_flow": 93.6,
        "average_duration_seconds": 2.0,
        "average_packets_per_second": 1.3,
    },
]
