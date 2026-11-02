EXPECTED_DOCUMENTATION_HOSTS = {
    "192.0.2.10",
    "198.51.100.20",
    "203.0.113.30",
}

EXPECTED_NORMAL_FIXTURE_BYTES = 9_672
EXPECTED_NORMAL_PACKET_COUNT = 144
EXPECTED_NORMAL_FLOW_COUNT = 48
EXPECTED_NORMAL_NUMERIC_RANGES = (
    (2.0, 4.0),
    (84.0, 216.0),
    (1.0, 4.0),
    (0.5, 4.0),
    (27.0, 168.0),
)

EXPECTED_UNUSUAL_FIXTURE_BYTES = 1_096
EXPECTED_UNUSUAL_PACKET_COUNT = 16
EXPECTED_MODEL_THRESHOLD = 0.636672
EXPECTED_DETECTION_RESULTS = [
    {
        "anomaly_score": 0.600084,
        "risk_score": 20,
        "risk_level": "Low",
        "is_statistically_unusual": False,
        "alert_flagged": False,
        "explanations": (
            "Packet count 12 is above synthetic training range 2 to 4.",
            "Byte count 648 is above synthetic training range 84 to 216.",
            "Packets per second 12 is above synthetic training range 0.5 to 4.",
        ),
    },
    {
        "anomaly_score": 0.620599,
        "risk_score": 20,
        "risk_level": "Low",
        "is_statistically_unusual": False,
        "alert_flagged": False,
        "explanations": (
            "Duration seconds 45 is above synthetic training range 1 to 4.",
            "Packets per second 0.044 is below synthetic training range 0.5 to 4.",
            "Bytes per second 1.867 is below synthetic training range 27 to 168.",
        ),
    },
    {
        "anomaly_score": 0.641502,
        "risk_score": 90,
        "risk_level": "High",
        "is_statistically_unusual": True,
        "alert_flagged": True,
        "explanations": (
            "Duration seconds 0.1 is below synthetic training range 1 to 4.",
            "Packets per second 20 is above synthetic training range 0.5 to 4.",
            "Bytes per second 840 is above synthetic training range 27 to 168.",
        ),
    },
]
EXPECTED_UNUSUAL_FLOWS = [
    {
        "protocol": "TCP",
        "source_ip": "192.0.2.10",
        "source_port": 56001,
        "destination_ip": "198.51.100.20",
        "destination_port": 443,
        "packet_count": 12,
        "byte_count": 648,
        "duration_seconds": 1.0,
        "packets_per_second": 12.0,
        "bytes_per_second": 648.0,
    },
    {
        "protocol": "UDP",
        "source_ip": "198.51.100.20",
        "source_port": 56002,
        "destination_ip": "203.0.113.30",
        "destination_port": 123,
        "packet_count": 2,
        "byte_count": 84,
        "duration_seconds": 45.0,
        "packets_per_second": 0.044,
        "bytes_per_second": 1.867,
    },
    {
        "protocol": "ICMP",
        "source_ip": "203.0.113.30",
        "source_port": None,
        "destination_ip": "192.0.2.10",
        "destination_port": None,
        "packet_count": 2,
        "byte_count": 84,
        "duration_seconds": 0.1,
        "packets_per_second": 20.0,
        "bytes_per_second": 840.0,
    },
]

EXPECTED_MIXED_FIXTURE_BYTES = 2_154
EXPECTED_MIXED_PACKET_COUNT = 33
EXPECTED_MIXED_FLOW_COUNT = 12
EXPECTED_MIXED_DETECTION_RESULTS = [
    ("UDP", 0.632450, "Low", False),
    ("TCP", 0.509147, "Low", False),
    ("TCP", 0.516079, "Low", False),
    ("TCP", 0.567335, "Low", False),
    ("UDP", 0.590858, "Low", False),
    ("TCP", 0.565939, "Low", False),
    ("TCP", 0.514441, "Low", False),
    ("TCP", 0.513404, "Low", False),
    ("UDP", 0.636672, "Low", False),
    ("ICMP", 0.641502, "High", True),
    ("ICMP", 0.641502, "High", True),
    ("ICMP", 0.641502, "High", True),
]
