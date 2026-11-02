import os
from pathlib import Path
from typing import Any

import pytest

from app.host_profiles import (
    BaselineAdmissionError,
    HostProfile,
    InMemoryBaselineStore,
    ProtocolCount,
    build_host_profiles,
)
from app.pcap_analysis import FlowSummary, analyze_pcap
from fixtures.phase3_expectations import (
    EXPECTED_FLOW_COUNT,
    EXPECTED_HOST_PROFILES,
    EXPECTED_PACKET_COUNT,
)


def flow(
    protocol: str,
    source_ip: str,
    destination_ip: str,
    *,
    source_port: int | None = None,
    destination_port: int | None = None,
    byte_count: int = 100,
    duration_seconds: float = 2.0,
    packets_per_second: float = 1.5,
) -> FlowSummary:
    return FlowSummary(
        protocol=protocol,
        source_ip=source_ip,
        source_port=source_port,
        destination_ip=destination_ip,
        destination_port=destination_port,
        packet_count=2,
        byte_count=byte_count,
        duration_seconds=duration_seconds,
        packets_per_second=packets_per_second,
        bytes_per_second=0.0,
    )


def profile_dict(profile: HostProfile) -> dict[str, Any]:
    return {
        "host_ip": profile.host_ip,
        "observed_flow_count": profile.observed_flow_count,
        "protocol_mix": [
            {"protocol": item.protocol, "flow_count": item.flow_count}
            for item in profile.protocol_mix
        ],
        "average_bytes_per_flow": profile.average_bytes_per_flow,
        "average_duration_seconds": profile.average_duration_seconds,
        "average_packets_per_second": profile.average_packets_per_second,
    }


def host_profile(
    *,
    host_ip: str = "192.0.2.10",
    flow_count: int = 2,
    tcp_count: int = 2,
    average_bytes: float = 100.0,
    average_duration: float = 2.0,
    average_packet_rate: float = 1.5,
) -> HostProfile:
    return HostProfile(
        host_ip=host_ip,
        observed_flow_count=flow_count,
        protocol_mix=(ProtocolCount(protocol="TCP", flow_count=tcp_count),),
        average_bytes_per_flow=average_bytes,
        average_duration_seconds=average_duration,
        average_packets_per_second=average_packet_rate,
    )


def test_each_flow_contributes_once_to_each_unique_endpoint() -> None:
    profiles = build_host_profiles(
        [
            flow("TCP", "192.0.2.10", "198.51.100.20", byte_count=108),
            flow("UDP", "198.51.100.20", "203.0.113.30", byte_count=84),
        ]
    )

    assert [(item.host_ip, item.observed_flow_count) for item in profiles] == [
        ("192.0.2.10", 1),
        ("198.51.100.20", 2),
        ("203.0.113.30", 1),
    ]


def test_reversing_display_direction_does_not_change_host_profiles() -> None:
    forward = flow(
        "TCP",
        "192.0.2.10",
        "198.51.100.20",
        source_port=51001,
        destination_port=443,
        byte_count=108,
        duration_seconds=1.0,
        packets_per_second=2.0,
    )
    reverse = flow(
        "TCP",
        "198.51.100.20",
        "192.0.2.10",
        source_port=443,
        destination_port=51001,
        byte_count=108,
        duration_seconds=1.0,
        packets_per_second=2.0,
    )

    assert [profile_dict(item) for item in build_host_profiles([forward])] == [
        profile_dict(item) for item in build_host_profiles([reverse])
    ]


def test_same_ip_flow_contributes_only_once_to_that_host() -> None:
    profiles = build_host_profiles(
        [
            flow(
                "TCP",
                "192.0.2.10",
                "192.0.2.10",
                source_port=50000,
                destination_port=50001,
            )
        ]
    )

    assert len(profiles) == 1
    assert profiles[0].host_ip == "192.0.2.10"
    assert profiles[0].observed_flow_count == 1


def test_profiles_sort_ips_and_protocols_and_round_hand_derived_averages() -> None:
    profiles = build_host_profiles(
        [
            flow(
                "udp",
                "2001:db8::2",
                "192.0.2.10",
                byte_count=84,
                duration_seconds=1.0,
                packets_per_second=2.0,
            ),
            flow(
                "TCP",
                "192.0.2.10",
                "2001:db8::1",
                byte_count=108,
                duration_seconds=2.0,
                packets_per_second=1.0,
            ),
            flow(
                "ICMP",
                "192.0.2.10",
                "198.51.100.20",
                byte_count=84,
                duration_seconds=4.0,
                packets_per_second=0.5,
            ),
        ]
    )

    assert [item.host_ip for item in profiles] == [
        "192.0.2.10",
        "198.51.100.20",
        "2001:db8::1",
        "2001:db8::2",
    ]
    first = profiles[0]
    assert [(item.protocol, item.flow_count) for item in first.protocol_mix] == [
        ("ICMP", 1),
        ("TCP", 1),
        ("UDP", 1),
    ]
    assert first.average_bytes_per_flow == 92.0
    assert first.average_duration_seconds == 2.333
    assert first.average_packets_per_second == 1.167


def test_zero_metrics_remain_zero_and_empty_input_returns_no_profiles() -> None:
    profiles = build_host_profiles(
        [
            flow(
                "ICMP",
                "192.0.2.10",
                "198.51.100.20",
                byte_count=0,
                duration_seconds=0.0,
                packets_per_second=0.0,
            )
        ]
    )

    assert profiles[0].average_bytes_per_flow == 0.0
    assert profiles[0].average_duration_seconds == 0.0
    assert profiles[0].average_packets_per_second == 0.0
    assert build_host_profiles([]) == ()


def test_rejected_batches_do_not_advance_warmup_count_or_version() -> None:
    store = InMemoryBaselineStore()
    profile = host_profile()

    first = store.admit_normal_batch((profile,), fixture_id="phase3-normal-v1")
    with pytest.raises(BaselineAdmissionError, match="not admitted"):
        store.admit_normal_batch((), fixture_id="phase3-normal-v1")
    with pytest.raises(BaselineAdmissionError, match="not admitted"):
        store.admit_normal_batch((profile,), fixture_id="other-fixture")
    second = store.admit_normal_batch((profile,), fixture_id="phase3-normal-v1")

    assert first.baseline_state == "warming"
    assert first.admitted_batch_count == 1
    assert first.baseline_version == 0
    assert second.baseline_state == "ready"
    assert second.admitted_batch_count == 2
    assert second.baseline_version == 1


def test_second_batch_creates_exact_baseline_and_retains_current_profile() -> None:
    store = InMemoryBaselineStore()
    first_profile = host_profile(
        flow_count=2,
        tcp_count=2,
        average_bytes=80.0,
        average_duration=1.0,
        average_packet_rate=2.0,
    )
    second_profile = host_profile(
        flow_count=4,
        tcp_count=4,
        average_bytes=120.0,
        average_duration=3.0,
        average_packet_rate=1.0,
    )

    warming = store.admit_normal_batch(
        (first_profile,), fixture_id="phase3-normal-v1"
    )
    ready = store.admit_normal_batch(
        (second_profile,), fixture_id="phase3-normal-v1"
    )

    assert warming.baseline_profiles == ()
    assert ready.current_profiles == (second_profile,)
    assert ready.window_batch_count == 2
    assert ready.previous_baseline_version is None
    assert len(ready.baseline_profiles) == 1
    baseline = ready.baseline_profiles[0]
    assert baseline.host_ip == "192.0.2.10"
    assert baseline.observed_batch_count == 2
    assert baseline.average_flow_count == 3.0
    assert [
        (item.protocol, item.average_flow_count) for item in baseline.protocol_mix
    ] == [("TCP", 3.0)]
    assert baseline.average_bytes_per_flow == 100.0
    assert baseline.average_duration_seconds == 2.0
    assert baseline.average_packets_per_second == 1.5


def test_sixth_batch_uses_latest_five_and_retains_only_previous_ready_snapshot() -> None:
    store = InMemoryBaselineStore()
    results = []
    for value in (10.0, 20.0, 30.0, 40.0, 50.0, 60.0):
        results.append(
            store.admit_normal_batch(
                (
                    host_profile(
                        average_bytes=value,
                        average_duration=value / 10,
                        average_packet_rate=value / 20,
                    ),
                ),
                fixture_id="phase3-normal-v1",
            )
        )

    sixth = results[-1]
    assert [item.baseline_version for item in results] == [0, 1, 2, 3, 4, 5]
    assert sixth.admitted_batch_count == 6
    assert sixth.window_batch_count == 5
    assert sixth.previous_baseline_version == 4
    assert sixth.baseline_profiles[0].average_bytes_per_flow == 40.0
    assert sixth.baseline_profiles[0].average_duration_seconds == 4.0
    assert sixth.baseline_profiles[0].average_packets_per_second == 2.0
    assert store.previous_snapshot is not None
    assert store.previous_snapshot.baseline_version == 4
    assert store.previous_snapshot.baseline_profiles[0].average_bytes_per_flow == 30.0


def test_zero_baseline_values_remain_zero() -> None:
    store = InMemoryBaselineStore()
    zero = host_profile(
        flow_count=1,
        tcp_count=1,
        average_bytes=0.0,
        average_duration=0.0,
        average_packet_rate=0.0,
    )

    store.admit_normal_batch((zero,), fixture_id="phase3-normal-v1")
    result = store.admit_normal_batch((zero,), fixture_id="phase3-normal-v1")

    baseline = result.baseline_profiles[0]
    assert baseline.average_bytes_per_flow == 0.0
    assert baseline.average_duration_seconds == 0.0
    assert baseline.average_packets_per_second == 0.0


def test_new_store_starts_warming_instead_of_recovering_another_store() -> None:
    first_store = InMemoryBaselineStore()
    profile = host_profile()
    first_store.admit_normal_batch((profile,), fixture_id="phase3-normal-v1")
    assert (
        first_store.admit_normal_batch(
            (profile,), fixture_id="phase3-normal-v1"
        ).baseline_version
        == 1
    )

    restarted = InMemoryBaselineStore()
    first_after_restart = restarted.admit_normal_batch(
        (profile,), fixture_id="phase3-normal-v1"
    )

    assert first_after_restart.baseline_state == "warming"
    assert first_after_restart.baseline_version == 0
    assert first_after_restart.admitted_batch_count == 1


@pytest.mark.skipif(
    "NEXUS_TEST_PHASE3_PCAP_PATH" not in os.environ,
    reason="real Phase 3 TShark fixture is not mounted",
)
def test_real_normal_fixture_produces_expected_host_profiles() -> None:
    result = analyze_pcap(Path(os.environ["NEXUS_TEST_PHASE3_PCAP_PATH"]))

    assert result.packet_count == EXPECTED_PACKET_COUNT
    assert len(result.flows) == EXPECTED_FLOW_COUNT
    assert [profile_dict(item) for item in build_host_profiles(result.flows)] == (
        EXPECTED_HOST_PROFILES
    )
