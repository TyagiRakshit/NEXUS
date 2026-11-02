from __future__ import annotations

import ipaddress
from collections import Counter, deque
from collections.abc import Iterable
from dataclasses import dataclass
from threading import Lock
from typing import Literal

from app.pcap_analysis import FlowSummary


@dataclass(frozen=True)
class ProtocolCount:
    protocol: str
    flow_count: int


@dataclass(frozen=True)
class HostProfile:
    host_ip: str
    observed_flow_count: int
    protocol_mix: tuple[ProtocolCount, ...]
    average_bytes_per_flow: float
    average_duration_seconds: float
    average_packets_per_second: float


@dataclass(frozen=True)
class ProtocolAverage:
    protocol: str
    average_flow_count: float


@dataclass(frozen=True)
class HostBaseline:
    host_ip: str
    observed_batch_count: int
    average_flow_count: float
    protocol_mix: tuple[ProtocolAverage, ...]
    average_bytes_per_flow: float
    average_duration_seconds: float
    average_packets_per_second: float


@dataclass(frozen=True)
class BaselineSnapshot:
    baseline_version: int
    admitted_batch_count: int
    window_batch_count: int
    baseline_profiles: tuple[HostBaseline, ...]


@dataclass(frozen=True)
class BaselineResult:
    baseline_state: Literal["warming", "ready"]
    warmup_required_batches: int
    admitted_batch_count: int
    window_batch_count: int
    baseline_version: int
    previous_baseline_version: int | None
    current_profiles: tuple[HostProfile, ...]
    baseline_profiles: tuple[HostBaseline, ...]


class BaselineAdmissionError(Exception):
    def __init__(self) -> None:
        super().__init__("Baseline batch was not admitted.")


def _ip_sort_key(address: str) -> tuple[int, bytes]:
    parsed = ipaddress.ip_address(address)
    return (parsed.version, parsed.packed)


def build_host_profiles(flows: Iterable[FlowSummary]) -> tuple[HostProfile, ...]:
    by_host: dict[str, list[FlowSummary]] = {}
    for flow in flows:
        endpoints = {
            str(ipaddress.ip_address(flow.source_ip)),
            str(ipaddress.ip_address(flow.destination_ip)),
        }
        for host_ip in endpoints:
            by_host.setdefault(host_ip, []).append(flow)

    profiles: list[HostProfile] = []
    for host_ip in sorted(by_host, key=_ip_sort_key):
        host_flows = by_host[host_ip]
        flow_count = len(host_flows)
        protocols = Counter(flow.protocol.upper() for flow in host_flows)
        profiles.append(
            HostProfile(
                host_ip=host_ip,
                observed_flow_count=flow_count,
                protocol_mix=tuple(
                    ProtocolCount(protocol=protocol, flow_count=count)
                    for protocol, count in sorted(protocols.items())
                ),
                average_bytes_per_flow=round(
                    sum(flow.byte_count for flow in host_flows) / flow_count, 3
                ),
                average_duration_seconds=round(
                    sum(flow.duration_seconds for flow in host_flows) / flow_count,
                    3,
                ),
                average_packets_per_second=round(
                    sum(flow.packets_per_second for flow in host_flows) / flow_count,
                    3,
                ),
            )
        )

    return tuple(profiles)


def _mean(values: Iterable[float]) -> float:
    collected = tuple(values)
    return round(sum(collected) / len(collected), 3)


def _build_baselines(
    batches: Iterable[tuple[HostProfile, ...]],
) -> tuple[HostBaseline, ...]:
    by_host: dict[str, list[HostProfile]] = {}
    for batch in batches:
        for profile in batch:
            by_host.setdefault(profile.host_ip, []).append(profile)

    baselines: list[HostBaseline] = []
    for host_ip in sorted(by_host, key=_ip_sort_key):
        profiles = by_host[host_ip]
        protocol_totals: Counter[str] = Counter()
        for profile in profiles:
            protocol_totals.update(
                {
                    item.protocol: item.flow_count
                    for item in profile.protocol_mix
                }
            )
        observed_batches = len(profiles)
        baselines.append(
            HostBaseline(
                host_ip=host_ip,
                observed_batch_count=observed_batches,
                average_flow_count=_mean(
                    profile.observed_flow_count for profile in profiles
                ),
                protocol_mix=tuple(
                    ProtocolAverage(
                        protocol=protocol,
                        average_flow_count=round(count / observed_batches, 3),
                    )
                    for protocol, count in sorted(protocol_totals.items())
                ),
                average_bytes_per_flow=_mean(
                    profile.average_bytes_per_flow for profile in profiles
                ),
                average_duration_seconds=_mean(
                    profile.average_duration_seconds for profile in profiles
                ),
                average_packets_per_second=_mean(
                    profile.average_packets_per_second for profile in profiles
                ),
            )
        )
    return tuple(baselines)


class InMemoryBaselineStore:
    def __init__(self) -> None:
        self._lock = Lock()
        self._batches: deque[tuple[HostProfile, ...]] = deque(maxlen=5)
        self._admitted_batch_count = 0
        self._current_snapshot: BaselineSnapshot | None = None
        self._previous_snapshot: BaselineSnapshot | None = None

    @property
    def previous_snapshot(self) -> BaselineSnapshot | None:
        return self._previous_snapshot

    def admit_normal_batch(
        self,
        profiles: tuple[HostProfile, ...],
        *,
        fixture_id: str,
    ) -> BaselineResult:
        if fixture_id != "phase3-normal-v1" or not profiles:
            raise BaselineAdmissionError()

        with self._lock:
            self._batches.append(profiles)
            self._admitted_batch_count += 1
            window_count = len(self._batches)

            if self._admitted_batch_count == 1:
                return BaselineResult(
                    baseline_state="warming",
                    warmup_required_batches=2,
                    admitted_batch_count=1,
                    window_batch_count=1,
                    baseline_version=0,
                    previous_baseline_version=None,
                    current_profiles=profiles,
                    baseline_profiles=(),
                )

            baseline_profiles = _build_baselines(self._batches)
            snapshot = BaselineSnapshot(
                baseline_version=self._admitted_batch_count - 1,
                admitted_batch_count=self._admitted_batch_count,
                window_batch_count=window_count,
                baseline_profiles=baseline_profiles,
            )
            if self._current_snapshot is not None:
                self._previous_snapshot = self._current_snapshot
            self._current_snapshot = snapshot

            return BaselineResult(
                baseline_state="ready",
                warmup_required_batches=2,
                admitted_batch_count=self._admitted_batch_count,
                window_batch_count=window_count,
                baseline_version=snapshot.baseline_version,
                previous_baseline_version=(
                    None
                    if self._previous_snapshot is None
                    else self._previous_snapshot.baseline_version
                ),
                current_profiles=profiles,
                baseline_profiles=baseline_profiles,
            )
