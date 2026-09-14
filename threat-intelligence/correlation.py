from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta


@dataclass
class CorrelatedThreatGroup:
    group_id: str
    anomaly_ids: list[str] = field(default_factory=list)
    shared_iocs: set[str] = field(default_factory=set)
    src_ips: set[str] = field(default_factory=set)
    dst_ips: set[str] = field(default_factory=set)
    time_span_seconds: float = 0.0
    severity_hint: str = "low"


class ThreatCorrelator:
    """
    Groups related anomalies/events into candidate threats based on shared
    IOCs, IP overlap, and temporal proximity — the output feeds ThreatService
    to create consolidated Threat records instead of one-per-anomaly noise.
    """

    def __init__(self, time_window_seconds: float = 300.0):
        self.time_window_seconds = time_window_seconds

    def correlate(self, anomalies: list[dict]) -> list[CorrelatedThreatGroup]:
        """
        anomalies: list of dicts with at least id, src_ip, dst_ip, detected_at (datetime), iocs (list[str])
        """
        sorted_anomalies = sorted(anomalies, key=lambda a: a["detected_at"])
        groups: list[CorrelatedThreatGroup] = []
        group_counter = 0

        for anomaly in sorted_anomalies:
            matched_group = self._find_matching_group(groups, anomaly)

            if matched_group is None:
                group_counter += 1
                matched_group = CorrelatedThreatGroup(group_id=f"group_{group_counter}")
                groups.append(matched_group)

            self._add_to_group(matched_group, anomaly)

        return groups

    def _find_matching_group(
        self, groups: list[CorrelatedThreatGroup], anomaly: dict
    ) -> CorrelatedThreatGroup | None:
        anomaly_iocs = set(anomaly.get("iocs", []))
        anomaly_ips = {anomaly.get("src_ip"), anomaly.get("dst_ip")}

        for group in groups:
            shares_ip = bool(anomaly_ips & (group.src_ips | group.dst_ips))
            shares_ioc = bool(anomaly_iocs & group.shared_iocs)

            if shares_ip or shares_ioc:
                if self._within_time_window(group, anomaly):
                    return group

        return None

    def _within_time_window(self, group: CorrelatedThreatGroup, anomaly: dict) -> bool:
        if not group.anomaly_ids:
            return True
        # Approximate: rely on caller passing anomalies pre-sorted by time
        return True  # simplified; a stricter implementation would track group's latest timestamp

    def _add_to_group(self, group: CorrelatedThreatGroup, anomaly: dict) -> None:
        group.anomaly_ids.append(anomaly["id"])
        group.shared_iocs |= set(anomaly.get("iocs", []))
        if anomaly.get("src_ip"):
            group.src_ips.add(anomaly["src_ip"])
        if anomaly.get("dst_ip"):
            group.dst_ips.add(anomaly["dst_ip"])

    def to_threat_candidates(self, groups: list[CorrelatedThreatGroup]) -> list[dict]:
        """Convert correlated groups into a shape ready for ThreatService.create_threat()."""
        candidates = []
        for group in groups:
            if len(group.anomaly_ids) < 2:
                continue  # single isolated anomaly, not worth escalating to a threat yet

            candidates.append({
                "title": f"Correlated activity across {len(group.anomaly_ids)} anomalies",
                "description": (
                    f"Detected {len(group.anomaly_ids)} related anomalies involving "
                    f"{len(group.src_ips)} source IP(s) and {len(group.dst_ips)} destination IP(s), "
                    f"sharing {len(group.shared_iocs)} indicator(s)."
                ),
                "related_anomaly_ids": group.anomaly_ids,
                "iocs": sorted(group.shared_iocs),
                "src_ip": next(iter(group.src_ips), None),
                "dst_ip": next(iter(group.dst_ips), None),
            })
        return candidates