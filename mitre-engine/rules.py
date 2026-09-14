"""
Heuristic rules that map raw flow/anomaly signals to MITRE ATT&CK indicator tags.
Each rule inspects flow features and returns a set of matched indicator strings,
which the mapper then cross-references against techniques.json.
"""

from typing import Callable

Rule = Callable[[dict], bool]


def is_port_scan(flow: dict) -> bool:
    return flow.get("packet_count", 0) < 5 and flow.get("duration_seconds", 0) < 1.0


def is_high_connection_rate(flow: dict) -> bool:
    return flow.get("packets_per_second", 0) > 100


def is_sequential_ports(flow_group: list[dict]) -> bool:
    ports = sorted(f.get("dst_port", 0) for f in flow_group if f.get("dst_port") is not None)
    if len(ports) < 3:
        return False
    diffs = [ports[i + 1] - ports[i] for i in range(len(ports) - 1)]
    return sum(1 for d in diffs if d == 1) / len(diffs) > 0.6


def is_large_outbound_transfer(flow: dict) -> bool:
    return flow.get("src_bytes", 0) > 50_000_000  # 50 MB+


def is_asymmetric_byte_ratio(flow: dict) -> bool:
    src, dst = flow.get("src_bytes", 0), flow.get("dst_bytes", 1)
    ratio = src / (dst + 1e-6)
    return ratio > 10 or ratio < 0.1


def is_beaconing(flow_group: list[dict]) -> bool:
    """Detect regular, periodic connection intervals typical of C2 beaconing."""
    if len(flow_group) < 5:
        return False
    starts = sorted(f.get("start_time", 0) for f in flow_group)
    intervals = [starts[i + 1] - starts[i] for i in range(len(starts) - 1)]
    if not intervals:
        return False
    mean_interval = sum(intervals) / len(intervals)
    variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
    std_dev = variance ** 0.5
    return mean_interval > 0 and (std_dev / mean_interval) < 0.2  # low variance = periodic


def is_volumetric_traffic(flow: dict) -> bool:
    return flow.get("bytes_per_second", 0) > 10_000_000  # 10 MB/s+


def is_syn_flood(flow: dict) -> bool:
    return flow.get("protocol") == "TCP" and flow.get("flags", "") == "S" and flow.get("packet_count", 0) > 100


def is_repeated_auth_attempts(flow_group: list[dict]) -> bool:
    auth_ports = {21, 22, 23, 3389, 445}
    relevant = [f for f in flow_group if f.get("dst_port") in auth_ports]
    return len(relevant) > 10


def is_internal_lateral_traffic(flow: dict) -> bool:
    def is_private(ip: str) -> bool:
        return ip.startswith(("10.", "172.16.", "192.168."))
    return is_private(flow.get("src_ip", "")) and is_private(flow.get("dst_ip", ""))


def is_high_dns_query_rate(flow_group: list[dict]) -> bool:
    dns_flows = [f for f in flow_group if f.get("dst_port") == 53]
    return len(dns_flows) > 50


SINGLE_FLOW_RULES: dict[str, Rule] = {
    "port_scan": is_port_scan,
    "high_connection_rate": is_high_connection_rate,
    "large_outbound_transfer": is_large_outbound_transfer,
    "asymmetric_byte_ratio": is_asymmetric_byte_ratio,
    "volumetric_traffic": is_volumetric_traffic,
    "syn_flood": is_syn_flood,
    "internal_lateral_traffic": is_internal_lateral_traffic,
}

GROUP_RULES: dict[str, Callable[[list[dict]], bool]] = {
    "sequential_ports": is_sequential_ports,
    "beaconing": is_beaconing,
    "repeated_auth_attempts": is_repeated_auth_attempts,
    "high_dns_query_rate": is_high_dns_query_rate,
}


def evaluate_single_flow(flow: dict) -> set[str]:
    return {name for name, rule in SINGLE_FLOW_RULES.items() if rule(flow)}


def evaluate_flow_group(flow_group: list[dict]) -> set[str]:
    return {name for name, rule in GROUP_RULES.items() if rule(flow_group)}