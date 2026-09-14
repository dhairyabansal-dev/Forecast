import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from scapy.all import IP, IPv6, TCP, UDP


@dataclass
class NetworkFlow:

    flow_id: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str

    first_seen: datetime
    last_seen: datetime

    packet_count: int = 0
    byte_count: int = 0

    forward_packets: int = 0
    reverse_packets: int = 0

    forward_bytes: int = 0
    reverse_bytes: int = 0

    packet_sizes: list[int] = field(default_factory=list)
    timestamps: list[float] = field(default_factory=list)

    tcp_flags: dict[str, int] = field(
        default_factory=lambda: {
            "SYN": 0,
            "ACK": 0,
            "FIN": 0,
            "RST": 0,
            "PSH": 0,
            "URG": 0
        }
    )

    def duration_seconds(self) -> float:

        duration = (
            self.last_seen - self.first_seen
        ).total_seconds()

        return max(duration, 0.0)

    def packets_per_second(self) -> float:

        duration = self.duration_seconds()

        if duration <= 0:
            return float(self.packet_count)

        return self.packet_count / duration

    def bytes_per_second(self) -> float:

        duration = self.duration_seconds()

        if duration <= 0:
            return float(self.byte_count)

        return self.byte_count / duration


class FlowTracker:

    def __init__(
        self,
        flow_timeout: int = 120
    ):
        self.flow_timeout = flow_timeout

        self.flows: dict[str, NetworkFlow] = {}

    def _get_packet_addresses(
        self,
        packet: Any
    ) -> Optional[tuple[str, str]]:

        if IP in packet:

            return (
                packet[IP].src,
                packet[IP].dst
            )

        if IPv6 in packet:

            return (
                packet[IPv6].src,
                packet[IPv6].dst
            )

        return None

    def _get_protocol_and_ports(
        self,
        packet: Any
    ) -> Optional[tuple[str, int, int]]:

        if TCP in packet:

            return (
                "TCP",
                int(packet[TCP].sport),
                int(packet[TCP].dport)
            )

        if UDP in packet:

            return (
                "UDP",
                int(packet[UDP].sport),
                int(packet[UDP].dport)
            )

        return (
            "OTHER",
            0,
            0
        )

    def _create_flow_key(
        self,
        source_ip: str,
        destination_ip: str,
        source_port: int,
        destination_port: int,
        protocol: str
    ) -> tuple[str, bool]:

        endpoint_a = (
            source_ip,
            source_port
        )

        endpoint_b = (
            destination_ip,
            destination_port
        )

        if endpoint_a <= endpoint_b:

            forward = True

            flow_id = (
                f"{source_ip}:{source_port}"
                f"-{destination_ip}:{destination_port}"
                f"-{protocol}"
            )

        else:

            forward = False

            flow_id = (
                f"{destination_ip}:{destination_port}"
                f"-{source_ip}:{source_port}"
                f"-{protocol}"
            )

        return flow_id, forward

    def _update_tcp_flags(
        self,
        flow: NetworkFlow,
        packet: Any
    ) -> None:

        if TCP not in packet:
            return

        flags = packet[TCP].flags

        if flags & 0x02:
            flow.tcp_flags["SYN"] += 1

        if flags & 0x10:
            flow.tcp_flags["ACK"] += 1

        if flags & 0x01:
            flow.tcp_flags["FIN"] += 1

        if flags & 0x04:
            flow.tcp_flags["RST"] += 1

        if flags & 0x08:
            flow.tcp_flags["PSH"] += 1

        if flags & 0x20:
            flow.tcp_flags["URG"] += 1

    def process_packet(
        self,
        packet: Any
    ) -> Optional[NetworkFlow]:

        addresses = self._get_packet_addresses(packet)

        if not addresses:
            return None

        source_ip, destination_ip = addresses

        protocol_data = (
            self._get_protocol_and_ports(packet)
        )

        if not protocol_data:
            return None

        protocol, source_port, destination_port = protocol_data

        flow_id, forward = self._create_flow_key(
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol
        )

        now = datetime.now(timezone.utc)

        packet_size = len(packet)

        if flow_id not in self.flows:

            self.flows[flow_id] = NetworkFlow(
                flow_id=flow_id,
                source_ip=source_ip,
                destination_ip=destination_ip,
                source_port=source_port,
                destination_port=destination_port,
                protocol=protocol,
                first_seen=now,
                last_seen=now
            )

        flow = self.flows[flow_id]

        flow.last_seen = now

        flow.packet_count += 1

        flow.byte_count += packet_size

        flow.packet_sizes.append(packet_size)

        flow.timestamps.append(
            time.time()
        )

        if forward:

            flow.forward_packets += 1

            flow.forward_bytes += packet_size

        else:

            flow.reverse_packets += 1

            flow.reverse_bytes += packet_size

        self._update_tcp_flags(
            flow,
            packet
        )

        return flow

    def get_active_flows(
        self
    ) -> list[NetworkFlow]:

        return list(
            self.flows.values()
        )

    def get_expired_flows(
        self
    ) -> list[NetworkFlow]:

        now = datetime.now(timezone.utc)

        expired_flows = []

        for flow in self.flows.values():

            idle_time = (
                now - flow.last_seen
            ).total_seconds()

            if idle_time >= self.flow_timeout:

                expired_flows.append(
                    flow
                )

        return expired_flows

    def remove_expired_flows(
        self
    ) -> list[NetworkFlow]:

        expired_flows = self.get_expired_flows()

        for flow in expired_flows:

            if flow.flow_id in self.flows:

                del self.flows[
                    flow.flow_id
                ]

        return expired_flows

    def get_flow(
        self,
        flow_id: str
    ) -> Optional[NetworkFlow]:

        return self.flows.get(
            flow_id
        )

    def get_summary(
        self
    ) -> dict[str, Any]:

        total_packets = sum(
            flow.packet_count
            for flow in self.flows.values()
        )

        total_bytes = sum(
            flow.byte_count
            for flow in self.flows.values()
        )

        protocols: dict[str, int] = {}

        for flow in self.flows.values():

            protocols[flow.protocol] = (
                protocols.get(
                    flow.protocol,
                    0
                )
                + 1
            )

        return {
            "active_flows": len(self.flows),
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "protocols": protocols
        }