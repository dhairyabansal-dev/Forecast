import uuid
from dataclasses import dataclass, field

from ingestion.packet_parser import ParsedPacket

DEFAULT_FLOW_TIMEOUT_SECONDS = 120


@dataclass
class Flow:
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    start_time: float
    last_time: float
    packet_sizes: list[int] = field(default_factory=list)
    timestamps: list[float] = field(default_factory=list)
    src_bytes: int = 0
    dst_bytes: int = 0
    packet_count: int = 0

    @property
    def duration_seconds(self) -> float:
        return max(self.last_time - self.start_time, 0.0)

    def to_dict(self) -> dict:
        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "duration_seconds": self.duration_seconds,
            "packet_count": self.packet_count,
            "src_bytes": self.src_bytes,
            "dst_bytes": self.dst_bytes,
            "packet_sizes": self.packet_sizes,
            "timestamps": self.timestamps,
        }


class FlowGenerator:
    """
    Groups individual packets into bidirectional flows keyed by the
    5-tuple (src_ip, dst_ip, src_port, dst_port, protocol), normalized
    so A->B and B->A packets belong to the same flow.
    """

    def __init__(self, timeout_seconds: float = DEFAULT_FLOW_TIMEOUT_SECONDS):
        self.timeout_seconds = timeout_seconds
        self._active_flows: dict[tuple, Flow] = {}
        self._completed_flows: list[Flow] = []

    def _flow_key(self, pkt: ParsedPacket) -> tuple:
        endpoints = tuple(sorted([
            (pkt.src_ip, pkt.src_port or 0),
            (pkt.dst_ip, pkt.dst_port or 0),
        ]))
        return (*endpoints, pkt.protocol)

    def process_packet(self, pkt: ParsedPacket) -> None:
        key = self._flow_key(pkt)

        if key in self._active_flows:
            flow = self._active_flows[key]
            if pkt.timestamp - flow.last_time > self.timeout_seconds:
                self._completed_flows.append(flow)
                del self._active_flows[key]
                flow = self._create_flow(key, pkt)
                self._active_flows[key] = flow
        else:
            flow = self._create_flow(key, pkt)
            self._active_flows[key] = flow

        self._update_flow(flow, pkt)

    def _create_flow(self, key: tuple, pkt: ParsedPacket) -> Flow:
        return Flow(
            flow_id=str(uuid.uuid4()),
            src_ip=pkt.src_ip,
            dst_ip=pkt.dst_ip,
            src_port=pkt.src_port,
            dst_port=pkt.dst_port,
            protocol=pkt.protocol,
            start_time=pkt.timestamp,
            last_time=pkt.timestamp,
        )

    def _update_flow(self, flow: Flow, pkt: ParsedPacket) -> None:
        flow.last_time = pkt.timestamp
        flow.packet_count += 1
        flow.packet_sizes.append(pkt.length)
        flow.timestamps.append(pkt.timestamp)

        if pkt.src_ip == flow.src_ip:
            flow.src_bytes += pkt.length
        else:
            flow.dst_bytes += pkt.length

    def process_packets(self, packets: list[ParsedPacket]) -> None:
        for pkt in packets:
            self.process_packet(pkt)

    def finalize(self) -> list[Flow]:
        """Call after all packets processed to flush remaining active flows."""
        self._completed_flows.extend(self._active_flows.values())
        self._active_flows.clear()
        return self._completed_flows

    def get_flows_as_dicts(self) -> list[dict]:
        return [f.to_dict() for f in self.finalize()]