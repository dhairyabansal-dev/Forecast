from dataclasses import dataclass, field
from typing import Optional

from scapy.all import IP, TCP, UDP, Packet


@dataclass
class ParsedPacket:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    length: int
    flags: Optional[str] = None
    ttl: Optional[int] = None
    payload_size: int = 0


def parse_packet(pkt: Packet) -> Optional[ParsedPacket]:
    """Extract relevant fields from a raw scapy packet. Returns None if not IP traffic."""
    if not pkt.haslayer(IP):
        return None

    ip_layer = pkt[IP]
    timestamp = float(pkt.time)
    length = len(pkt)

    src_port = dst_port = None
    protocol = "OTHER"
    flags = None
    payload_size = 0

    if pkt.haslayer(TCP):
        tcp_layer = pkt[TCP]
        protocol = "TCP"
        src_port = int(tcp_layer.sport)
        dst_port = int(tcp_layer.dport)
        flags = str(tcp_layer.flags)
        payload_size = len(tcp_layer.payload)
    elif pkt.haslayer(UDP):
        udp_layer = pkt[UDP]
        protocol = "UDP"
        src_port = int(udp_layer.sport)
        dst_port = int(udp_layer.dport)
        payload_size = len(udp_layer.payload)

    return ParsedPacket(
        timestamp=timestamp,
        src_ip=ip_layer.src,
        dst_ip=ip_layer.dst,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        length=length,
        flags=flags,
        ttl=int(ip_layer.ttl),
        payload_size=payload_size,
    )


def parse_packets(packets: list[Packet]) -> list[ParsedPacket]:
    parsed = []
    for pkt in packets:
        result = parse_packet(pkt)
        if result is not None:
            parsed.append(result)
    return parsed