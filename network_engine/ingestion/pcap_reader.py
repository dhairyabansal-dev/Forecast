from pathlib import Path
from typing import Iterator

from scapy.all import PcapReader, Packet

from ingestion.packet_parser import ParsedPacket, parse_packet


def read_pcap(file_path: str | Path) -> Iterator[Packet]:
    """Stream packets from a pcap file one at a time (memory-efficient for large captures)."""
    with PcapReader(str(file_path)) as reader:
        for pkt in reader:
            yield pkt


def read_and_parse_pcap(file_path: str | Path) -> Iterator[ParsedPacket]:
    """Read a pcap and yield parsed packets, skipping non-IP traffic."""
    for pkt in read_pcap(file_path):
        parsed = parse_packet(pkt)
        if parsed is not None:
            yield parsed


def count_packets(file_path: str | Path) -> int:
    """Count total packets in a pcap without loading everything into memory."""
    count = 0
    for _ in read_pcap(file_path):
        count += 1
    return count


def read_pcap_batch(file_path: str | Path, batch_size: int = 1000) -> Iterator[list[ParsedPacket]]:
    """Yield parsed packets in fixed-size batches, useful for streaming into the feature pipeline."""
    batch = []
    for parsed in read_and_parse_pcap(file_path):
        batch.append(parsed)
        if len(batch) >= batch_size:
            yield batch
            batch = []
    if batch:
        yield batch