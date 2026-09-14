import math
import statistics
from typing import Any

try:
    from .flow_tracker import NetworkFlow
except ImportError:
    from flow_tracker import NetworkFlow


class FeatureExtractor:

    FEATURE_NAMES = [
        "duration_seconds",
        "packet_count",
        "byte_count",
        "packets_per_second",
        "bytes_per_second",
        "average_packet_size",
        "packet_size_std",
        "min_packet_size",
        "max_packet_size",
        "forward_packet_ratio",
        "reverse_packet_ratio",
        "forward_byte_ratio",
        "reverse_byte_ratio",
        "syn_count",
        "ack_count",
        "fin_count",
        "rst_count",
        "psh_count",
        "urg_count",
        "interarrival_mean",
        "interarrival_std",
        "source_port",
        "destination_port",
        "protocol_tcp",
        "protocol_udp"
    ]

    def _safe_divide(
        self,
        numerator: float,
        denominator: float
    ) -> float:

        if denominator == 0:
            return 0.0

        return numerator / denominator

    def _packet_size_statistics(
        self,
        flow: NetworkFlow
    ) -> dict[str, float]:

        sizes = flow.packet_sizes

        if not sizes:

            return {
                "average": 0.0,
                "std": 0.0,
                "min": 0.0,
                "max": 0.0
            }

        average = statistics.mean(sizes)

        std = (
            statistics.stdev(sizes)
            if len(sizes) > 1
            else 0.0
        )

        return {
            "average": float(average),
            "std": float(std),
            "min": float(min(sizes)),
            "max": float(max(sizes))
        }

    def _interarrival_statistics(
        self,
        flow: NetworkFlow
    ) -> dict[str, float]:

        timestamps = flow.timestamps

        if len(timestamps) < 2:

            return {
                "mean": 0.0,
                "std": 0.0
            }

        intervals = []

        for index in range(
            1,
            len(timestamps)
        ):

            interval = (
                timestamps[index]
                - timestamps[index - 1]
            )

            intervals.append(
                max(interval, 0.0)
            )

        mean_interval = statistics.mean(
            intervals
        )

        std_interval = (
            statistics.stdev(intervals)
            if len(intervals) > 1
            else 0.0
        )

        return {
            "mean": float(mean_interval),
            "std": float(std_interval)
        }

    def extract(
        self,
        flow: NetworkFlow
    ) -> dict[str, Any]:

        packet_stats = (
            self._packet_size_statistics(flow)
        )

        interarrival_stats = (
            self._interarrival_statistics(flow)
        )

        total_packets = flow.packet_count

        total_bytes = flow.byte_count

        protocol_tcp = (
            1.0
            if flow.protocol == "TCP"
            else 0.0
        )

        protocol_udp = (
            1.0
            if flow.protocol == "UDP"
            else 0.0
        )

        features = {
            "duration_seconds": float(
                flow.duration_seconds()
            ),

            "packet_count": float(
                total_packets
            ),

            "byte_count": float(
                total_bytes
            ),

            "packets_per_second": float(
                flow.packets_per_second()
            ),

            "bytes_per_second": float(
                flow.bytes_per_second()
            ),

            "average_packet_size": (
                packet_stats["average"]
            ),

            "packet_size_std": (
                packet_stats["std"]
            ),

            "min_packet_size": (
                packet_stats["min"]
            ),

            "max_packet_size": (
                packet_stats["max"]
            ),

            "forward_packet_ratio": (
                self._safe_divide(
                    flow.forward_packets,
                    total_packets
                )
            ),

            "reverse_packet_ratio": (
                self._safe_divide(
                    flow.reverse_packets,
                    total_packets
                )
            ),

            "forward_byte_ratio": (
                self._safe_divide(
                    flow.forward_bytes,
                    total_bytes
                )
            ),

            "reverse_byte_ratio": (
                self._safe_divide(
                    flow.reverse_bytes,
                    total_bytes
                )
            ),

            "syn_count": float(
                flow.tcp_flags["SYN"]
            ),

            "ack_count": float(
                flow.tcp_flags["ACK"]
            ),

            "fin_count": float(
                flow.tcp_flags["FIN"]
            ),

            "rst_count": float(
                flow.tcp_flags["RST"]
            ),

            "psh_count": float(
                flow.tcp_flags["PSH"]
            ),

            "urg_count": float(
                flow.tcp_flags["URG"]
            ),

            "interarrival_mean": (
                interarrival_stats["mean"]
            ),

            "interarrival_std": (
                interarrival_stats["std"]
            ),

            "source_port": float(
                flow.source_port
            ),

            "destination_port": float(
                flow.destination_port
            ),

            "protocol_tcp": protocol_tcp,

            "protocol_udp": protocol_udp
        }

        return features

    def extract_vector(
        self,
        flow: NetworkFlow
    ) -> list[float]:

        features = self.extract(flow)

        return [
            float(features[name])
            for name in self.FEATURE_NAMES
        ]

    def extract_many(
        self,
        flows: list[NetworkFlow]
    ) -> list[list[float]]:

        return [
            self.extract_vector(flow)
            for flow in flows
        ]

    def get_feature_names(
        self
    ) -> list[str]:

        return self.FEATURE_NAMES.copy()