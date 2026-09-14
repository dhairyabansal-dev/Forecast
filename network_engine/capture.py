import logging
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from scapy.all import (
    AsyncSniffer,
    IP,
    IPv6,
    TCP,
    UDP,
    get_working_if,
    show_interfaces
)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger(__name__)


class NetworkCapture:

    def __init__(
        self,
        interface: Optional[Any] = None,
        packet_callback: Optional[Callable[[Any], None]] = None,
        packet_limit: int = 1000
    ):
        self.interface = interface
        self.packet_callback = packet_callback
        self.packet_limit = packet_limit

        self.sniffer: Optional[AsyncSniffer] = None
        self.running = False

        self.packet_count = 0
        self.protocol_counts = Counter()

        self.started_at: Optional[datetime] = None
        self.last_packet_at: Optional[datetime] = None

        self.lock = threading.Lock()

    def auto_detect_interface(self) -> Optional[Any]:
        try:
            interface = get_working_if()

            logger.info(
                "Automatically detected working interface: %s",
                interface
            )

            return interface

        except Exception as error:
            logger.exception(
                "Could not automatically detect interface: %s",
                error
            )

            return None

    def _detect_protocol(self, packet: Any) -> str:

        if TCP in packet:
            return "TCP"

        if UDP in packet:
            return "UDP"

        if IP in packet:
            return "IPv4"

        if IPv6 in packet:
            return "IPv6"

        return "OTHER"

    def _handle_packet(self, packet: Any) -> None:

        with self.lock:

            self.packet_count += 1

            protocol = self._detect_protocol(packet)

            self.protocol_counts[protocol] += 1

            self.last_packet_at = datetime.now(timezone.utc)

        if self.packet_callback:

            try:
                self.packet_callback(packet)

            except Exception as error:

                logger.exception(
                    "Packet callback failed: %s",
                    error
                )

    def start(self) -> bool:

        if self.running:

            logger.warning(
                "Packet capture is already running."
            )

            return True

        if self.interface is None:

            self.interface = self.auto_detect_interface()

        if self.interface is None:

            logger.error(
                "No working network interface available."
            )

            return False

        try:

            self.started_at = datetime.now(timezone.utc)

            self.sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self._handle_packet,
                store=False
            )

            self.sniffer.start()

            self.running = True

            logger.info(
                "Network capture started on interface: %s",
                self.interface
            )

            return True

        except Exception as error:

            logger.exception(
                "Failed to start packet capture: %s",
                error
            )

            self.running = False

            return False

    def stop(self) -> None:

        if not self.running:

            return

        try:

            if self.sniffer:

                self.sniffer.stop()

        except Exception as error:

            logger.warning(
                "Error while stopping sniffer: %s",
                error
            )

        finally:

            self.running = False

            logger.info(
                "Network capture stopped. Total packets: %s",
                self.packet_count
            )

    def get_statistics(self) -> dict[str, Any]:

        duration = 0.0

        if self.started_at:

            end_time = (
                datetime.now(timezone.utc)
                if self.running
                else self.last_packet_at
                or datetime.now(timezone.utc)
            )

            duration = (
                end_time - self.started_at
            ).total_seconds()

        packets_per_second = (
            self.packet_count / duration
            if duration > 0
            else 0
        )

        return {
            "running": self.running,
            "interface": str(self.interface),
            "packet_count": self.packet_count,
            "protocol_counts": dict(
                self.protocol_counts
            ),
            "started_at": (
                self.started_at.isoformat()
                if self.started_at
                else None
            ),
            "last_packet_at": (
                self.last_packet_at.isoformat()
                if self.last_packet_at
                else None
            ),
            "duration_seconds": round(
                duration,
                2
            ),
            "packets_per_second": round(
                packets_per_second,
                2
            )
        }


def test_capture(
    interface: Optional[Any] = None,
    duration: int = 15
) -> dict[str, Any]:

    capture = NetworkCapture(
        interface=interface,
        packet_limit=100000
    )

    started = capture.start()

    if not started:

        return {
            "success": False,
            "error": "Could not start network capture"
        }

    try:

        logger.info(
            "Capturing network traffic for %s seconds...",
            duration
        )

        time.sleep(duration)

    finally:

        capture.stop()

    return {
        "success": True,
        "statistics": capture.get_statistics()
    }


if __name__ == "__main__":

    print("\nAvailable Network Interfaces:\n")

    show_interfaces()

    print("\nStarting automatic capture test...\n")

    result = test_capture(
        duration=15
    )

    print("\nCapture Result:\n")

    print(result)