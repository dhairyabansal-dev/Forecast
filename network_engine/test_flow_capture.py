import sys
import time

from capture import NetworkCapture
from flow_tracker import FlowTracker


flow_tracker = FlowTracker(
    flow_timeout=120
)


def handle_packet(packet):

    flow_tracker.process_packet(packet)


def main():

    print("\nStarting live network flow capture...\n")

    capture = NetworkCapture(
        packet_callback=handle_packet,
        packet_limit=100000
    )

    started = capture.start()

    if not started:

        print("Failed to start capture.")

        return

    try:

        print(
            "Capturing traffic for 20 seconds..."
        )

        print(
            "Open some websites while this runs.\n"
        )

        time.sleep(20)

    except KeyboardInterrupt:

        print("\nCapture interrupted.")

    finally:

        capture.stop()

    print("\n========== CAPTURE STATISTICS ==========\n")

    print(
        capture.get_statistics()
    )

    print("\n========== FLOW SUMMARY ==========\n")

    print(
        flow_tracker.get_summary()
    )

    print("\n========== ACTIVE FLOWS ==========\n")

    flows = flow_tracker.get_active_flows()

    for index, flow in enumerate(flows[:10], start=1):

        print(f"\nFlow {index}")

        print(
            f"ID: {flow.flow_id}"
        )

        print(
            f"Protocol: {flow.protocol}"
        )

        print(
            f"Packets: {flow.packet_count}"
        )

        print(
            f"Bytes: {flow.byte_count}"
        )

        print(
            f"Duration: "
            f"{flow.duration_seconds():.2f}s"
        )

        print(
            f"Packets/sec: "
            f"{flow.packets_per_second():.2f}"
        )

    print(
        "\n========================================\n"
    )


if __name__ == "__main__":

    main()