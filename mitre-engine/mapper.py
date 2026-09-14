import json
from pathlib import Path

from rules import evaluate_flow_group, evaluate_single_flow

TECHNIQUES_PATH = Path(__file__).parent / "techniques.json"


class MitreMapper:
    """Maps detected flow/behavior indicators to MITRE ATT&CK techniques."""

    def __init__(self, techniques_path: str | Path = TECHNIQUES_PATH):
        with open(techniques_path, "r") as f:
            self.techniques: dict = json.load(f)

    def match_indicators(self, indicators: set[str]) -> list[dict]:
        """Return techniques whose indicator set overlaps with the detected indicators."""
        matches = []
        for technique_id, info in self.techniques.items():
            technique_indicators = set(info.get("indicators", []))
            matched = indicators & technique_indicators

            if matched:
                confidence = len(matched) / len(technique_indicators)
                matches.append({
                    "technique_id": technique_id,
                    "technique_name": info["name"],
                    "tactic": info["tactic"],
                    "confidence": round(confidence, 3),
                    "matched_indicators": sorted(matched),
                })

        return sorted(matches, key=lambda m: m["confidence"], reverse=True)

    def map_flow(self, flow: dict, flow_group: list[dict] | None = None) -> list[dict]:
        """
        Analyze a single flow (optionally with its broader conversation group)
        and return matched MITRE techniques ranked by confidence.
        """
        indicators = evaluate_single_flow(flow)
        if flow_group:
            indicators |= evaluate_flow_group(flow_group)

        return self.match_indicators(indicators)

    def map_anomaly_batch(self, flows: list[dict]) -> dict[str, list[dict]]:
        """
        Group flows by (src_ip, dst_ip) conversation and map each group,
        returning results keyed by flow_id.
        """
        from collections import defaultdict

        groups: dict[tuple, list[dict]] = defaultdict(list)
        for flow in flows:
            key = (flow.get("src_ip"), flow.get("dst_ip"))
            groups[key].append(flow)

        results = {}
        for group_flows in groups.values():
            for flow in group_flows:
                mapped = self.map_flow(flow, flow_group=group_flows)
                if mapped:
                    results[flow.get("flow_id")] = mapped

        return results