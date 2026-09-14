import json
from collections import Counter
from pathlib import Path

TECHNIQUES_PATH = Path(__file__).parent / "techniques.json"


class TacticClassifier:
    """
    Given a set of matched MITRE techniques (from the mapper), determines
    the overall attack tactic/stage a threat most likely represents —
    useful for summarizing threats at a higher level for the dashboard.
    """

    TACTIC_KILL_CHAIN_ORDER = [
        "reconnaissance", "resource-development", "initial-access", "execution",
        "persistence", "privilege-escalation", "defense-evasion", "credential-access",
        "discovery", "lateral-movement", "collection", "command-and-control",
        "exfiltration", "impact",
    ]

    def __init__(self, techniques_path: str | Path = TECHNIQUES_PATH):
        with open(techniques_path, "r") as f:
            self.techniques: dict = json.load(f)

    def classify(self, matched_techniques: list[dict]) -> dict:
        """
        matched_techniques: output from MitreMapper.match_indicators / map_flow
        Returns the dominant tactic plus a breakdown of tactic frequency and
        the furthest kill-chain stage reached (useful for severity estimation).
        """
        if not matched_techniques:
            return {"dominant_tactic": None, "tactic_breakdown": {}, "kill_chain_stage": None}

        tactics = [t["tactic"] for t in matched_techniques]
        tactic_counts = Counter(tactics)
        dominant_tactic = tactic_counts.most_common(1)[0][0]

        # Furthest stage reached in the kill chain = highest severity indicator
        stage_indices = [
            self.TACTIC_KILL_CHAIN_ORDER.index(t)
            for t in tactics
            if t in self.TACTIC_KILL_CHAIN_ORDER
        ]
        furthest_stage = (
            self.TACTIC_KILL_CHAIN_ORDER[max(stage_indices)] if stage_indices else None
        )

        return {
            "dominant_tactic": dominant_tactic,
            "tactic_breakdown": dict(tactic_counts),
            "kill_chain_stage": furthest_stage,
        }

    def estimate_severity(self, matched_techniques: list[dict]) -> str:
        """Rough severity heuristic based on kill-chain progression and confidence."""
        if not matched_techniques:
            return "low"

        classification = self.classify(matched_techniques)
        stage = classification["kill_chain_stage"]
        max_confidence = max(t["confidence"] for t in matched_techniques)

        late_stage_tactics = {"exfiltration", "impact", "command-and-control", "lateral-movement"}

        if stage in late_stage_tactics and max_confidence > 0.5:
            return "critical"
        elif stage in late_stage_tactics or max_confidence > 0.6:
            return "high"
        elif max_confidence > 0.3:
            return "medium"
        return "low"