from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class IntelligenceRecord:
    """
    A unified record combining IOC extraction, enrichment, and MITRE mapping
    results for a single threat — the object that gets persisted/displayed
    as the final "threat intelligence" summary.
    """
    threat_id: str
    title: str
    severity: str
    iocs: list[str] = field(default_factory=list)
    enrichment_results: list[dict] = field(default_factory=list)
    mitre_techniques: list[dict] = field(default_factory=list)
    dominant_tactic: str | None = None
    kill_chain_stage: str | None = None
    confidence_score: float = 0.0
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "threat_id": self.threat_id,
            "title": self.title,
            "severity": self.severity,
            "iocs": self.iocs,
            "enrichment_results": self.enrichment_results,
            "mitre_techniques": self.mitre_techniques,
            "dominant_tactic": self.dominant_tactic,
            "kill_chain_stage": self.kill_chain_stage,
            "confidence_score": self.confidence_score,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def build(
        cls,
        threat_id: str,
        title: str,
        iocs: list[str],
        enrichment_results: list,
        mitre_techniques: list[dict],
        tactic_classification: dict,
    ) -> "IntelligenceRecord":
        max_confidence = max((t["confidence"] for t in mitre_techniques), default=0.0)
        malicious_ioc_ratio = (
            sum(1 for r in enrichment_results if r.is_known_malicious) / len(enrichment_results)
            if enrichment_results else 0.0
        )
        combined_confidence = round(0.6 * max_confidence + 0.4 * malicious_ioc_ratio, 3)

        severity_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
        severity = severity_map.get(
            tactic_classification.get("kill_chain_stage") and "high" or "medium", "low"
        )

        return cls(
            threat_id=threat_id,
            title=title,
            severity=severity,
            iocs=iocs,
            enrichment_results=[r.__dict__ for r in enrichment_results],
            mitre_techniques=mitre_techniques,
            dominant_tactic=tactic_classification.get("dominant_tactic"),
            kill_chain_stage=tactic_classification.get("kill_chain_stage"),
            confidence_score=combined_confidence,
        )