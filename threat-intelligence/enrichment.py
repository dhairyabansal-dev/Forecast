from dataclasses import dataclass
from typing import Optional


@dataclass
class EnrichmentResult:
    indicator: str
    indicator_type: str
    reputation_score: float  # 0.0 (benign) - 1.0 (malicious)
    is_known_malicious: bool
    tags: list[str]
    source: str
    raw_context: Optional[dict] = None


class ThreatIntelEnricher:
    """
    Enriches IOCs with reputation/context data. This wraps a local
    known-bad list by default; swap `lookup_fn` for a real feed
    (VirusTotal, AbuseIPDB, MISP, etc.) in production.
    """

    def __init__(self, known_malicious: Optional[dict[str, dict]] = None):
        # known_malicious: {indicator: {"tags": [...], "score": float}}
        self.known_malicious = known_malicious or {}

    def _classify_type(self, indicator: str) -> str:
        if "." in indicator and all(part.isdigit() for part in indicator.split(".") if part):
            return "ip"
        if indicator.startswith(("http://", "https://")):
            return "url"
        if len(indicator) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in indicator):
            return "hash"
        if "@" in indicator:
            return "email"
        return "domain"

    def enrich(self, indicator: str) -> EnrichmentResult:
        indicator_type = self._classify_type(indicator)
        known = self.known_malicious.get(indicator)

        if known:
            return EnrichmentResult(
                indicator=indicator,
                indicator_type=indicator_type,
                reputation_score=known.get("score", 0.9),
                is_known_malicious=True,
                tags=known.get("tags", []),
                source="local_threat_feed",
                raw_context=known,
            )

        return EnrichmentResult(
            indicator=indicator,
            indicator_type=indicator_type,
            reputation_score=0.0,
            is_known_malicious=False,
            tags=[],
            source="local_threat_feed",
        )

    def enrich_batch(self, indicators: list[str]) -> list[EnrichmentResult]:
        return [self.enrich(ioc) for ioc in indicators]

    def add_known_malicious(self, indicator: str, tags: list[str], score: float = 0.9) -> None:
        self.known_malicious[indicator] = {"tags": tags, "score": score}