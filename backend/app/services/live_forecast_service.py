import asyncio
import sys
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
NETWORK_ENGINE_DIR = PROJECT_ROOT / "network_engine"
MITRE_ENGINE_DIR = PROJECT_ROOT / "mitre-engine"
THREAT_INTELLIGENCE_DIR = PROJECT_ROOT / "threat-intelligence"
for module_path in (NETWORK_ENGINE_DIR, MITRE_ENGINE_DIR, THREAT_INTELLIGENCE_DIR):
    if str(module_path) not in sys.path:
        sys.path.insert(0, str(module_path))

from app.core.constants import ForecastConfidence
from app.database.connection import get_db_context
from app.database.repositories.anomaly_repository import AnomalyRepository
from app.database.repositories.evidence_repository import EvidenceRepository
from app.database.repositories.forecast_repository import ForecastRepository
from app.database.repositories.threat_repository import ThreatRepository
from app.models.anomaly import Anomaly
from app.models.evidence import Evidence
from app.models.forecast import Forecast
from app.services.blockchain_service import BlockchainService
from app.services.detection_service import DetectionService
from app.services.threat_service import ThreatService
from app.core.constants import EvidenceStatus
from app.utils.helpers import utc_now

from network_engine.capture import NetworkCapture
from feature_extractor import FeatureExtractor
from network_engine.flow_tracker import FlowTracker
from network_engine.state_bridge import flows_to_state_trajectory
from ml_engine.world_model.attack_stage_mapper import map_rollout_to_stages
from ml_engine.world_model.explainability import perturbation_attribution
from ml_engine.world_model.state_representation import STATE_DIM, STATE_DIMENSIONS
from ml_engine.world_model.state_transition_model import rollout_k_steps
from scripts.live_world_model_demo import load_trained_model
from mapper import MitreMapper
from tactic_classifier import TacticClassifier
from correlation import ThreatCorrelator
from ioc_extractor import extract_iocs_from_flow


class LiveForecastService:
    def __init__(self) -> None:
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="live-forecast")
        self._lock = threading.Lock()
        self._jobs: dict[str, dict[str, Any]] = {}
        self._future: Optional[Future] = None

    def start(
        self,
        duration_seconds: int,
        forecast_steps: int,
        window_size: int,
        network_segment: Optional[str],
        packet_limit: int,
        loop: asyncio.AbstractEventLoop,
    ) -> str:
        with self._lock:
            if self._future is not None and not self._future.done():
                raise RuntimeError("A live forecast capture is already running")

            job_id = str(uuid4())
            self._jobs[job_id] = {"status": "queued", "forecast_id": None, "error": None}
            self._future = self._executor.submit(
                self._run_job,
                job_id,
                duration_seconds,
                forecast_steps,
                window_size,
                network_segment,
                packet_limit,
                loop,
            )
            return job_id

    def get_status(self, job_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            status = self._jobs.get(job_id)
            return dict(status) if status is not None else None

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)

    def _set_status(self, job_id: str, **values: Any) -> None:
        with self._lock:
            self._jobs[job_id].update(values)

    def _capture(self, duration_seconds: int, packet_limit: int) -> list:
        tracker = FlowTracker()
        capture = NetworkCapture(
            packet_callback=tracker.process_packet,
            packet_limit=packet_limit,
        )

        if not capture.start():
            raise RuntimeError("Live network capture could not be started")

        try:
            time.sleep(duration_seconds)
        finally:
            capture.stop()

        flows = tracker.get_active_flows()
        if not flows:
            raise RuntimeError("Live capture completed without usable network flows")
        return flows

    def _run_job(
        self,
        job_id: str,
        duration_seconds: int,
        forecast_steps: int,
        window_size: int,
        network_segment: Optional[str],
        packet_limit: int,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        try:
            self._set_status(job_id, status="capturing")
            flows = self._capture(duration_seconds, packet_limit)
            detection_error = None
            try:
                detection_data = self._score_flows(flows)
            except Exception as exc:
                detection_data = {"records": [], "mapped": {}}
                detection_error = f"Detection pipeline unavailable: {exc}"
            trajectory = flows_to_state_trajectory(flows)
            if trajectory.ndim != 2 or trajectory.shape[1] != STATE_DIM:
                raise ValueError(
                    f"Live trajectory must have shape (n, {STATE_DIM}), received {trajectory.shape}"
                )

            actual_window_size = min(window_size, len(trajectory))
            if actual_window_size < 2:
                raise RuntimeError("Live capture did not produce enough trajectory steps")

            self._set_status(job_id, status="forecasting")
            model = load_trained_model()
            window = trajectory[-actual_window_size:]
            predicted_states, risk_scores = rollout_k_steps(
                model,
                window,
                k=forecast_steps,
            )
            stages = map_rollout_to_stages(predicted_states)
            attributions = perturbation_attribution(model, window, k=1)

            now = utc_now()
            points = []
            for index, (risk, stage) in enumerate(zip(risk_scores, stages)):
                point_time = now + timedelta(hours=index + 1)
                points.append({
                    "timestamp": point_time.isoformat(),
                    "predicted_threat_level": float(np.clip(risk, 0.0, 1.0)),
                    "lower_bound": float(np.clip(risk - 0.05, 0.0, 1.0)),
                    "upper_bound": float(np.clip(risk + 0.05, 0.0, 1.0)),
                    "predicted_stage": stage["predicted_stage"],
                    "stage_confidence": float(stage["confidence"]),
                    "explainability": {
                        name: float(value) for name, value in attributions.items()
                    },
                })

            mean_confidence = float(np.mean([point["stage_confidence"] for point in points]))
            confidence = (
                ForecastConfidence.HIGH
                if mean_confidence >= 0.75
                else ForecastConfidence.MEDIUM
                if mean_confidence >= 0.5
                else ForecastConfidence.LOW
            )
            peak_index = int(np.argmax(risk_scores))
            forecast = Forecast(
                network_segment=network_segment,
                horizon_hours=forecast_steps,
                sequence_length=actual_window_size,
                confidence=confidence.value,
                model_version="network-world-model-v1",
                points=points,
                peak_threat_level=float(risk_scores[peak_index]),
                peak_timestamp=now + timedelta(hours=peak_index + 1),
                generated_at=now,
            )

            self._set_status(job_id, status="persisting")
            persistence = asyncio.run_coroutine_threadsafe(
                self._persist(forecast, detection_data),
                loop,
            )
            forecast_id = persistence.result()
            self._set_status(
                job_id,
                status="completed",
                forecast_id=forecast_id,
                error=detection_error,
            )
        except Exception as exc:
            self._set_status(job_id, status="failed", error=str(exc))

    def _score_flows(self, flows: list) -> dict[str, Any]:
        extractor = FeatureExtractor()
        detector = DetectionService(None)
        flow_records = []

        for flow in flows:
            raw_features = extractor.extract(flow)
            feature_vector = extractor.extract_vector(flow)
            flow_dict = {
                "flow_id": flow.flow_id,
                "src_ip": flow.source_ip,
                "dst_ip": flow.destination_ip,
                "src_port": flow.source_port,
                "dst_port": flow.destination_port,
                "protocol": flow.protocol,
                "packet_count": flow.packet_count,
                "duration_seconds": flow.duration_seconds(),
                "packets_per_second": flow.packets_per_second(),
                "bytes_per_second": flow.bytes_per_second(),
                "src_bytes": flow.forward_bytes,
                "dst_bytes": flow.reverse_bytes,
                "flags": "S" if flow.tcp_flags["SYN"] else "",
                "dst_port": flow.destination_port,
                "start_time": flow.timestamps[0] if flow.timestamps else 0.0,
            }
            iocs = extract_iocs_from_flow(flow_dict).all_iocs()
            score, is_anomalous = detector.score_features(feature_vector)
            flow_records.append({
                "flow": flow_dict,
                "feature_vector": feature_vector,
                "raw_features": raw_features,
                "score": score,
                "is_anomalous": is_anomalous,
                "iocs": iocs,
            })

        anomalous_flows = [record for record in flow_records if record["is_anomalous"]]
        mapper = MitreMapper()
        mapped = mapper.map_anomaly_batch([record["flow"] for record in anomalous_flows])
        return {
            "records": flow_records,
            "mapped": mapped,
        }

    async def _persist(self, forecast: Forecast, detection_data: dict[str, Any]) -> str:
        async with get_db_context() as session:
            anomaly_repo = AnomalyRepository(session)
            anomaly_models = [
                Anomaly(
                    flow_id=record["flow"]["flow_id"],
                    src_ip=record["flow"]["src_ip"],
                    dst_ip=record["flow"]["dst_ip"],
                    src_port=record["flow"]["src_port"],
                    dst_port=record["flow"]["dst_port"],
                    protocol=record["flow"]["protocol"],
                    anomaly_score=record["score"],
                    is_anomalous=record["is_anomalous"],
                    raw_features=record["raw_features"],
                    detected_at=utc_now(),
                )
                for record in detection_data["records"]
            ]
            persisted_anomalies = await anomaly_repo.bulk_create(anomaly_models)

            anomalous_records = [
                (record, anomaly)
                for record, anomaly in zip(detection_data["records"], persisted_anomalies)
                if record["is_anomalous"]
            ]
            threat_service = ThreatService(session)
            mitre_classifier = TacticClassifier()
            threat_correlator = ThreatCorrelator()
            correlation_input = [
                {
                    "id": anomaly.id,
                    "src_ip": anomaly.src_ip,
                    "dst_ip": anomaly.dst_ip,
                    "detected_at": anomaly.detected_at,
                    "iocs": record["iocs"],
                }
                for record, anomaly in anomalous_records
            ]
            candidates = threat_correlator.to_threat_candidates(
                threat_correlator.correlate(correlation_input)
            )
            evidence_repo = EvidenceRepository(session)
            blockchain = BlockchainService()
            for candidate in candidates:
                candidate_flow_ids = {
                    anomaly.flow_id
                    for anomaly in persisted_anomalies
                    if anomaly.id in candidate["related_anomaly_ids"]
                }
                techniques = [
                    match
                    for flow_id in candidate_flow_ids
                    for match in detection_data["mapped"].get(flow_id, [])
                ]
                classification = mitre_classifier.classify(techniques)
                if not techniques or not classification["dominant_tactic"]:
                    continue
                top_technique = techniques[0]
                threat = await threat_service.create_threat(
                    title=candidate["title"],
                    description=candidate["description"],
                    severity=mitre_classifier.estimate_severity(techniques),
                    confidence_score=float(top_technique["confidence"]),
                    src_ip=candidate["src_ip"],
                    dst_ip=candidate["dst_ip"],
                    mitre_technique_id=top_technique["technique_id"],
                    mitre_tactic=classification["dominant_tactic"],
                    related_anomaly_ids=candidate["related_anomaly_ids"],
                    iocs=candidate["iocs"],
                )
                evidence_payload = {
                    "threat_id": threat.id,
                    "related_anomaly_ids": candidate["related_anomaly_ids"],
                    "mitre_techniques": techniques,
                    "captured_at": utc_now().isoformat(),
                }
                evidence = Evidence(
                    threat_id=threat.id,
                    title=f"Live capture evidence for {threat.title}",
                    description="Captured flow metadata and detection mappings.",
                    payload=evidence_payload,
                    content_hash=blockchain.compute_evidence_hash(evidence_payload),
                    status=EvidenceStatus.HASHED.value,
                )
                await evidence_repo.create(evidence)
                if blockchain.contract is not None and blockchain._account is not None:
                    result = await asyncio.to_thread(
                        blockchain.anchor_evidence,
                        evidence.content_hash,
                    )
                    await evidence_repo.update(
                        evidence,
                        status=EvidenceStatus.ANCHORED.value,
                        blockchain_tx_hash=result["tx_hash"],
                        blockchain_block_number=result["block_number"],
                        anchored_at=result["anchored_at"],
                    )

            created = await ForecastRepository(session).create(forecast)
            return created.id


live_forecast_service = LiveForecastService()
