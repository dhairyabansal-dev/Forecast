from enum import Enum


class ThreatSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnomalyStatus(str, Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"


class ForecastConfidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class MitreTactic(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource-development"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class EvidenceStatus(str, Enum):
    DRAFT = "draft"
    HASHED = "hashed"
    ANCHORED = "anchored"
    VERIFIED = "verified"
    TAMPERED = "tampered"


# Network / feature engineering constants
DEFAULT_FLOW_TIMEOUT_SECONDS = 120
DEFAULT_PACKET_BATCH_SIZE = 1000
MIN_FLOW_PACKETS_FOR_FEATURES = 3

# ML defaults
DEFAULT_ANOMALY_CONTAMINATION = 0.02
DEFAULT_SEQUENCE_LENGTH = 48
DEFAULT_FORECAST_HORIZON = 24
RANDOM_SEED = 42

# API
API_V1_PREFIX = "/api/v1"
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200