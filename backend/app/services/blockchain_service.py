from eth_account import Account
from web3 import Web3

from app.core.config import settings
from app.utils.hashing import hash_json
from app.utils.helpers import utc_now
from app.utils.logger import app_logger

THREAT_EVIDENCE_ABI = [
    {
        "inputs": [{"internalType": "bytes32", "name": "evidenceHash", "type": "bytes32"}],
        "name": "anchorEvidence",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "evidenceHash", "type": "bytes32"}],
        "name": "isAnchored",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
]


class BlockchainService:
    """Anchor evidence content hashes on-chain for tamper-evident storage."""

    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider(settings.BLOCKCHAIN_PROVIDER_URL))
        self._contract = None
        self._account = None

        if settings.BLOCKCHAIN_PRIVATE_KEY:
            try:
                self._account = Account.from_key(settings.BLOCKCHAIN_PRIVATE_KEY)
            except (TypeError, ValueError) as exc:
                app_logger.warning("Invalid blockchain private key; blockchain writes disabled: %s", exc)

    @property
    def contract(self):
        if self._contract is None and settings.THREAT_EVIDENCE_CONTRACT_ADDRESS:
            try:
                address = Web3.to_checksum_address(
                    settings.THREAT_EVIDENCE_CONTRACT_ADDRESS.strip()
                )
            except ValueError as exc:
                app_logger.warning("Invalid blockchain contract address: %s", exc)
                return None

            self._contract = self.w3.eth.contract(
                address=address,
                abi=THREAT_EVIDENCE_ABI,
            )
        return self._contract

    def is_connected(self) -> bool:
        try:
            return self.w3.is_connected()
        except Exception:
            return False

    @staticmethod
    def _hash_bytes(content_hash: str) -> bytes:
        normalized = content_hash.strip().lower()
        if normalized.startswith("0x"):
            normalized = normalized[2:]
        if len(normalized) != 64:
            raise ValueError("Evidence hash must be exactly 64 hexadecimal characters")
        try:
            return bytes.fromhex(normalized)
        except ValueError as exc:
            raise ValueError("Evidence hash must contain only hexadecimal characters") from exc

    def compute_evidence_hash(self, payload: dict) -> str:
        """Return the SHA-256 hex digest stored by the evidence schema."""
        return hash_json(payload)

    def anchor_evidence(self, content_hash: str) -> dict:
        """Submit a transaction anchoring the given content hash on-chain."""
        if self.contract is None:
            raise RuntimeError("Blockchain contract not configured (missing address).")
        if self._account is None:
            raise RuntimeError("Blockchain private key not configured.")

        hash_bytes = self._hash_bytes(content_hash)
        nonce = self.w3.eth.get_transaction_count(self._account.address)
        tx = self.contract.functions.anchorEvidence(hash_bytes).build_transaction({
            "from": self._account.address,
            "nonce": nonce,
            "chainId": settings.BLOCKCHAIN_CHAIN_ID,
            "gas": 200000,
            "gasPrice": self.w3.eth.gas_price,
        })

        signed_tx = self._account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

        app_logger.info(
            f"Evidence anchored on-chain: tx={tx_hash.hex()} block={receipt.blockNumber}"
        )

        return {
            "tx_hash": tx_hash.hex(),
            "block_number": receipt.blockNumber,
            "anchored_at": utc_now(),
        }

    def verify_evidence(self, content_hash: str) -> bool:
        """Check whether a given content hash is anchored on-chain."""
        if self.contract is None:
            raise RuntimeError("Blockchain contract not configured (missing address).")

        hash_bytes = self._hash_bytes(content_hash)
        return self.contract.functions.isAnchored(hash_bytes).call()
