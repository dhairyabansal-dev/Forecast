from datetime import datetime
from typing import Optional

from eth_account import Account
from web3 import Web3

from app.core.config import settings
from app.utils.hashing import hash_json
from app.utils.helpers import utc_now
from app.utils.logger import app_logger

# Minimal ABI for the ThreatEvidence contract: anchor(bytes32) and getRecord(bytes32)
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
    """Anchors evidence content hashes on-chain for tamper-evident storage."""

    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider(settings.BLOCKCHAIN_PROVIDER_URL))
        self._contract = None
        self._account = None

        if settings.BLOCKCHAIN_PRIVATE_KEY:
            self._account = Account.from_key(settings.BLOCKCHAIN_PRIVATE_KEY)

    @property
    def contract(self):
        if self._contract is None and settings.THREAT_EVIDENCE_CONTRACT_ADDRESS:
            self._contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(settings.THREAT_EVIDENCE_CONTRACT_ADDRESS),
                abi=THREAT_EVIDENCE_ABI,
            )
        return self._contract

    def is_connected(self) -> bool:
        try:
            return self.w3.is_connected()
        except Exception:
            return False

    def compute_evidence_hash(self, payload: dict) -> str:
        """Returns the 64-character SHA-256 hex digest stored by the evidence schema."""
        return hash_json(payload)

    def anchor_evidence(self, content_hash: str) -> dict:
        """
        Submit a transaction anchoring the given content hash on-chain.
        Returns tx_hash, block_number, anchored_at. Requires contract + private key configured.
        """
        if self.contract is None:
            raise RuntimeError("Blockchain contract not configured (missing address).")
        if self._account is None:
            raise RuntimeError("Blockchain private key not configured.")

        hash_bytes = bytes.fromhex(content_hash.replace("0x", ""))

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

        app_logger.info(f"Evidence anchored on-chain: tx={tx_hash.hex()} block={receipt.blockNumber}")

        return {
            "tx_hash": tx_hash.hex(),
            "block_number": receipt.blockNumber,
            "anchored_at": utc_now(),
        }

    def verify_evidence(self, content_hash: str) -> bool:
        """Check whether a given content hash is anchored on-chain."""
        if self.contract is None:
            raise RuntimeError("Blockchain contract not configured (missing address).")

        hash_bytes = bytes.fromhex(content_hash.replace("0x", ""))
        return self.contract.functions.isAnchored(hash_bytes).call()