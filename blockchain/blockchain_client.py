import json
from pathlib import Path

from eth_account import Account
from web3 import Web3

ABI_PATH = Path(__file__).parent / "abi" / "ThreatEvidence.json"


class BlockchainClient:
    """
    Low-level Web3 client for the ThreatEvidence contract.
    Used by both the deploy/interact scripts and the backend's BlockchainService.
    """

    def __init__(self, provider_url: str, chain_id: int, private_key: str | None = None):
        self.w3 = Web3(Web3.HTTPProvider(provider_url))
        self.chain_id = chain_id
        self.account = Account.from_key(private_key) if private_key else None

        with open(ABI_PATH, "r") as f:
            self.abi = json.load(f)

    def is_connected(self) -> bool:
        return self.w3.is_connected()

    def get_contract(self, address: str):
        return self.w3.eth.contract(address=Web3.to_checksum_address(address), abi=self.abi)

    def _build_and_send(self, function_call, gas: int = 200000):
        if self.account is None:
            raise RuntimeError("No private key configured for signing transactions.")

        nonce = self.w3.eth.get_transaction_count(self.account.address)
        tx = function_call.build_transaction({
            "from": self.account.address,
            "nonce": nonce,
            "chainId": self.chain_id,
            "gas": gas,
            "gasPrice": self.w3.eth.gas_price,
        })
        signed = self.account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        return tx_hash.hex(), receipt

    def anchor_evidence(self, contract_address: str, evidence_hash_hex: str) -> dict:
        contract = self.get_contract(contract_address)
        hash_bytes = bytes.fromhex(evidence_hash_hex.replace("0x", ""))

        tx_hash, receipt = self._build_and_send(contract.functions.anchorEvidence(hash_bytes))

        return {
            "tx_hash": tx_hash,
            "block_number": receipt["blockNumber"],
            "gas_used": receipt["gasUsed"],
            "status": "success" if receipt["status"] == 1 else "failed",
        }

    def is_anchored(self, contract_address: str, evidence_hash_hex: str) -> bool:
        contract = self.get_contract(contract_address)
        hash_bytes = bytes.fromhex(evidence_hash_hex.replace("0x", ""))
        return contract.functions.isAnchored(hash_bytes).call()

    def get_record(self, contract_address: str, evidence_hash_hex: str) -> dict:
        contract = self.get_contract(contract_address)
        hash_bytes = bytes.fromhex(evidence_hash_hex.replace("0x", ""))
        submitter, timestamp, exists = contract.functions.getRecord(hash_bytes).call()
        return {"submitter": submitter, "timestamp": timestamp, "exists": exists}

    def get_total_records(self, contract_address: str) -> int:
        contract = self.get_contract(contract_address)
        return contract.functions.totalRecords().call()