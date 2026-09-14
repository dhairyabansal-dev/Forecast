import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "backend"))

from eth_account import Account
from solcx import compile_source, install_solc
from web3 import Web3

CONTRACT_PATH = Path(__file__).parent.parent / "contracts" / "ThreatEvidence.sol"
ABI_OUTPUT_PATH = Path(__file__).parent.parent / "abi" / "ThreatEvidence.json"


def compile_contract() -> tuple[list, str]:
    install_solc("0.8.20")

    with open(CONTRACT_PATH, "r") as f:
        source = f.read()

    compiled = compile_source(
        source,
        output_values=["abi", "bin"],
        solc_version="0.8.20",
    )
    _, contract_interface = compiled.popitem()

    return contract_interface["abi"], contract_interface["bin"]


def deploy(provider_url: str, chain_id: int, private_key: str) -> str:
    w3 = Web3(Web3.HTTPProvider(provider_url))
    account = Account.from_key(private_key)

    abi, bytecode = compile_contract()

    # Save the ABI so the backend / client stay in sync with the compiled contract
    with open(ABI_OUTPUT_PATH, "w") as f:
        json.dump(abi, f, indent=2)

    contract = w3.eth.contract(abi=abi, bytecode=bytecode)

    nonce = w3.eth.get_transaction_count(account.address)
    tx = contract.constructor().build_transaction({
        "from": account.address,
        "nonce": nonce,
        "chainId": chain_id,
        "gas": 3_000_000,
        "gasPrice": w3.eth.gas_price,
    })

    signed_tx = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)

    print(f"Contract deployed at: {receipt.contractAddress}")
    print(f"Transaction hash: {tx_hash.hex()}")
    print(f"Gas used: {receipt.gasUsed}")

    return receipt.contractAddress


def main():
    parser = argparse.ArgumentParser(description="Deploy the ThreatEvidence contract.")
    parser.add_argument("--provider-url", default="http://localhost:8545")
    parser.add_argument("--chain-id", type=int, default=1337)
    parser.add_argument("--private-key", required=True)
    args = parser.parse_args()

    address = deploy(args.provider_url, args.chain_id, args.private_key)
    print(f"\nAdd this to your .env file:\nTHREAT_EVIDENCE_CONTRACT_ADDRESS={address}")


if __name__ == "__main__":
    main()