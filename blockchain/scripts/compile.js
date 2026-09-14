// Compiles ThreatEvidence.sol using the npm 'solc' package (avoids solc-bin.ethereum.org
// entirely, since Windows DNS/network issues can block that host for some users).
// Run this from inside the hardhat-node/ folder where 'solc' is installed.

const fs = require("fs");
const path = require("path");
const solc = require("solc");

const CONTRACT_PATH = path.join(__dirname, "..", "contracts", "ThreatEvidence.sol");
const ABI_OUTPUT_PATH = path.join(__dirname, "..", "abi", "ThreatEvidence.json");
const BYTECODE_OUTPUT_PATH = path.join(__dirname, "..", "abi", "ThreatEvidence.bin");

const source = fs.readFileSync(CONTRACT_PATH, "utf8");

const input = {
  language: "Solidity",
  sources: {
    "ThreatEvidence.sol": { content: source },
  },
  settings: {
    outputSelection: {
      "*": {
        "*": ["abi", "evm.bytecode.object"],
      },
    },
  },
};

const output = JSON.parse(solc.compile(JSON.stringify(input)));

if (output.errors) {
  const fatalErrors = output.errors.filter((e) => e.severity === "error");
  output.errors.forEach((e) => console.log(e.formattedMessage));
  if (fatalErrors.length > 0) {
    process.exit(1);
  }
}

const contract = output.contracts["ThreatEvidence.sol"]["ThreatEvidence"];
const abi = contract.abi;
const bytecode = contract.evm.bytecode.object;

fs.mkdirSync(path.dirname(ABI_OUTPUT_PATH), { recursive: true });
fs.writeFileSync(ABI_OUTPUT_PATH, JSON.stringify(abi, null, 2));
fs.writeFileSync(BYTECODE_OUTPUT_PATH, bytecode);

console.log("Compiled successfully.");
console.log("ABI written to:", ABI_OUTPUT_PATH);
console.log("Bytecode written to:", BYTECODE_OUTPUT_PATH);