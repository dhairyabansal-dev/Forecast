// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ThreatEvidence {
    struct EvidenceRecord {
        address submitter;
        uint256 timestamp;
        bool exists;
    }

    mapping(bytes32 => EvidenceRecord) private records;

    address public owner;
    uint256 public totalRecords;

    event EvidenceAnchored(bytes32 indexed evidenceHash, address indexed submitter, uint256 timestamp);

    modifier onlyOwner() {
        require(msg.sender == owner, "ThreatEvidence: caller is not the owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function anchorEvidence(bytes32 evidenceHash) external {
        require(!records[evidenceHash].exists, "ThreatEvidence: hash already anchored");

        records[evidenceHash] = EvidenceRecord({
            submitter: msg.sender,
            timestamp: block.timestamp,
            exists: true
        });

        totalRecords += 1;

        emit EvidenceAnchored(evidenceHash, msg.sender, block.timestamp);
    }

    function isAnchored(bytes32 evidenceHash) external view returns (bool) {
        return records[evidenceHash].exists;
    }

    function getRecord(bytes32 evidenceHash)
        external
        view
        returns (address submitter, uint256 timestamp, bool exists)
    {
        EvidenceRecord memory record = records[evidenceHash];
        return (record.submitter, record.timestamp, record.exists);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "ThreatEvidence: new owner is the zero address");
        owner = newOwner;
    }
}