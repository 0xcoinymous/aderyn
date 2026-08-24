// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_GovernanceMultiDomainBatchSubset20 is SR_ReplayBenchSignerBase {
    mapping(uint256 => uint256) public proposalExecutions;
    mapping(bytes32 => bool) public usedSingle;
    mapping(bytes32 => bool) public usedBatchPart;

    constructor(address signer_) SR_ReplayBenchSignerBase(signer_) {}

    function executeSingle(bytes32 callHash, uint256 nonce, bytes calldata signature) external {
        require(!usedSingle[callHash], "used");
        bytes32 digest = keccak256(abi.encode(callHash, nonce));
        require(_isAuthorized(digest, signature), "invalid signature");
        usedSingle[callHash] = true;
    }

    function executeAsBatchPart(bytes32 callHash, uint256 nonce, bytes calldata signature) external {
        require(!usedBatchPart[callHash], "used");
        bytes32 digest = keccak256(abi.encode(callHash, nonce));
        require(_isAuthorized(digest, signature), "invalid signature");
        usedBatchPart[callHash] = true;
    }
}
