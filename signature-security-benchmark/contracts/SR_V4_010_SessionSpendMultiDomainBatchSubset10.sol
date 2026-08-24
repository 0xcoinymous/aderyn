// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_SessionSpendMultiDomainBatchSubset10 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public sessionSpent;
    mapping(bytes32 => bool) public usedSingle;
    mapping(bytes32 => bool) public usedBatchPart;

    constructor(address signer_) { authorizedSigner = signer_; }

    function executeSingle(bytes32 callHash, uint256 nonce, bytes calldata signature) external {
        require(!usedSingle[callHash], "used");
        bytes32 digest = keccak256(abi.encode(callHash, nonce));
        require(SR_ReplayBenchSignatureChecker.isValidSignatureNow(authorizedSigner, digest, signature), "invalid signature");
        usedSingle[callHash] = true;
    }

    function executeAsBatchPart(bytes32 callHash, uint256 nonce, bytes calldata signature) external {
        require(!usedBatchPart[callHash], "used");
        bytes32 digest = keccak256(abi.encode(callHash, nonce));
        require(SR_ReplayBenchSignatureChecker.isValidSignatureNow(authorizedSigner, digest, signature), "invalid signature");
        usedBatchPart[callHash] = true;
    }
}
