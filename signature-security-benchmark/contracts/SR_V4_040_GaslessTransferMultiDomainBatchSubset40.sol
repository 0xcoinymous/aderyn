// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_GaslessTransferMultiDomainBatchSubset40 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public transferred;
    mapping(bytes32 => bool) public usedSingle;
    mapping(bytes32 => bool) public usedBatchPart;

    constructor(address signer_) { authorizedSigner = signer_; }

    function executeSingle(bytes32 callHash, uint256 nonce, bytes calldata signature) external {
        require(!usedSingle[callHash], "used");
        bytes32 digest = keccak256(abi.encode(callHash, nonce));
        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");
        usedSingle[callHash] = true;
    }

    function executeAsBatchPart(bytes32 callHash, uint256 nonce, bytes calldata signature) external {
        require(!usedBatchPart[callHash], "used");
        bytes32 digest = keccak256(abi.encode(callHash, nonce));
        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");
        usedBatchPart[callHash] = true;
    }
}
