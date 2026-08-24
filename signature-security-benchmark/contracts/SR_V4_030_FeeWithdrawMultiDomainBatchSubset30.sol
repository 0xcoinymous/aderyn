// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_FeeWithdrawMultiDomainBatchSubset30 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public feeWithdrawn;
    mapping(bytes32 => bool) public usedSingle;
    mapping(bytes32 => bool) public usedBatchPart;

    constructor(address signer_) { authorizedSigner = signer_; }

    function executeSingle(bytes32 callHash, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        require(!usedSingle[callHash], "used");
        bytes32 digest = keccak256(abi.encode(callHash, nonce));
        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");
        usedSingle[callHash] = true;
    }

    function executeAsBatchPart(bytes32 callHash, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        require(!usedBatchPart[callHash], "used");
        bytes32 digest = keccak256(abi.encode(callHash, nonce));
        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");
        usedBatchPart[callHash] = true;
    }
}
