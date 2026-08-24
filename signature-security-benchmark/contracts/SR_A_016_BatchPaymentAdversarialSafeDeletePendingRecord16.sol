// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_BatchPaymentAdversarialSafeDeletePendingRecord16 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bytes32) public pendingHash;
    uint256 public executions;
    constructor(address signer_) { authorizedSigner = signer_; }
    function register(bytes32 id, bytes32 actionHash) external { require(pendingHash[id] == bytes32(0)); pendingHash[id] = actionHash; }
    function execute(bytes32 id, bytes32 actionHash, bytes calldata signature) external {
        require(pendingHash[id] == actionHash && actionHash != bytes32(0), "not pending");
        bytes32 digest = keccak256(abi.encode(address(this), id, actionHash));
        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");
        delete pendingHash[id];
        executions += 1;
    }
}
