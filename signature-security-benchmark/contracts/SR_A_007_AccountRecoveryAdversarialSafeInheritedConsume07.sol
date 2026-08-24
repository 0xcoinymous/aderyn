// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

abstract contract SR_AccountRecoveryAdversarialSafeInheritedConsume07ReplayBase {
    mapping(bytes32 => bool) internal consumed;
    function _requireFresh(bytes32 id) internal view { require(!consumed[id], "used"); }
    function _consume(bytes32 id) internal { consumed[id] = true; }
}

contract SR_AccountRecoveryAdversarialSafeInheritedConsume07 is SR_AccountRecoveryAdversarialSafeInheritedConsume07ReplayBase {
    address public immutable authorizedSigner;
    mapping(address => address) public owners; mapping(address => uint256) public recoveryCount;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address account, address newOwner, bytes32 recoveryId, bytes32 authorizationId, uint8 v, bytes32 r, bytes32 s) external {
        _requireFresh(authorizationId);
        bytes32 digest = keccak256(abi.encode(account, newOwner, recoveryId, authorizationId));
        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");
        _consume(authorizationId);
        owners[account] = newOwner; recoveryCount[account] += 1;
    }
}
