// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_GovernanceSafeRollbackTwoCallsNoRevert04 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public used; mapping(bytes32 => bool) public executionFailed;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(uint256 proposalId, bytes32 actionHash, bytes32 authorizationId, address target, bytes calldata payload, bytes calldata signature) external {
        require(!used[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(proposalId, actionHash, authorizationId));
        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");
        used[authorizationId] = true;
        (bool first,) = target.call(payload);
        if (first) {
            (bool second,) = target.call(payload);
            executionFailed[authorizationId] = !second;
        } else {
            executionFailed[authorizationId] = true;
        }
    }
}
