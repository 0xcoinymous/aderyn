// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_AirdropSafeRollbackCallRecordFailure02 is SR_ReplayBenchSignerBase {
    mapping(bytes32 => bool) public used; mapping(bytes32 => bool) public executionFailed;

    constructor(address signer_) SR_ReplayBenchSignerBase(signer_) {}

    function execute(address user, uint256 amount, bytes32 campaign, bytes32 authorizationId, address target, bytes calldata payload, bytes calldata signature) external {
        require(!used[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(user, amount, campaign, authorizationId));
        require(_isAuthorized(digest, signature), "invalid signature");
        used[authorizationId] = true;
        (bool success,) = target.call(payload);
        executionFailed[authorizationId] = !success;
    }
}
