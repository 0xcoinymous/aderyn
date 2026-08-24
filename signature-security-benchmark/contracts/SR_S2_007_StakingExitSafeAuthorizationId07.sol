// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_StakingExitSafeAuthorizationId07 is SR_ReplayBenchSignerBase {
    mapping(address => uint256) public exitedStake;
    mapping(bytes32 => bool) public usedAuthorization;

    constructor(address signer_) SR_ReplayBenchSignerBase(signer_) {}

    function exitStake(address staker, uint256 amount, uint256 validatorId, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedAuthorization[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(staker, amount, validatorId, authorizationId));

        require(_isAuthorized(digest, signature), "invalid signature");

        usedAuthorization[authorizationId] = true;

        exitedStake[staker] += amount;
    }
}
