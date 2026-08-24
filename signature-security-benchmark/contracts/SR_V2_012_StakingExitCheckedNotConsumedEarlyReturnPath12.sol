// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_StakingExitCheckedNotConsumedEarlyReturnPath12 {
    address public immutable authorizedSigner; SR_IReplayBenchVerifier public immutable verifier;
    mapping(address => uint256) public exitedStake;
    mapping(bytes32 => bool) public used;

    constructor(address signer_, SR_IReplayBenchVerifier verifier_) { authorizedSigner = signer_; verifier = verifier_; }

    function exitStake(address staker, uint256 amount, uint256 validatorId, bytes32 authorizationId, bool skipConsumption, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(staker, amount, validatorId, authorizationId));

        require(verifier.isValid(authorizedSigner, digest, signature), "invalid signature");

        if (skipConsumption) {
            exitedStake[staker] += amount;
            return;
        }
        used[authorizationId] = true;
    }
}
