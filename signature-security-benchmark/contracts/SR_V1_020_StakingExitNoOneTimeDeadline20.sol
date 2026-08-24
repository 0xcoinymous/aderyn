// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_StakingExitNoOneTimeDeadline20 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public exitedStake;

    constructor(address signer_) { authorizedSigner = signer_; }

    function exitStake(address staker, uint256 amount, uint256 validatorId, uint256 deadline, bytes calldata signature) external {
        require(block.timestamp <= deadline, "expired");

        bytes32 digest = keccak256(abi.encode(staker, amount, validatorId, deadline));

        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");

        exitedStake[staker] += amount;
    }
}
