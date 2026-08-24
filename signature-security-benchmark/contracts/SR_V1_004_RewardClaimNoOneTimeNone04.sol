// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_RewardClaimNoOneTimeNone04 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public rewardsClaimed;

    constructor(address signer_) { authorizedSigner = signer_; }

    function claimReward(address user, uint256 amount, uint256 epoch, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(user, amount, epoch));

        require(_verifySignature(digest, signature), "invalid signature");

        rewardsClaimed[user] += amount;
    }


    function _verifySignature(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
