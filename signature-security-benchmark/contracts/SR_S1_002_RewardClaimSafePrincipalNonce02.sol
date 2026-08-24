// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_RewardClaimSafePrincipalNonce02 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public rewardsClaimed;
    mapping(address => uint256) public nonces;

    constructor(address signer_) { authorizedSigner = signer_; }

    function claimReward(address user, uint256 amount, uint256 epoch, uint256 nonce, bytes calldata signature) external {
        require(nonce == nonces[user], "wrong nonce");

        bytes32 digest = keccak256(abi.encode(user, amount, epoch, nonce));

        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");

        nonces[user] = nonce + 1;

        rewardsClaimed[user] += amount;
    }
}
