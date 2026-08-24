// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_StakingExitSafeMultiSignedWallet07 {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e;
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public exitedStake;

    function execute(address staker, uint256 amount, uint256 validatorId, address account, uint256 nonce, bytes calldata signature) external {
        require(nonce == nonces[account], "wrong nonce");
        bytes32 digest = keccak256(abi.encode(account, staker, amount, validatorId, nonce));
        require(SR_IReplayBench1271(account).isValidSignature(digest, signature) == MAGICVALUE, "invalid signature");
        nonces[account] = nonce + 1;
        exitedStake[staker] += amount;
    }
}
