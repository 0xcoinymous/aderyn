// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_AirdropNoOneTimeSignedNonce16 {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e; address public immutable wallet;
    mapping(address => uint256) public airdropPaid;

    constructor(address wallet_) { wallet = wallet_; }

    function claimAirdrop(address user, uint256 amount, bytes32 campaign, uint256 nonce, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(user, amount, campaign, nonce));

        require(SR_IReplayBench1271(wallet).isValidSignature(digest, signature) == MAGICVALUE, "invalid signature");

        airdropPaid[user] += amount;
    }
}
