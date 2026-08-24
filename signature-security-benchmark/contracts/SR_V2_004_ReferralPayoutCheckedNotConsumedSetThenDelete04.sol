// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_ReferralPayoutCheckedNotConsumedSetThenDelete04 {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e; address public immutable wallet;
    mapping(address => uint256) public referralPaid;
    mapping(bytes32 => bool) public used;

    constructor(address wallet_) { wallet = wallet_; }

    function payReferral(address referrer, address user, uint256 amount, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(referrer, user, amount, authorizationId));

        require(SR_IReplayBench1271(wallet).isValidSignature(digest, signature) == MAGICVALUE, "invalid signature");

        used[authorizationId] = true;
        delete used[authorizationId];

        referralPaid[referrer] += amount;
    }
}
