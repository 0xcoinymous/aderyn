// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_CouponNoOneTimeDeadline18 is SR_ReplayBenchSignerBase {
    mapping(address => uint256) public couponCredit;

    constructor(address signer_) SR_ReplayBenchSignerBase(signer_) {}

    function redeemCoupon(address user, uint256 amount, bytes32 coupon, uint256 deadline, bytes calldata signature) external {
        require(block.timestamp <= deadline, "expired");

        bytes32 digest = keccak256(abi.encode(user, amount, coupon, deadline));

        require(_isAuthorized(digest, signature), "invalid signature");

        couponCredit[user] += amount;
    }
}
