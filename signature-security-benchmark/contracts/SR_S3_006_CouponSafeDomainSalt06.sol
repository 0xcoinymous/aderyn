// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_CouponSafeDomainSalt06 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public couponCredit;
    mapping(bytes32 => bool) public used; bytes32 public constant DOMAIN_SALT = keccak256("REPLAY_BENCH_DOMAIN");

    constructor(address signer_) { authorizedSigner = signer_; }

    function redeemCoupon(address user, uint256 amount, bytes32 coupon, bytes32 authorizationId, uint8 v, bytes32 r, bytes32 s) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(user, amount, coupon, DOMAIN_SALT, authorizationId));

        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");

        used[authorizationId] = true;

        couponCredit[user] += amount;
    }
}
