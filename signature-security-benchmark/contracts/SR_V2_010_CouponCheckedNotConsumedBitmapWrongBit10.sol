// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_CouponCheckedNotConsumedBitmapWrongBit10 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public couponCredit;
    mapping(address => mapping(uint256 => uint256)) public nonceBitmap;

    constructor(address signer_) { authorizedSigner = signer_; }

    function redeemCoupon(address user, uint256 amount, bytes32 coupon, bytes32 authorizationId, bytes calldata signature) external {
        uint256 word = uint256(authorizationId) >> 8;
        uint256 bit = uint256(authorizationId) & 255;
        uint256 mask = uint256(1) << bit;
        require(nonceBitmap[user][word] & mask == 0, "used");

        bytes32 digest = keccak256(abi.encode(user, amount, coupon, authorizationId));

        require(_verifySignature(digest, signature), "invalid signature");

        nonceBitmap[user][word] |= uint256(1) << ((bit + 1) & 255);

        couponCredit[user] += amount;
    }


    function _verifySignature(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
