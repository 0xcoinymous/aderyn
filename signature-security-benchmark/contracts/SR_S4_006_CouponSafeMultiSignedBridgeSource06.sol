// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_CouponSafeMultiSignedBridgeSource06 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public couponCredit;
    mapping(uint256 => mapping(bytes32 => bool)) public usedByDomain;

    constructor(address signer_) { authorizedSigner = signer_; }

    function redeemCoupon(address user, uint256 amount, bytes32 coupon, uint256 sourceChainId, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedByDomain[sourceChainId][authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(user, amount, coupon, sourceChainId, authorizationId));

        require(SR_ReplayBenchSignatureChecker.isValidSignatureNow(authorizedSigner, digest, signature), "invalid signature");

        usedByDomain[sourceChainId][authorizationId] = true;

        couponCredit[user] += amount;
    }
}
