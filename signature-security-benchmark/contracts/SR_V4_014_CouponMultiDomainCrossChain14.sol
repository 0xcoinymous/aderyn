// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_CouponMultiDomainCrossChain14 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public couponCredit;
    mapping(uint256 => mapping(address => uint256)) public noncesByChainDomain;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address user, uint256 amount, bytes32 coupon, uint256 executionChainId, uint256 nonce, bytes calldata signature) external {
        require(nonce == noncesByChainDomain[executionChainId][user], "wrong nonce");

        // Vulnerable: executionChainId is the replay-state namespace but is not authenticated.
        bytes32 digest = keccak256(abi.encode(user, amount, coupon, nonce));
        (address recovered, bool ok) = SR_ReplayBenchECDSA.tryRecover(digest, signature);
        require(ok && recovered == authorizedSigner, "invalid signature");

        noncesByChainDomain[executionChainId][user] = nonce + 1;
        couponCredit[user] += amount;
    }
}
