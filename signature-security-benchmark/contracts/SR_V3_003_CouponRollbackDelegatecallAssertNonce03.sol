// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_CouponRollbackDelegatecallAssertNonce03 {
    address public immutable authorizedSigner;
    uint256 public successfulExecutions;
    mapping(address => uint256) public nonces;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address user, uint256 amount, bytes32 coupon, uint256 nonce, address target, bytes calldata payload, bytes calldata signature) external {
        require(nonce == nonces[user], "wrong nonce");
        bytes32 digest = keccak256(abi.encode(user, amount, coupon, nonce));
        require(SR_ReplayBenchSignatureChecker.isValidSignatureNow(authorizedSigner, digest, signature), "invalid signature");
        nonces[user] = nonce + 1;
        (bool success,) = target.delegatecall(payload);
        assert(success);
        successfulExecutions += 1;
    }
}
