// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_LoanDrawRollbackPartialSessionNonce07 {
    address public immutable authorizedSigner;
    uint256 public successfulExecutions;
    mapping(address => uint256) public nonces;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address borrower, uint256 amount, bytes32 facilityId, uint256 nonce, address firstTarget, bytes calldata firstPayload, address secondTarget, bytes calldata secondPayload, bytes calldata signature) external {
        require(nonce == nonces[borrower], "wrong nonce");
        bytes32 digest = keccak256(abi.encode(borrower, amount, facilityId, nonce));
        (address recovered, bool ok) = SR_ReplayBenchECDSA.tryRecover(digest, signature);
        require(ok && recovered == authorizedSigner, "invalid signature");
        nonces[borrower] = nonce + 1;
        (bool first,) = firstTarget.call(firstPayload);
        require(first, "first session call failed");
        (bool second,) = secondTarget.call(secondPayload);
        if (!second) revert("session reverted");
        successfulExecutions += 1;
    }
}
