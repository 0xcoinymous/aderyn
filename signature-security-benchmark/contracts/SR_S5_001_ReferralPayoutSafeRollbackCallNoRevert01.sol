// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_ReferralPayoutSafeRollbackCallNoRevert01 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public used; mapping(bytes32 => bool) public executionFailed;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address referrer, address user, uint256 amount, bytes32 authorizationId, address target, bytes calldata payload, bytes calldata signature) external {
        require(!used[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(referrer, user, amount, authorizationId));
        require(SR_ReplayBenchSignatureChecker.isValidSignatureNow(authorizedSigner, digest, signature), "invalid signature");
        used[authorizationId] = true;
        (bool success,) = target.call(payload);
        if (!success) executionFailed[authorizationId] = true;
    }
}
