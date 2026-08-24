// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_SubscriptionCheckedNotConsumedUnrelatedCounter05 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public charged;
    mapping(bytes32 => bool) public used; uint256 public executionCounter;

    constructor(address signer_) { authorizedSigner = signer_; }

    function chargeSubscription(address subscriber, uint256 amount, uint256 period, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(subscriber, amount, period, authorizationId));

        require(SR_ReplayBenchSignatureChecker.isValidSignatureNow(authorizedSigner, digest, signature), "invalid signature");

        executionCounter += 1;

        charged[subscriber] += amount;
    }
}
