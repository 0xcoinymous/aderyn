// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_FeeWithdrawRollbackPostconditionAuthorizationId19 {
    address public immutable authorizedSigner; SR_IReplayBenchVerifier public immutable verifier;
    uint256 public successfulExecutions;
    mapping(bytes32 => bool) public usedAuthorization;

    constructor(address signer_, SR_IReplayBenchVerifier verifier_) { authorizedSigner = signer_; verifier = verifier_; }

    function execute(address recipient, uint256 amount, bytes32 feeId, bytes32 authorizationId, address target, bytes calldata payload, bytes32 expectedReturnHash, bytes calldata signature) external {
        require(!usedAuthorization[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(recipient, amount, feeId, authorizationId));
        require(verifier.isValid(authorizedSigner, digest, signature), "invalid signature");
        usedAuthorization[authorizationId] = true;
        (bool success, bytes memory result) = target.call(payload);
        require(success, "action failed");
        require(keccak256(result) == expectedReturnHash, "bad postcondition");
        successfulExecutions += 1;
    }
}
