// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_StakingExitRollbackPostconditionNonce05 {
    address public immutable authorizedSigner;
    uint256 public successfulExecutions;
    mapping(address => uint256) public nonces;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address staker, uint256 amount, uint256 validatorId, uint256 nonce, address target, bytes calldata payload, bytes32 expectedReturnHash, uint8 v, bytes32 r, bytes32 s) external {
        require(nonce == nonces[staker], "wrong nonce");
        bytes32 digest = keccak256(abi.encode(staker, amount, validatorId, nonce));
        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");
        nonces[staker] = nonce + 1;
        (bool success, bytes memory result) = target.call(payload);
        require(success, "action failed");
        require(keccak256(result) == expectedReturnHash, "bad postcondition");
        successfulExecutions += 1;
    }
}
