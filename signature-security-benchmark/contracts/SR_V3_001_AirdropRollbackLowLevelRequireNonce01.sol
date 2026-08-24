// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_AirdropRollbackLowLevelRequireNonce01 {
    address public immutable authorizedSigner; SR_IReplayBenchVerifier public immutable verifier;
    uint256 public successfulExecutions;
    mapping(address => uint256) public nonces;

    constructor(address signer_, SR_IReplayBenchVerifier verifier_) { authorizedSigner = signer_; verifier = verifier_; }

    function execute(address user, uint256 amount, bytes32 campaign, uint256 nonce, address target, bytes calldata payload, bytes calldata signature) external {
        require(nonce == nonces[user], "wrong nonce");
        bytes32 digest = keccak256(abi.encode(user, amount, campaign, nonce));
        require(verifier.isValid(authorizedSigner, digest, signature), "invalid signature");
        nonces[user] = nonce + 1;
        (bool success,) = target.call(payload);
        require(success, "action failed");
        successfulExecutions += 1;
    }
}
