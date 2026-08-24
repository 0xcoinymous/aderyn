// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_PermitLikeRollbackDelegatecallAssertUsedDigest10 {
    address public immutable authorizedSigner; SR_IReplayBenchVerifier public immutable verifier;
    uint256 public successfulExecutions;
    mapping(bytes32 => bool) public usedDigest;

    constructor(address signer_, SR_IReplayBenchVerifier verifier_) { authorizedSigner = signer_; verifier = verifier_; }

    function execute(address owner, address spender, uint256 value, address target, bytes calldata payload, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(owner, spender, value));
        require(!usedDigest[digest], "used");
        require(verifier.isValid(authorizedSigner, digest, signature), "invalid signature");
        usedDigest[digest] = true;
        (bool success,) = target.delegatecall(payload);
        assert(success);
        successfulExecutions += 1;
    }
}
