// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_GaslessTransferAdversarialSafeExternalVerifierSafe08 {
    address public immutable authorizedSigner; SR_IReplayBenchVerifier public immutable verifier;
    mapping(address => uint256) public transferred;
    mapping(bytes32 => bool) public used;

    constructor(address signer_, SR_IReplayBenchVerifier verifier_) { authorizedSigner = signer_; verifier = verifier_; }

    function transferBySig(address from, address to, uint256 amount, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(from, to, amount, authorizationId));

        require(verifier.isValid(authorizedSigner, digest, signature), "invalid signature");

        used[authorizationId] = true;

        transferred[to] += amount;
    }
}
