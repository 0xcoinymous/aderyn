// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_BridgeMintCheckedNotConsumedPendingOnly30 {
    address public immutable authorizedSigner; SR_IReplayBenchVerifier public immutable verifier;
    mapping(address => uint256) public bridgedMint;
    mapping(bytes32 => bool) public used; mapping(bytes32 => bool) public pending;

    constructor(address signer_, SR_IReplayBenchVerifier verifier_) { authorizedSigner = signer_; verifier = verifier_; }

    function mintBridged(address recipient, uint256 amount, bytes32 messageId, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(recipient, amount, messageId, authorizationId));

        require(verifier.isValid(authorizedSigner, digest, signature), "invalid signature");

        pending[authorizationId] = true;

        bridgedMint[recipient] += amount;
    }
}
