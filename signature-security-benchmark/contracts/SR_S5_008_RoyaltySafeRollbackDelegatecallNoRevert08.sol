// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_RoyaltySafeRollbackDelegatecallNoRevert08 {
    address public immutable authorizedSigner; SR_IReplayBenchVerifier public immutable verifier;
    mapping(bytes32 => bool) public used; mapping(bytes32 => bool) public executionFailed;

    constructor(address signer_, SR_IReplayBenchVerifier verifier_) { authorizedSigner = signer_; verifier = verifier_; }

    function execute(address creator, uint256 amount, bytes32 saleId, bytes32 authorizationId, address target, bytes calldata payload, bytes calldata signature) external {
        require(!used[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(creator, amount, saleId, authorizationId));
        require(verifier.isValid(authorizedSigner, digest, signature), "invalid signature");
        used[authorizationId] = true;
        (bool success,) = target.delegatecall(payload);
        executionFailed[authorizationId] = !success;
    }
}
