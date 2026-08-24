// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_VaultHarvestRollbackCustomErrorAuthorizationId16 {
    address public immutable authorizedSigner;
    uint256 public successfulExecutions;
    mapping(bytes32 => bool) public usedAuthorization;
    error ExternalActionFailed();

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address vault, uint256 amount, bytes32 harvestId, bytes32 authorizationId, address target, bytes calldata payload, bytes calldata signature) external {
        require(!usedAuthorization[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(vault, amount, harvestId, authorizationId));
        (address recovered, bool ok) = SR_ReplayBenchECDSA.tryRecover(digest, signature);
        require(ok && recovered == authorizedSigner, "invalid signature");
        usedAuthorization[authorizationId] = true;
        (bool success,) = target.call(payload);
        if (!success) revert ExternalActionFailed();
        successfulExecutions += 1;
    }
}
