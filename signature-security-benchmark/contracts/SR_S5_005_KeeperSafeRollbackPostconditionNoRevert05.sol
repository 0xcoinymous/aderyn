// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_KeeperSafeRollbackPostconditionNoRevert05 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public used; mapping(bytes32 => bool) public executionFailed;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(bytes32 jobId, address keeper, uint256 reward, bytes32 authorizationId, address target, bytes calldata payload, bytes calldata signature) external {
        require(!used[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(jobId, keeper, reward, authorizationId));
        (address recovered, bool ok) = SR_ReplayBenchECDSA.tryRecover(digest, signature);
        require(ok && recovered == authorizedSigner, "invalid signature");
        used[authorizationId] = true;
        (bool success, bytes memory result) = target.call(payload);
        executionFailed[authorizationId] = !success || result.length == 0;
    }
}
