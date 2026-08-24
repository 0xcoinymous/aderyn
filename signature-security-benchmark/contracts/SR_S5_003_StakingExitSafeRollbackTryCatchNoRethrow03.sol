// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_StakingExitSafeRollbackTryCatchNoRethrow03 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public used; mapping(bytes32 => bool) public executionFailed;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address staker, uint256 amount, uint256 validatorId, bytes32 authorizationId, address target, bytes calldata payload, uint8 v, bytes32 r, bytes32 s) external {
        require(!used[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(staker, amount, validatorId, authorizationId));
        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");
        used[authorizationId] = true;
        try SR_IReplayBenchAction(target).run(payload) returns (bool ok) {
            executionFailed[authorizationId] = !ok;
        } catch {
            executionFailed[authorizationId] = true;
        }
    }
}
