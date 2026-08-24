// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_UpgradeSafeRollbackSessionAbortNoRevert07 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public used; mapping(bytes32 => bool) public executionFailed;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address implementation, bytes32 codeHash, uint256 version, bytes32 authorizationId, address target, bytes calldata payload, bytes calldata signature) external {
        require(!used[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(implementation, codeHash, version, authorizationId));
        _authorize(digest, signature);
        used[authorizationId] = true;
        (bool success,) = target.call(payload);
        if (!success) { executionFailed[authorizationId] = true; return; }
    }


    function _authorize(bytes32 digest, bytes calldata signature) internal view {
        require(_recoverMatches(digest, signature), "invalid signature");
    }

    function _recoverMatches(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
