// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_BondRedeemSafeRollbackCallbackNoRevert06 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public used; mapping(bytes32 => bool) public executionFailed;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address holder, uint256 amount, bytes32 bondId, bytes32 authorizationId, address target, bytes calldata payload, bytes calldata signature) external {
        require(!used[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(holder, amount, bondId, authorizationId));
        require(_verifySignature(digest, signature), "invalid signature");
        used[authorizationId] = true;
        (bool success, bytes memory result) = target.call(payload);
        if (!success || result.length < 4) executionFailed[authorizationId] = true;
    }


    function _verifySignature(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
