// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_UpgradeCheckedNotConsumedEarlyReturnPath28 {
    address public immutable authorizedSigner;
    address public currentImplementation; uint256 public upgradeCount;
    mapping(bytes32 => bool) public used;

    constructor(address signer_) { authorizedSigner = signer_; }

    function upgradeBySig(address implementation, bytes32 codeHash, uint256 version, bytes32 authorizationId, bool skipConsumption, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(implementation, codeHash, version, authorizationId));

        require(_verifySignature(digest, signature), "invalid signature");

        if (skipConsumption) {
            currentImplementation = implementation; upgradeCount += 1;
            return;
        }
        used[authorizationId] = true;
    }


    function _verifySignature(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
