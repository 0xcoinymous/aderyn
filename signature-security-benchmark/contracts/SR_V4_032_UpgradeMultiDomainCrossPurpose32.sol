// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_UpgradeMultiDomainCrossPurpose32 {
    address public immutable authorizedSigner;
    address public currentImplementation; uint256 public upgradeCount;
    mapping(bytes32 => bool) public executed;
    mapping(bytes32 => bool) public cancelled;

    constructor(address signer_) { authorizedSigner = signer_; }

    function executeAuthorization(address implementation, bytes32 codeHash, uint256 version, bytes32 authorizationId, bytes calldata signature) external {
        require(!executed[authorizationId], "executed");
        bytes32 digest = keccak256(abi.encode(implementation, codeHash, version, authorizationId));
        (address recovered, bool ok) = SR_ReplayBenchECDSA.tryRecover(digest, signature);
        require(ok && recovered == authorizedSigner, "invalid signature");
        executed[authorizationId] = true;
        currentImplementation = implementation; upgradeCount += 1;
    }

    function cancelAuthorization(address implementation, bytes32 codeHash, uint256 version, bytes32 authorizationId, bytes calldata signature) external {
        require(!cancelled[authorizationId], "cancelled");
        bytes32 digest = keccak256(abi.encode(implementation, codeHash, version, authorizationId));
        (address recovered, bool ok) = SR_ReplayBenchECDSA.tryRecover(digest, signature);
        require(ok && recovered == authorizedSigner, "invalid signature");
        cancelled[authorizationId] = true;
    }
}
