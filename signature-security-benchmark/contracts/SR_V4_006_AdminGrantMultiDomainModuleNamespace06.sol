// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_AdminGrantMultiDomainModuleNamespace06 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public roles;
    mapping(bytes32 => mapping(bytes32 => bool)) public usedByDomain;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address account, uint256 role, bytes32 moduleId, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedByDomain[moduleId][authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(account, role, authorizationId));
        require(_verifySignature(digest, signature), "invalid signature");
        usedByDomain[moduleId][authorizationId] = true;
        roles[account] = role;
    }


    function _verifySignature(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
