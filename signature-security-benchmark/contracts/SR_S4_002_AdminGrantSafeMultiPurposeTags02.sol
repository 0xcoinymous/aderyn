// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_AdminGrantSafeMultiPurposeTags02 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public roles;
    mapping(bytes32 => bool) public used;

    constructor(address signer_) { authorizedSigner = signer_; }

    function primary(address account, uint256 role, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[keccak256(abi.encode(authorizationId, bytes32("PRIMARY")))], "used");
        bytes32 digest = keccak256(abi.encode(account, role, authorizationId, keccak256("PRIMARY")));
        require(_verifySignature(digest, signature), "invalid signature");
        used[keccak256(abi.encode(authorizationId, bytes32("PRIMARY")))] = true;
        roles[account] = role;
    }

    function alternate(address account, uint256 role, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[keccak256(abi.encode(authorizationId, bytes32("ALTERNATE")))], "used");
        bytes32 digest = keccak256(abi.encode(account, role, authorizationId, keccak256("ALTERNATE")));
        require(_verifySignature(digest, signature), "invalid signature");
        used[keccak256(abi.encode(authorizationId, bytes32("ALTERNATE")))] = true;
        roles[account] = role;
    }


    function _verifySignature(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
