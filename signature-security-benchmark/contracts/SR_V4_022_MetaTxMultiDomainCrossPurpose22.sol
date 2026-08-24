// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_MetaTxMultiDomainCrossPurpose22 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public metaValue;
    mapping(bytes32 => bool) public executed;
    mapping(bytes32 => bool) public cancelled;

    constructor(address signer_) { authorizedSigner = signer_; }

    function executeAuthorization(address user, address target, uint256 value, bytes32 callHash, bytes32 authorizationId, bytes calldata signature) external {
        require(!executed[authorizationId], "executed");
        bytes32 digest = keccak256(abi.encode(user, target, value, callHash, authorizationId));
        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");
        executed[authorizationId] = true;
        metaValue[user] += value;
    }

    function cancelAuthorization(address user, address target, uint256 value, bytes32 callHash, bytes32 authorizationId, bytes calldata signature) external {
        require(!cancelled[authorizationId], "cancelled");
        bytes32 digest = keccak256(abi.encode(user, target, value, callHash, authorizationId));
        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");
        cancelled[authorizationId] = true;
    }
}
