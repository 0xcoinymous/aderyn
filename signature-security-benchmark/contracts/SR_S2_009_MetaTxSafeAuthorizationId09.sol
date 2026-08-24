// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_MetaTxSafeAuthorizationId09 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public metaValue;
    mapping(bytes32 => bool) public usedAuthorization;

    constructor(address signer_) { authorizedSigner = signer_; }

    function executeMeta(address user, address target, uint256 value, bytes32 callHash, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedAuthorization[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(user, target, value, callHash, authorizationId));

        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");

        usedAuthorization[authorizationId] = true;

        metaValue[user] += value;
    }
}
