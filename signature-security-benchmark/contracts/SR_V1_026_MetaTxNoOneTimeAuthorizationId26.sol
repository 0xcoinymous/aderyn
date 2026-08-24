// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_MetaTxNoOneTimeAuthorizationId26 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public metaValue;

    constructor(address signer_) { authorizedSigner = signer_; }

    function executeMeta(address user, address target, uint256 value, bytes32 callHash, bytes32 authorizationId, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(user, target, value, callHash, authorizationId));

        require(SR_ReplayBenchSignatureChecker.isValidSignatureNow(authorizedSigner, digest, signature), "invalid signature");

        metaValue[user] += value;
    }
}
