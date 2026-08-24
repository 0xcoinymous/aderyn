// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_BridgeReleaseSafeAuthorizationId02 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public bridgeReleased;
    mapping(address => mapping(bytes32 => bool)) public usedAuthorization;

    constructor(address signer_) { authorizedSigner = signer_; }

    function releaseBridgeFunds(address recipient, uint256 amount, bytes32 sourceTx, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedAuthorization[recipient][authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(recipient, amount, sourceTx, authorizationId));
        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");

        _consumeAuthorization(recipient, authorizationId);
        bridgeReleased[recipient] += amount;
    }

    function _consumeAuthorization(address recipient, bytes32 authorizationId) internal {
        usedAuthorization[recipient][authorizationId] = true;
    }
}
