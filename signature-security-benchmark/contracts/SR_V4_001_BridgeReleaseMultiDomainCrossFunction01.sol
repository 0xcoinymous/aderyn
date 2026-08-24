// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_BridgeReleaseMultiDomainCrossFunction01 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public bridgeReleased;
    mapping(bytes32 => bool) public usedPrimary;
    mapping(bytes32 => bool) public usedAlternate;

    constructor(address signer_) { authorizedSigner = signer_; }

    function primary(address recipient, uint256 amount, bytes32 sourceTx, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedPrimary[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(recipient, amount, sourceTx, authorizationId));
        require(SR_ReplayBenchSignatureChecker.isValidSignatureNow(authorizedSigner, digest, signature), "invalid signature");
        usedPrimary[authorizationId] = true;
        bridgeReleased[recipient] += amount;
    }

    function alternate(address recipient, uint256 amount, bytes32 sourceTx, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedAlternate[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(recipient, amount, sourceTx, authorizationId));
        require(SR_ReplayBenchSignatureChecker.isValidSignatureNow(authorizedSigner, digest, signature), "invalid signature");
        usedAlternate[authorizationId] = true;
        bridgeReleased[recipient] += amount;
    }
}
