// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_RescueMultiDomainCrossFunction31 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public rescued;
    mapping(bytes32 => bool) public usedPrimary;
    mapping(bytes32 => bool) public usedAlternate;

    constructor(address signer_) { authorizedSigner = signer_; }

    function primary(address recipient, uint256 amount, bytes32 rescueId, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedPrimary[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(recipient, amount, rescueId, authorizationId));
        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");
        usedPrimary[authorizationId] = true;
        rescued[recipient] += amount;
    }

    function alternate(address recipient, uint256 amount, bytes32 rescueId, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedAlternate[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(recipient, amount, rescueId, authorizationId));
        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");
        usedAlternate[authorizationId] = true;
        rescued[recipient] += amount;
    }
}
