// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_RfqMultiDomainModuleNamespace26 {
    address public immutable authorizedSigner; SR_IReplayBenchVerifier public immutable verifier;
    mapping(bytes32 => uint256) public rfqFilled;
    mapping(bytes32 => mapping(bytes32 => bool)) public usedByDomain;

    constructor(address signer_, SR_IReplayBenchVerifier verifier_) { authorizedSigner = signer_; verifier = verifier_; }

    function execute(bytes32 quoteId, address maker, address taker, uint256 amount, bytes32 moduleId, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedByDomain[moduleId][authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(quoteId, maker, taker, amount, authorizationId));
        require(verifier.isValid(authorizedSigner, digest, signature), "invalid signature");
        usedByDomain[moduleId][authorizationId] = true;
        rfqFilled[quoteId] += amount;
    }
}
