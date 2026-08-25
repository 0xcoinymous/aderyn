// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_GovernanceAuthorizationNoFreshnessExternalPath033 {
    mapping(uint256 => mapping(address => uint8)) public voteChoice;
    mapping(address => uint256) public nonces;

    
    uint256 public executionCount;
    SF_IFreshnessVerifier public immutable verifier;

    constructor(SF_IFreshnessVerifier verifier_) {
        verifier = verifier_;
    }

    function _digest(bytes memory payload) internal view returns (bytes32) {
        return keccak256(abi.encode(payload, address(this), block.chainid));
    }

    function _signatureOk(address signer_, bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return verifier.verify(signer_, digest, signature);
    }

    function execute(address delegator, uint256 proposalId, uint8 choice, bytes calldata signature) external payable {
        address signer_ = delegator;
        require(choice <= 2, "choice");
        uint256 nonce = nonces[signer_];
        bytes32 digest = _digest(abi.encode(delegator, proposalId, choice, nonce));
        require(_signatureOk(signer_, digest, signature), "signature");

        nonces[signer_] = nonce + 1;
        voteChoice[proposalId][delegator] = choice;
        executionCount += 1;
    }

    function hasExecuted() external view returns (bool) { return executionCount != 0; }

}
