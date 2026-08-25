// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_GovernanceAuthorizationSafeIndefiniteOneTimeHelper011 {
    mapping(uint256 => mapping(address => uint8)) public voteChoice;
    mapping(address => uint256) public nonces;

    mapping(address => uint256) public authorizationVersion;
    uint256 public executionCount;
    SF_IFreshnessVerifier public immutable verifier;

    constructor(SF_IFreshnessVerifier verifier_) {
        verifier = verifier_;
    }

    function _verifyFresh(
        address signer_,
        bytes32 digest,
        bytes calldata signature
    ) internal view returns (bool) {
        if (!verifier.verify(signer_, digest, signature)) return false;

        return true;
    }

    function execute(address delegator, uint256 proposalId, uint8 choice, bytes calldata signature) external payable {
        address signer_ = delegator;
        require(choice <= 2, "choice");
        uint256 authVersion = authorizationVersion[signer_];
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(delegator, proposalId, choice, nonce, authVersion, address(this), block.chainid));
        require(_verifyFresh(signer_, digest, signature), "fresh/signature");
        nonces[signer_] = nonce + 1;
        voteChoice[proposalId][delegator] = choice;
        executionCount += 1;
    }

    function hasExecuted() external view returns (bool) { return executionCount != 0; }

    function invalidateStandingAuthorizations() external { authorizationVersion[msg.sender] += 1; }

}
