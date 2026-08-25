// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_GovernanceAuthorizationSafeMonotonicRoundHelper011 {
    mapping(uint256 => mapping(address => uint8)) public voteChoice;
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public latestFreshness;

    uint256 public executionCount;
    SF_IFreshnessVerifier public immutable verifier;

    constructor(SF_IFreshnessVerifier verifier_) {
        verifier = verifier_;
    }

    function _verifyOnly(address signer_, bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return verifier.verify(signer_, digest, signature);
    }

    function execute(address delegator, uint256 proposalId, uint8 choice, uint64 round, bytes calldata signature) external payable {
        address signer_ = delegator;
        require(choice <= 2, "choice");
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(delegator, proposalId, choice, nonce, address(this), block.chainid, round));
        require(_verifyOnly(signer_, digest, signature), "signature");
        require(uint256(round) > latestFreshness[signer_], "old round");
        latestFreshness[signer_] = uint256(round);
        nonces[signer_] = nonce + 1;
        voteChoice[proposalId][delegator] = choice;
        executionCount += 1;
    }

    function hasExecuted() external view returns (bool) { return executionCount != 0; }

}
