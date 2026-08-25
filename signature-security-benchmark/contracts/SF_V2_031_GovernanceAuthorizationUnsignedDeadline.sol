// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_GovernanceAuthorizationUnsignedDeadline031 {
    mapping(uint256 => mapping(address => uint8)) public voteChoice;
    mapping(address => uint256) public nonces;

    
    uint256 public executionCount;


    function execute(address delegator, uint256 proposalId, uint8 choice, uint256 deadline, bytes calldata signature) external payable {
        address signer_ = delegator;
        require(choice <= 2, "choice");
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(delegator, proposalId, choice, nonce, address(this), block.chainid));
        require(SF_FreshnessBenchLib.recover(digest, signature) == signer_, "signature");
        require(block.timestamp <= deadline, "expired");
        nonces[signer_] = nonce + 1;
        voteChoice[proposalId][delegator] = choice;
        executionCount += 1;
    }

    function hasExecuted() external view returns (bool) { return executionCount != 0; }

}
