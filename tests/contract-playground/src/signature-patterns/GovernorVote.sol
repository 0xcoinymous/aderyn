// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Safe: GovernorAlpha-style castVoteBySig. No nonce, but receipt.hasVoted (through a storage
// pointer) allows one vote per signer and proposal.
contract GovernorVote {
    string public constant name = "Gov";
    bytes32 public constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");
    bytes32 public constant BALLOT_TYPEHASH = keccak256("Ballot(uint256 proposalId,bool support)");
    struct Receipt { bool hasVoted; bool support; uint96 votes; }
    struct Proposal { uint endBlock; mapping (address => Receipt) receipts; uint forVotes; }
    mapping (uint => Proposal) public proposals;
    function castVoteBySig(uint proposalId, bool support, uint8 v, bytes32 r, bytes32 s) public {
        bytes32 domainSeparator = keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256(bytes(name)), getChainId(), address(this)));
        bytes32 structHash = keccak256(abi.encode(BALLOT_TYPEHASH, proposalId, support));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        address signatory = ecrecover(digest, v, r, s);
        require(signatory != address(0), "invalid signature");
        return _castVote(signatory, proposalId, support);
    }
    function _castVote(address voter, uint proposalId, bool support) internal {
        Proposal storage proposal = proposals[proposalId];
        require(block.number <= proposal.endBlock, "voting is closed");
        Receipt storage receipt = proposal.receipts[voter];
        require(receipt.hasVoted == false, "voter already voted");
        proposal.forVotes += 1;
        receipt.hasVoted = true;
        receipt.support = support;
    }
    function getChainId() internal view returns (uint) { uint256 chainId; assembly { chainId := chainid() } return chainId; }
}
