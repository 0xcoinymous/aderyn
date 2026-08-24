// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_DelegatedVoteMultiDomainCrossPurpose02 is SR_ReplayBenchSignerBase {
    mapping(uint256 => uint256) public proposalVotes;
    mapping(bytes32 => bool) public executed;
    mapping(bytes32 => bool) public cancelled;

    constructor(address signer_) SR_ReplayBenchSignerBase(signer_) {}

    function executeAuthorization(address voter, uint256 proposalId, uint256 weight, bytes32 authorizationId, bytes calldata signature) external {
        require(!executed[authorizationId], "executed");
        bytes32 digest = keccak256(abi.encode(voter, proposalId, weight, authorizationId));
        require(_isAuthorized(digest, signature), "invalid signature");
        executed[authorizationId] = true;
        proposalVotes[proposalId] += weight;
    }

    function cancelAuthorization(address voter, uint256 proposalId, uint256 weight, bytes32 authorizationId, bytes calldata signature) external {
        require(!cancelled[authorizationId], "cancelled");
        bytes32 digest = keccak256(abi.encode(voter, proposalId, weight, authorizationId));
        require(_isAuthorized(digest, signature), "invalid signature");
        cancelled[authorizationId] = true;
    }
}
