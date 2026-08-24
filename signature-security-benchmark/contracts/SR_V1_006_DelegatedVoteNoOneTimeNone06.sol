// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_DelegatedVoteNoOneTimeNone06 {
    address public immutable authorizedSigner; SR_IReplayBenchVerifier public immutable verifier;
    mapping(uint256 => uint256) public proposalVotes;

    constructor(address signer_, SR_IReplayBenchVerifier verifier_) { authorizedSigner = signer_; verifier = verifier_; }

    function voteBySig(address voter, uint256 proposalId, uint256 weight, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(voter, proposalId, weight));

        require(verifier.isValid(authorizedSigner, digest, signature), "invalid signature");

        proposalVotes[proposalId] += weight;
    }
}
