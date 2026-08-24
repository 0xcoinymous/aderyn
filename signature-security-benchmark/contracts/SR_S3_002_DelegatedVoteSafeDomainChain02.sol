// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_DelegatedVoteSafeDomainChain02 {
    address public immutable authorizedSigner; SR_IReplayBenchVerifier public immutable verifier;
    mapping(uint256 => uint256) public proposalVotes;
    mapping(bytes32 => bool) public used;

    constructor(address signer_, SR_IReplayBenchVerifier verifier_) { authorizedSigner = signer_; verifier = verifier_; }

    function voteBySig(address voter, uint256 proposalId, uint256 weight, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(voter, proposalId, weight, block.chainid, authorizationId));

        require(verifier.isValid(authorizedSigner, digest, signature), "invalid signature");

        used[authorizationId] = true;

        proposalVotes[proposalId] += weight;
    }
}
