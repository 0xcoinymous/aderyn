// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_GovernanceNoOneTimeDeadline24 {
    address public immutable authorizedSigner; SR_IReplayBenchVerifier public immutable verifier;
    mapping(uint256 => uint256) public proposalExecutions;

    constructor(address signer_, SR_IReplayBenchVerifier verifier_) { authorizedSigner = signer_; verifier = verifier_; }

    function executeProposal(uint256 proposalId, bytes32 actionHash, uint256 deadline, bytes calldata signature) external {
        require(block.timestamp <= deadline, "expired");

        bytes32 digest = keccak256(abi.encode(proposalId, actionHash, deadline));

        require(verifier.isValid(authorizedSigner, digest, signature), "invalid signature");

        proposalExecutions[proposalId] += 1;
    }
}
